package pkg

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"log/slog"

	"github.com/projectdiscovery/pd-agent/pkg/client"
	"github.com/projectdiscovery/pd-agent/pkg/runtools"
	"github.com/projectdiscovery/pd-agent/pkg/types"
	fileutil "github.com/projectdiscovery/utils/file"
	sliceutil "github.com/projectdiscovery/utils/slice"
	"github.com/shirou/gopsutil/v3/mem"
	"github.com/tidwall/gjson"
)

func Run(ctx context.Context, task *types.Task) (*types.TaskResult, []string, error) {
	if task.Options.ScanID != "" {
		if task.Tool != types.Nuclei {
			return nil, nil, fmt.Errorf("scan path: unsupported tool %q (only nuclei is wired)", task.Tool.String())
		}
		return runNucleiScan(ctx, task)
	} else if task.Options.EnumerationID != "" {
		// Enumeration pipeline: linear flow, each step gates the next.
		//
		//   1. dnsx       → resolve hostnames (skip if all IPs)
		//   2. port scan  → find open ports (always runs)
		//   3. httpx      → probe web services (only on open ports)
		//   4. httpx -screenshot → screenshot (only on confirmed web services)
		//   5. tlsx       → TLS scan (only on open ports)

		steps := task.Options.Steps
		wantScreenshot := sliceutil.Contains(steps, "http_screenshot")
		manualAssetId := task.Options.EnumerationID
		var outputFiles []string

		hosts := task.Options.Hosts
		enumID := task.Options.EnumerationID

		// --- Step 1: DNS resolve (skip if all targets are IPs) ---
		if sliceutil.Contains(steps, "dns_resolve") {
			ips, hostnames := splitIPsAndHostnames(hosts)
			if len(hostnames) == 0 {
				slog.Info("skipping dnsx, all targets are IPs", "ip_count", len(ips), "enumeration_id", enumID)
			} else {
				_, err := runEmbeddedTool(ctx, task, "dnsx", func(ctx context.Context, outputFile string) error {
					_, err := runtools.RunDnsx(ctx, hostnames, runtools.DnsxOptions{OutputFile: outputFile})
					return err
				}, &manualAssetId, &outputFiles)
				if err != nil {
					return nil, nil, err
				}
				// dnsx doesn't change the host list for subsequent tools
			}
		}

		// --- Step 2: Port scan (always — use step's naabu or quick filter) ---
		var hostsWithOpenPorts []string
		if sliceutil.Contains(steps, "port_scan") {
			// Full port scan via naabu. ServiceVersion turns on naabu's
			// native fingerprinting (nmap-service-probes parsed in-process,
			// no external binary).
			serviceVersion := sliceutil.Contains(steps, "ports_service_scan")
			of, err := runEmbeddedTool(ctx, task, "naabu", func(ctx context.Context, outputFile string) error {
				_, err := runtools.RunNaabu(ctx, hosts, runtools.NaabuOptions{
					OutputFile:        outputFile,
					SkipHostDiscovery: true,
					ServiceVersion:    serviceVersion,
				})
				// naabu returns an error when no ports are found; that's not
				// a pipeline failure — downstream steps short-circuit on an
				// empty hostsWithOpenPorts list.
				if err != nil {
					slog.Warn("naabu enumeration finished with error", "error", err)
				}
				return nil
			}, &manualAssetId, &outputFiles)
			if err != nil {
				return nil, nil, err
			}
			if of != "" {
				c, err := fileutil.ReadFile(of)
				if err == nil {
					for line := range c {
						hostsWithOpenPorts = append(hostsWithOpenPorts, line)
					}
				}
			}
		} else {
			// No port_scan step — quick filter on HTTP ports (80, 443, 8443)
			filtered, err := quickPortFilter(ctx, hosts, enumID)
			if err != nil {
				slog.Warn("quick port filter failed, proceeding with all hosts", "error", err)
				hostsWithOpenPorts = hosts
			} else {
				hostsWithOpenPorts = filtered
			}
		}

		slog.Info("port scan complete",
			"original_hosts", len(hosts),
			"hosts_with_open_ports", len(hostsWithOpenPorts),
			"enumeration_id", enumID)

		if len(hostsWithOpenPorts) == 0 {
			slog.Info("no open ports found, skipping httpx/tlsx/screenshot", "enumeration_id", enumID)
			return nil, outputFiles, nil
		}

		// --- Step 3: httpx probe (on open ports only, no screenshot) ---
		var webServices []string
		if sliceutil.Contains(steps, "http_probe") {
			_, err := runEmbeddedTool(ctx, task, "httpx", func(ctx context.Context, outputFile string) error {
				_, urls, err := runtools.RunHttpx(ctx, hostsWithOpenPorts, runtools.HttpxOptions{OutputFile: outputFile})
				webServices = urls
				return err
			}, &manualAssetId, &outputFiles)
			if err != nil {
				return nil, nil, err
			}
			slog.Info("httpx probe complete",
				"input_hosts", len(hostsWithOpenPorts),
				"web_services_found", len(webServices),
				"enumeration_id", enumID)
		}

		// --- Step 4: httpx screenshot (only on confirmed web services) ---
		if wantScreenshot && len(webServices) > 0 {
			slog.Info("running httpx screenshot on confirmed web services",
				"web_services", len(webServices), "enumeration_id", enumID)
			_, err := runEmbeddedTool(ctx, task, "httpx-screenshot", func(ctx context.Context, outputFile string) error {
				_, _, err := runtools.RunHttpx(ctx, webServices, runtools.HttpxOptions{
					OutputFile: outputFile,
					Screenshot: true,
				})
				return err
			}, &manualAssetId, &outputFiles)
			if err != nil {
				return nil, nil, err
			}
		} else if wantScreenshot {
			slog.Info("skipping httpx screenshot, no web services found", "enumeration_id", enumID)
		}

		// --- Step 5: TLS scan (on open ports only) ---
		if sliceutil.Contains(steps, "tls_scan") {
			_, err := runEmbeddedTool(ctx, task, "tlsx", func(ctx context.Context, outputFile string) error {
				_, err := runtools.RunTlsx(ctx, hostsWithOpenPorts, runtools.TlsxOptions{OutputFile: outputFile})
				return err
			}, &manualAssetId, &outputFiles)
			if err != nil {
				return nil, nil, err
			}
		}

		return nil, outputFiles, nil
	}

	return nil, nil, nil
}

// runEmbeddedTool runs a tool whose execution lives in pd-agent's own process
// (via pkg/runtools) instead of a CLI subprocess. It owns the same output-file
// and dashboard-upload orchestration as runEnumTool but skips the args/env/exec
// machinery: the caller passes a runFn that takes the resolved output path and
// performs the scan. Returns the output file path on success.
func runEmbeddedTool(
	ctx context.Context,
	task *types.Task,
	toolName string,
	runFn func(ctx context.Context, outputFile string) error,
	manualAssetId *string,
	outputFiles *[]string,
) (string, error) {
	var outputFile string
	if task.Options.Output != "" {
		_ = fileutil.CreateFolder(task.Options.Output)
		outputFile = filepath.Join(task.Options.Output, fmt.Sprintf("%s.output", toolName))
	} else {
		tmp, err := fileutil.GetTempFileName()
		if err != nil {
			return "", fmt.Errorf("create temp output file for %s: %w", toolName, err)
		}
		outputFile = tmp
	}

	slog.Info("running embedded tool", "tool", toolName, "output", outputFile)
	if err := runFn(ctx, outputFile); err != nil {
		return outputFile, err
	}

	*outputFiles = append(*outputFiles, outputFile)

	// Embedded tools never delegate dashboard upload; we always handle it
	// here when the task is dashboard-bound and the file is non-empty.
	if task.Options.EnumerationID == "" && task.Options.TeamID == "" {
		return outputFile, nil
	}
	info, err := os.Stat(outputFile)
	if err != nil || info.Size() == 0 {
		return outputFile, nil
	}
	assetId, err := uploadToCloudWithId(ctx, task, outputFile, *manualAssetId)
	if err == nil {
		*manualAssetId = assetId
		return outputFile, nil
	}
	assetId, err = uploadToCloud(ctx, task, outputFile)
	if err != nil {
		return outputFile, err
	}
	*manualAssetId = assetId
	return outputFile, nil
}

// runNucleiScan replaces the previous parseScanArgs + runCommand shell-out
// path. It builds NucleiOptions from the task, runs nuclei via pkg/runtools,
// uploads the JSONL output to PDCP if the task is dashboard-bound, and
// returns the output file path.
func runNucleiScan(ctx context.Context, task *types.Task) (*types.TaskResult, []string, error) {
	if len(task.Options.Hosts) == 0 {
		return nil, nil, fmt.Errorf("nuclei scan: no targets")
	}

	// Name the output file after the chunk id (task.Id is set to the
	// chunk's metaID upstream). Gives the upload step a stable, traceable
	// filename rather than a random temp suffix.
	outputName := task.Id
	if outputName == "" {
		outputName = "nuclei"
	}
	outputName += ".jsonl"

	var outputFile string
	if task.Options.Output != "" {
		_ = fileutil.CreateFolder(task.Options.Output)
		outputFile = filepath.Join(task.Options.Output, outputName)
	} else {
		dir, err := os.MkdirTemp("", "pd-agent-nuclei-*")
		if err != nil {
			return nil, nil, fmt.Errorf("create temp output dir for nuclei: %w", err)
		}
		outputFile = filepath.Join(dir, outputName)
	}

	opts := runtools.NucleiOptions{
		OutputFile:           outputFile,
		Targets:              task.Options.Hosts,
		Templates:            task.Options.Templates,
		ScanID:               task.Options.ScanID,
		TeamID:               task.Options.TeamID,
		AllowLocalFileAccess: true,
		MatcherStatus:        true,
		EnableCodeTemplates:  hasMoreThan2GBRAM(),
		Headless:             hasMoreThan8GBRAM() && isAMD64(),
	}

	// task.Options.Config is the work message's `config` field — base64 of
	// a nuclei -config-style YAML. Decode and hand the bytes to the SDK's
	// WithConfigBytes (same path the CLI uses for -config <file>). nuclei's
	// SDK also picks up an inline `report-config: <path>` reference from the
	// config and loads the reporting YAML implicitly.
	if task.Options.Config != "" {
		decoded, err := base64.StdEncoding.DecodeString(task.Options.Config)
		if err != nil {
			slog.Warn("nuclei scan: failed to base64-decode task.Options.Config; running without overrides",
				"scan_id", task.Options.ScanID, "error", err)
		} else {
			opts.ConfigYAML = decoded
		}
	}

	// Reporting config (nuclei -rc / -report-config): tracker credentials for
	// auto-creating Jira/Linear/GitHub/etc. issues on matched findings.
	// Resolution order — operator override wins:
	//   1. PDCP_REPORTING_CONFIG env — path to a local YAML on the agent.
	//      Lets customers keep tracker creds off the platform and out of the
	//      work message entirely. If set, takes precedence even if the work
	//      message also carries ReportConfig.
	//   2. task.Options.ReportConfig — base64 YAML the platform shipped.
	if path := os.Getenv("PDCP_REPORTING_CONFIG"); path != "" {
		if data, err := os.ReadFile(path); err == nil {
			opts.ReportingConfigYAML = data
			slog.Info("nuclei scan: loaded reporting config from env (overriding work message)",
				"scan_id", task.Options.ScanID, "path", path, "bytes", len(data))
		} else {
			slog.Warn("nuclei scan: PDCP_REPORTING_CONFIG read failed",
				"path", path, "error", err)
		}
	} else if task.Options.ReportConfig != "" {
		decoded, err := base64.StdEncoding.DecodeString(task.Options.ReportConfig)
		if err != nil {
			slog.Warn("nuclei scan: failed to base64-decode task.Options.ReportConfig; reporting disabled for this scan",
				"scan_id", task.Options.ScanID, "error", err)
		} else {
			opts.ReportingConfigYAML = decoded
			slog.Info("nuclei scan: loaded reporting config from work message",
				"scan_id", task.Options.ScanID, "bytes", len(decoded))
		}
	}

	slog.Info("running embedded nuclei",
		"scan_id", task.Options.ScanID,
		"targets", len(opts.Targets),
		"templates", len(opts.Templates),
		"output", outputFile,
		"code", opts.EnableCodeTemplates,
		"headless", opts.Headless,
		"config_bytes", len(opts.ConfigYAML),
	)

	// Dashboard upload is handled by the nuclei SDK itself (WithPDCPUpload,
	// wired in pkg/runtools/nuclei.go) — matched-only findings flow into
	// pdcp.UploadWriter the same way -dashboard -scan-id does on the CLI.
	if _, err := runtools.RunNuclei(ctx, opts); err != nil {
		return nil, nil, fmt.Errorf("nuclei scan: %w", err)
	}

	// Scan-log upload: ship the raw nuclei output file (full JSONL, both
	// matched and unmatched events) to the platform via the presigned-URL
	// flow. This is what powers the "what did the agent actually execute"
	// audit view on the platform side. Skipped when ScanID or HistoryID
	// isn't set (local/test runs).
	if task.Options.ScanID != "" && task.Options.HistoryID != 0 {
		if err := uploadNucleiOutputViaSignedURL(ctx, task, outputFile); err != nil {
			slog.Warn("nuclei scan: scan-log upload failed",
				"scan_id", task.Options.ScanID,
				"history_id", task.Options.HistoryID,
				"chunk_id", task.Id,
				"error", err)
		}
	}

	// Empty TaskResult: the embedded path doesn't capture stdout/stderr the
	// way the subprocess did. ExtractUnresponsiveHosts loses its input here;
	// that diagnostic stops working under the embedded path until we hook
	// nuclei's logger to surface skip events.
	return &types.TaskResult{}, []string{outputFile}, nil
}

// signedUploadResponse mirrors the /v1/scans/{scan_id}/scan_log/upload-url
// response shape. Headers are authoritative — set them verbatim on the PUT,
// don't add Content-Type or anything else (the V4 signature covers headers).
type signedUploadResponse struct {
	UploadURL  string            `json:"upload_url"`
	Method     string            `json:"method"`
	Headers    map[string]string `json:"headers"`
	MaxBytes   int64             `json:"max_bytes"`
	ObjectPath string            `json:"object_path"`
	ExpiresAt  time.Time         `json:"expires_at"`
}

// uploadNucleiOutputViaSignedURL ships the per-chunk nuclei output file to
// the platform via the presigned-URL flow. Two-hop:
//  1. POST /v1/scans/{scan_id}/scan_log/upload-url?history_id=N
//     body: {"filename": "<chunk_id>.jsonl"}
//  2. PUT the file bytes to the signed URL with the exact headers map.
//
// Filename uses task.Id (chunk_id) so the platform can correlate uploaded
// logs back to a specific chunk inside a scan run.
func uploadNucleiOutputViaSignedURL(ctx context.Context, task *types.Task, outputFile string) error {
	info, err := os.Stat(outputFile)
	if err != nil {
		return fmt.Errorf("stat output: %w", err)
	}
	if info.Size() == 0 {
		slog.Debug("nuclei scan: output file empty, skipping scan-log upload",
			"scan_id", task.Options.ScanID, "chunk_id", task.Id)
		return nil
	}

	filename := task.Id + ".jsonl"
	httpClient, err := client.CreateAuthenticatedClient(task.Options.TeamID, os.Getenv("PDCP_API_KEY"))
	if err != nil {
		return fmt.Errorf("auth client: %w", err)
	}

	// Step 1: request the signed URL.
	reqBody, _ := json.Marshal(map[string]string{"filename": filename})
	apiURL := fmt.Sprintf("%s/v1/scans/%s/scan_log/upload-url?history_id=%d",
		PCDPApiServer, task.Options.ScanID, task.Options.HistoryID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL, bytes.NewReader(reqBody))
	if err != nil {
		return fmt.Errorf("build upload-url request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("get upload-url: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("upload-url status %d: %s", resp.StatusCode, string(respBody))
	}

	var signed signedUploadResponse
	if err := json.Unmarshal(respBody, &signed); err != nil {
		return fmt.Errorf("decode upload-url response: %w", err)
	}
	if signed.UploadURL == "" || signed.Method == "" {
		return fmt.Errorf("upload-url response missing url/method")
	}
	if signed.MaxBytes > 0 && info.Size() > signed.MaxBytes {
		return fmt.Errorf("output file %d bytes exceeds signed-url max %d", info.Size(), signed.MaxBytes)
	}

	// Step 2: PUT the file to the signed URL with the exact headers.
	f, err := os.Open(outputFile)
	if err != nil {
		return fmt.Errorf("open output: %w", err)
	}
	defer func() { _ = f.Close() }()

	putReq, err := http.NewRequestWithContext(ctx, signed.Method, signed.UploadURL, f)
	if err != nil {
		return fmt.Errorf("build PUT: %w", err)
	}
	putReq.ContentLength = info.Size()
	for k, v := range signed.Headers {
		putReq.Header.Set(k, v)
	}

	putResp, err := http.DefaultClient.Do(putReq)
	if err != nil {
		return fmt.Errorf("PUT: %w", err)
	}
	defer func() { _ = putResp.Body.Close() }()

	if putResp.StatusCode != http.StatusOK && putResp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(putResp.Body)
		return fmt.Errorf("PUT status %d: %s", putResp.StatusCode, string(body))
	}
	_, _ = io.Copy(io.Discard, putResp.Body)

	slog.Info("nuclei scan: output file uploaded",
		"scan_id", task.Options.ScanID,
		"history_id", task.Options.HistoryID,
		"chunk_id", task.Id,
		"size_bytes", info.Size(),
		"object_path", signed.ObjectPath)
	return nil
}

// splitIPsAndHostnames separates a list of hosts into IP addresses and hostnames.
// Handles host:port format — strips port before checking.
func splitIPsAndHostnames(hosts []string) (ips, hostnames []string) {
	for _, h := range hosts {
		// Strip port if present (e.g., "10.0.0.1:8080" → "10.0.0.1")
		host := h
		if hostOnly, _, err := net.SplitHostPort(h); err == nil {
			host = hostOnly
		}
		if net.ParseIP(host) != nil {
			ips = append(ips, h) // keep original (with port if present)
		} else {
			hostnames = append(hostnames, h)
		}
	}
	return ips, hostnames
}

// quickPortFilter runs a lightweight naabu scan on HTTP default ports (80, 443, 8443)
// to check which hosts are alive before launching expensive tools like httpx with Chrome.
// Returns host:port pairs for hosts with at least one open port.
func quickPortFilter(ctx context.Context, hosts []string, enumID string) ([]string, error) {
	httpPorts := []string{"80", "443", "8443"}
	hostPorts, err := runNaabuScan(ctx, hosts, httpPorts, enumID, "quick-filter")
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(hostPorts))
	for h, ports := range hostPorts {
		for _, p := range ports {
			out = append(out, net.JoinHostPort(h, p))
		}
	}
	return out, nil
}

func uploadToCloud(ctx context.Context, _ *types.Task, outputFile string) (string, error) {
	slog.Debug("uploading to cloud", "file", outputFile)
	f, err := os.Open(outputFile)
	if err != nil {
		return "", err
	}
	defer func() {
		_ = f.Close()
	}()
	apiURL := fmt.Sprintf("%s/v1/assets", PCDPApiServer)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL, f)
	if err != nil {
		return "", err
	}
	defer func() {
		_ = req.Body.Close()
	}()

	req.Header.Set("Content-Type", "application/octet-stream")

	client, err := client.CreateAuthenticatedClient(os.Getenv("PDCP_TEAM_ID"), os.Getenv("PDCP_API_KEY"))
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	data := gjson.ParseBytes(body)
	assetId := data.Get("asset_id").String()
	return assetId, nil
}

func uploadToCloudWithId(ctx context.Context, _ *types.Task, outputFile string, assetId string) (string, error) {
	f, err := os.Open(outputFile)
	if err != nil {
		return "", err
	}
	defer func() {
		_ = f.Close()
	}()
	apiURL := fmt.Sprintf("%s/v1/assets/%s/contents?upload_type=append", PCDPApiServer, assetId)
	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, apiURL, f)
	if err != nil {
		return "", err
	}
	defer func() {
		_ = req.Body.Close()
	}()

	req.Header.Set("Content-Type", "application/octet-stream")

	client, err := client.CreateAuthenticatedClient(os.Getenv("PDCP_TEAM_ID"), os.Getenv("PDCP_API_KEY"))
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return assetId, nil
}

// getTotalRAM returns the total physical/installed RAM in bytes (not virtual memory)
// Returns 0 and an error if unable to determine RAM
// Note: mem.VirtualMemory().Total returns the total physical RAM installed on the system
func getTotalRAM() (uint64, error) {
	vmStat, err := mem.VirtualMemory()
	if err != nil {
		return 0, err
	}
	// Total field represents the total physical RAM installed, not virtual memory
	return vmStat.Total, nil
}

// hasMoreThan2GBRAM checks if the system has more than 2GB of RAM
// Returns true if RAM > 2GB, false otherwise or if unable to determine
func hasMoreThan2GBRAM() bool {
	const minRAMBytes = 2 * 1024 * 1024 * 1024 // 2GB in bytes

	totalRAM, err := getTotalRAM()
	if err != nil {
		slog.Debug("unable to determine system RAM, disabling code templates", "error", err)
		return false
	}

	return totalRAM > minRAMBytes
}

// hasMoreThan8GBRAM checks if the system has more than 8GB of RAM
// Returns true if RAM > 8GB, false otherwise or if unable to determine
func hasMoreThan8GBRAM() bool {
	const minRAMBytes = 8 * 1024 * 1024 * 1024 // 8GB in bytes

	totalRAM, err := getTotalRAM()
	if err != nil {
		slog.Debug("unable to determine system RAM, disabling headless mode", "error", err)
		return false
	}

	return totalRAM > minRAMBytes
}

// isAMD64 checks if the system architecture is AMD64 (x86_64)
// Returns true if architecture is amd64, false otherwise
func isAMD64() bool {
	return runtime.GOARCH == "amd64"
}
