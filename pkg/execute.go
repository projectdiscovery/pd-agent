package pkg

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"log/slog"

	"github.com/projectdiscovery/pd-agent/pkg/client"
	"github.com/projectdiscovery/pd-agent/pkg/envconfig"
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
		// Enumeration pipeline: each step gates the next.
		//   dnsx -> port scan -> httpx (+screenshot) -> tlsx
		steps := task.Options.Steps
		wantScreenshot := sliceutil.Contains(steps, "http_screenshot")
		manualAssetId := task.Options.EnumerationID
		var outputFiles []string

		hosts := task.Options.Hosts
		enumID := task.Options.EnumerationID

		if sliceutil.Contains(steps, "dns_resolve") {
			ips, hostnames := splitIPsAndHostnames(hosts)
			if len(hostnames) == 0 {
				slog.Debug("skipping dnsx, all targets are IPs", "ip_count", len(ips), "enumeration_id", enumID)
			} else {
				_, err := runEmbeddedTool(ctx, task, "dnsx", func(ctx context.Context, outputFile string) error {
					_, err := runtools.RunDnsx(ctx, hostnames, runtools.DnsxOptions{OutputFile: outputFile})
					return err
				}, &manualAssetId, &outputFiles)
				if err != nil {
					return nil, nil, err
				}
			}
		}

		var hostsWithOpenPorts []string
		if sliceutil.Contains(steps, "port_scan") {
			serviceVersion := sliceutil.Contains(steps, "ports_service_scan")
			of, err := runEmbeddedTool(ctx, task, "naabu", func(ctx context.Context, outputFile string) error {
				_, err := runtools.RunNaabu(ctx, hosts, runtools.NaabuOptions{
					OutputFile:        outputFile,
					SkipHostDiscovery: true,
					ServiceVersion:    serviceVersion,
				})
				// naabu returns an error when no ports are found; downstream
				// steps short-circuit on an empty hostsWithOpenPorts list.
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
			// Quick HTTP-port filter (80, 443, 8443) when no naabu step.
			filtered, err := quickPortFilter(ctx, hosts, enumID)
			if err != nil {
				slog.Warn("quick port filter failed, proceeding with all hosts", "error", err)
				hostsWithOpenPorts = hosts
			} else {
				hostsWithOpenPorts = filtered
			}
		}

		if len(hostsWithOpenPorts) == 0 {
			slog.Debug("port scan complete, no open ports, skipping downstream",
				"original_hosts", len(hosts), "enumeration_id", enumID)
			return nil, outputFiles, nil
		}
		slog.Info("port scan complete",
			"original_hosts", len(hosts),
			"hosts_with_open_ports", len(hostsWithOpenPorts),
			"enumeration_id", enumID)

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

// runEmbeddedTool resolves an output path, invokes runFn, and uploads the
// result when the task is dashboard-bound. Returns the output file path.
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

// runNucleiScan runs nuclei via pkg/runtools and uploads the JSONL output
// for dashboard-bound tasks.
func runNucleiScan(ctx context.Context, task *types.Task) (*types.TaskResult, []string, error) {
	if len(task.Options.Hosts) == 0 {
		return nil, nil, fmt.Errorf("nuclei scan: no targets")
	}

	// Naming the file after the chunk id gives the upload step a traceable filename.
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

	// task.Options.Config is base64'd RuntimeConfig YAML for the SDK's
	// WithConfigBytes (tag/severity/rate-limit merging).
	if task.Options.Config != "" {
		decoded, err := base64.StdEncoding.DecodeString(task.Options.Config)
		if err != nil {
			slog.Warn("nuclei scan: failed to base64-decode task.Options.Config; running without overrides",
				"scan_id", task.Options.ScanID, "error", err)
		} else {
			opts.ConfigYAML = decoded
		}
	}

	// Reporting config (nuclei -rc): tracker credentials for auto-filing
	// Jira/Linear/GitHub issues on matches. PDCP_REPORTING_CONFIG (local
	// YAML) wins over the work-message base64 so operators can keep creds
	// off the platform.
	if path := envconfig.ReportingConfigPath(); path != "" {
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

	// Match upload is handled by the nuclei SDK via WithPDCPUpload.
	if _, err := runtools.RunNuclei(ctx, opts); err != nil {
		return nil, nil, fmt.Errorf("nuclei scan: %w", err)
	}

	// Raw scan-log upload (full JSONL, matched + unmatched). Opt-in via
	// PDCP_ENABLE_SCAN_LOG_UPLOAD; default off so agents without storage
	// provisioned don't hammer the API with rejected uploads.
	if envconfig.ScanLogUploadEnabled() && task.Options.ScanID != "" && task.Options.HistoryID != 0 {
		if err := uploadNucleiOutputViaSignedURL(ctx, task, outputFile); err != nil {
			slog.Warn("nuclei scan: scan-log upload failed",
				"scan_id", task.Options.ScanID,
				"history_id", task.Options.HistoryID,
				"chunk_id", task.Id,
				"error", err)
		}
	}

	// Empty TaskResult: embedded path doesn't capture stdout/stderr, so
	// ExtractUnresponsiveHosts has no input until we hook nuclei's logger.
	return &types.TaskResult{}, []string{outputFile}, nil
}

// signedUploadResponse mirrors /v1/scans/{scan_id}/scan_log/upload-url.
// Headers are authoritative: set them verbatim on the PUT and add nothing
// else, since the SigV4 signature covers headers.
type signedUploadResponse struct {
	UploadURL  string            `json:"upload_url"`
	Method     string            `json:"method"`
	Headers    map[string]string `json:"headers"`
	MaxBytes   int64             `json:"max_bytes"`
	ObjectPath string            `json:"object_path"`
	ExpiresAt  time.Time         `json:"expires_at"`
}

// uploadNucleiOutputViaSignedURL ships the per-chunk output via:
//  1. POST /v1/scans/{scan_id}/scan_log/upload-url?history_id=N with {"filename": ...}
//  2. PUT gzipped bytes to the signed URL with the response Headers verbatim.
//
// Gzipped as an opaque .gz blob (no Content-Encoding) so the SigV4 signed
// headers never need to cover Content-Encoding; server gunzips on read.
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

	// Gzip into a sibling temp so we can stat for ContentLength. Unique name
	// keeps a redelivered chunk from clobbering a still-PUTting goroutine.
	gzFile, err := os.CreateTemp(filepath.Dir(outputFile), filepath.Base(outputFile)+"-*.gz")
	if err != nil {
		return fmt.Errorf("create gz tempfile: %w", err)
	}
	gzPath := gzFile.Name()
	_ = gzFile.Close()
	defer func() { _ = os.Remove(gzPath) }()
	gzSize, err := gzipFile(outputFile, gzPath)
	if err != nil {
		return fmt.Errorf("gzip output: %w", err)
	}

	slog.Debug("nuclei scan: gzipped scan-log",
		"scan_id", task.Options.ScanID, "chunk_id", task.Id,
		"raw_bytes", info.Size(), "gz_bytes", gzSize)

	filename := task.Id + ".jsonl.gz"
	httpClient, err := client.CreateAuthenticatedClient(task.Options.TeamID, envconfig.APIKey())
	if err != nil {
		return fmt.Errorf("auth client: %w", err)
	}

	reqBody, _ := json.Marshal(map[string]string{"filename": filename})
	apiURL := fmt.Sprintf("%s/v1/scans/%s/scan_log/upload-url?history_id=%d",
		envconfig.APIServer(), task.Options.ScanID, task.Options.HistoryID)
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
	if signed.MaxBytes > 0 && gzSize > signed.MaxBytes {
		return fmt.Errorf("gzipped output %d bytes exceeds signed-url max %d", gzSize, signed.MaxBytes)
	}

	f, err := os.Open(gzPath)
	if err != nil {
		return fmt.Errorf("open gz: %w", err)
	}
	defer func() { _ = f.Close() }()

	putReq, err := http.NewRequestWithContext(ctx, signed.Method, signed.UploadURL, f)
	if err != nil {
		return fmt.Errorf("build PUT: %s", stripSignedURL(err))
	}
	putReq.ContentLength = gzSize
	for k, v := range signed.Headers {
		putReq.Header.Set(k, v)
	}

	putResp, err := http.DefaultClient.Do(putReq)
	if err != nil {
		return fmt.Errorf("PUT: %s", stripSignedURL(err))
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
		"raw_bytes", info.Size(),
		"gz_bytes", gzSize,
		"object_path", signed.ObjectPath)
	return nil
}

// stripSignedURL drops the URL from a *url.Error so SigV4/GCS HMAC query
// signatures never reach the logs. Keeps operation and underlying cause.
func stripSignedURL(err error) string {
	var ue *url.Error
	if errors.As(err, &ue) {
		return fmt.Sprintf("%s: %s", ue.Op, ue.Err)
	}
	return err.Error()
}

// gzipFile streams src through gzip into dst at BestSpeed (nuclei JSONL
// compresses ~10x even at level 1) and returns the dst size.
func gzipFile(src, dst string) (int64, error) {
	in, err := os.Open(src)
	if err != nil {
		return 0, fmt.Errorf("open src: %w", err)
	}
	defer func() { _ = in.Close() }()

	out, err := os.Create(dst)
	if err != nil {
		return 0, fmt.Errorf("create dst: %w", err)
	}
	gzw, err := gzip.NewWriterLevel(out, gzip.BestSpeed)
	if err != nil {
		_ = out.Close()
		return 0, fmt.Errorf("gzip writer: %w", err)
	}
	if _, err := io.Copy(gzw, in); err != nil {
		_ = gzw.Close()
		_ = out.Close()
		return 0, fmt.Errorf("gzip copy: %w", err)
	}
	if err := gzw.Close(); err != nil {
		_ = out.Close()
		return 0, fmt.Errorf("gzip close: %w", err)
	}
	if err := out.Close(); err != nil {
		return 0, fmt.Errorf("close dst: %w", err)
	}
	st, err := os.Stat(dst)
	if err != nil {
		return 0, fmt.Errorf("stat dst: %w", err)
	}
	return st.Size(), nil
}

// splitIPsAndHostnames separates IPs from hostnames; strips port if present.
func splitIPsAndHostnames(hosts []string) (ips, hostnames []string) {
	for _, h := range hosts {
		host := h
		if hostOnly, _, err := net.SplitHostPort(h); err == nil {
			host = hostOnly
		}
		if net.ParseIP(host) != nil {
			ips = append(ips, h)
		} else {
			hostnames = append(hostnames, h)
		}
	}
	return ips, hostnames
}

// quickPortFilter runs naabu on 80/443/8443 to drop dead hosts before launching
// heavy tools like httpx+Chrome. Returns host:port pairs.
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
	apiURL := fmt.Sprintf("%s/v1/assets", envconfig.APIServer())
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL, f)
	if err != nil {
		return "", err
	}
	defer func() {
		_ = req.Body.Close()
	}()

	req.Header.Set("Content-Type", "application/octet-stream")

	client, err := client.CreateAuthenticatedClient(envconfig.TeamID(), envconfig.APIKey())
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
	apiURL := fmt.Sprintf("%s/v1/assets/%s/contents?upload_type=append", envconfig.APIServer(), assetId)
	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, apiURL, f)
	if err != nil {
		return "", err
	}
	defer func() {
		_ = req.Body.Close()
	}()

	req.Header.Set("Content-Type", "application/octet-stream")

	client, err := client.CreateAuthenticatedClient(envconfig.TeamID(), envconfig.APIKey())
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

// getTotalRAM returns total installed physical RAM in bytes.
func getTotalRAM() (uint64, error) {
	vmStat, err := mem.VirtualMemory()
	if err != nil {
		return 0, err
	}
	return vmStat.Total, nil
}

func hasMoreThan2GBRAM() bool {
	const minRAMBytes = 2 * 1024 * 1024 * 1024

	totalRAM, err := getTotalRAM()
	if err != nil {
		slog.Debug("unable to determine system RAM, disabling code templates", "error", err)
		return false
	}

	return totalRAM > minRAMBytes
}

func hasMoreThan8GBRAM() bool {
	const minRAMBytes = 8 * 1024 * 1024 * 1024

	totalRAM, err := getTotalRAM()
	if err != nil {
		slog.Debug("unable to determine system RAM, disabling headless mode", "error", err)
		return false
	}

	return totalRAM > minRAMBytes
}

func isAMD64() bool {
	return runtime.GOARCH == "amd64"
}
