package pkg

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"

	"log/slog"

	"github.com/projectdiscovery/pd-agent/pkg/client"
	"github.com/projectdiscovery/pd-agent/pkg/envconfig"
	"github.com/projectdiscovery/pd-agent/pkg/runtools"
	"github.com/projectdiscovery/pd-agent/pkg/scanlog"
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
			ports := task.Options.EnumerationPorts
			if ports == "" {
				ports = "top-100"
			}
			of, err := runEmbeddedTool(ctx, task, "naabu", func(ctx context.Context, outputFile string) error {
				_, err := runtools.RunNaabu(ctx, hosts, runtools.NaabuOptions{
					OutputFile:        outputFile,
					SkipHostDiscovery: true,
					ServiceVersion:    serviceVersion,
					Ports:             ports,
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

	// A template the platform scheduled but the agent lacks would be skipped
	// silently, reporting a clean scan that never ran those checks.
	if missing, err := runtools.EnsureTemplatesFor(ctx, opts.Templates); err != nil {
		if !envconfig.AllowMissingTemplates() {
			return nil, nil, fmt.Errorf("nuclei scan: %w (set %s=true to scan with an incomplete set)",
				err, envconfig.KeyAllowMissingTemplates)
		}
		slog.Error("nuclei scan: scanning with an incomplete template set",
			"scan_id", task.Options.ScanID,
			"chunk_id", task.Id,
			"missing_count", len(missing),
			"error", err)
	}

	// Match upload is handled by the nuclei SDK via WithPDCPUpload.
	if _, err := runtools.RunNuclei(ctx, opts); err != nil {
		return nil, nil, fmt.Errorf("nuclei scan: %w", err)
	}

	// Raw scan-log upload (full JSONL, matched + unmatched), best-effort: a
	// storage failure must not fail the chunk.
	if dests := scanlog.Destinations(); len(dests) > 0 && task.Options.ScanID != "" && task.Options.HistoryID != 0 {
		meta := scanlog.Meta{
			TeamID:    task.Options.TeamID,
			ScanID:    task.Options.ScanID,
			ChunkID:   task.Id,
			HistoryID: task.Options.HistoryID,
		}
		if err := scanlog.Upload(ctx, dests, meta, outputFile); err != nil {
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
