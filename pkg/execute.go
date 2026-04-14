package pkg

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"log/slog"

	"github.com/projectdiscovery/pd-agent/pkg/client"
	"github.com/projectdiscovery/pd-agent/pkg/types"
	"github.com/projectdiscovery/utils/conversion"
	envutil "github.com/projectdiscovery/utils/env"
	fileutil "github.com/projectdiscovery/utils/file"
	mapsutil "github.com/projectdiscovery/utils/maps"
	osutils "github.com/projectdiscovery/utils/os"
	sliceutil "github.com/projectdiscovery/utils/slice"
	stringsutil "github.com/projectdiscovery/utils/strings"
	"github.com/shirou/gopsutil/v3/mem"
	"github.com/tidwall/gjson"
)

// verifyToolInPath checks if a tool exists in the system PATH
func verifyToolInPath(toolName string) error {
	_, err := exec.LookPath(toolName)
	if err != nil {
		return fmt.Errorf("tool '%s' not found in PATH: %w", toolName, err)
	}
	return nil
}

// checkToolInPath checks if a tool exists in the system PATH, handling Windows .exe extension
func checkToolInPath(toolName string) (string, error) {
	if osutils.IsWindows() {
		toolName = toolName + ".exe"
	}
	path, err := exec.LookPath(toolName)
	if err != nil {
		return "", fmt.Errorf("tool '%s' not found in PATH: %w", toolName, err)
	}
	return path, nil
}

// PrerequisiteCheckResult represents the result of checking a single prerequisite
type PrerequisiteCheckResult struct {
	ToolName string
	Found    bool
	Path     string
	Error    error
}

// CheckPrerequisites checks if all required prerequisites are installed
// Returns a map of tool names to their check results
func CheckPrerequisites(tools []string) map[string]PrerequisiteCheckResult {
	results := make(map[string]PrerequisiteCheckResult)

	for _, tool := range tools {
		path, err := checkToolInPath(tool)
		result := PrerequisiteCheckResult{
			ToolName: tool,
			Found:    err == nil,
			Path:     path,
			Error:    err,
		}
		results[tool] = result
	}

	return results
}

// CheckAllPrerequisites checks the default set of prerequisites: dnsx, nuclei, httpx, naabu, nmap
func CheckAllPrerequisites() map[string]PrerequisiteCheckResult {
	prerequisites := []string{"dnsx", "nuclei", "httpx", "naabu", "nmap"}
	return CheckPrerequisites(prerequisites)
}

func Run(ctx context.Context, task *types.Task) (*types.TaskResult, []string, error) {
	// Verify tool exists in PATH
	if err := verifyToolInPath(task.Tool.String()); err != nil {
		return nil, nil, err
	}

	if task.Options.ScanID != "" {
		envs, args, outputFile, removeFunc, err := parseScanArgs(ctx, task)
		if err != nil {
			return nil, nil, err
		}
		defer removeFunc()

		taskResult, err := runCommand(ctx, envs, args)
		if err != nil {
			return nil, nil, err
		}

		ExtractUnresponsiveHosts(taskResult)

		var outputFiles []string
		if outputFile != "" {
			outputFiles = []string{outputFile}
		}
		return taskResult, outputFiles, nil
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
				of, err := runEnumTool(ctx, task, "dnsx", hostnames, nil, &manualAssetId, &outputFiles)
				if err != nil {
					return nil, nil, err
				}
				// dnsx doesn't change the host list for subsequent tools
				_ = of
			}
		}

		// --- Step 2: Port scan (always — use step's naabu or quick filter) ---
		var hostsWithOpenPorts []string
		if sliceutil.Contains(steps, "port_scan") {
			// Full port scan via naabu
			var naabuArgs []string
			if sliceutil.Contains(steps, "ports_service_scan") {
				naabuArgs = []string{"-nmap-cli", "nmap -sV -Pn"}
			}
			of, err := runEnumTool(ctx, task, "naabu", hosts, naabuArgs, &manualAssetId, &outputFiles)
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
			of, err := runEnumTool(ctx, task, "httpx", hostsWithOpenPorts, []string{"-irr"}, &manualAssetId, &outputFiles)
			if err != nil {
				return nil, nil, err
			}
			if of != "" {
				c, err := fileutil.ReadFile(of)
				if err == nil {
					for line := range c {
						webServices = append(webServices, line)
					}
				}
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
			_, err := runEnumTool(ctx, task, "httpx", webServices, []string{"-screenshot", "-irr"}, &manualAssetId, &outputFiles)
			if err != nil {
				return nil, nil, err
			}
		} else if wantScreenshot {
			slog.Info("skipping httpx screenshot, no web services found", "enumeration_id", enumID)
		}

		// --- Step 5: TLS scan (on open ports only) ---
		if sliceutil.Contains(steps, "tls_scan") {
			_, err := runEnumTool(ctx, task, "tlsx", hostsWithOpenPorts, nil, &manualAssetId, &outputFiles)
			if err != nil {
				return nil, nil, err
			}
		}

		return nil, outputFiles, nil
	}

	return nil, nil, nil
}

// runEnumTool executes a single enumeration tool and handles output file, dashboard
// upload, and asset ID tracking. Returns the output file path (if any).
func runEnumTool(
	ctx context.Context,
	task *types.Task,
	toolName string,
	hosts []string,
	extraArgs []string,
	manualAssetId *string,
	outputFiles *[]string,
) (string, error) {
	if err := verifyToolInPath(toolName); err != nil {
		return "", err
	}

	currentTask := *task
	currentTask.Options.Hosts = hosts

	envs, args, outputFile, removeFunc, err := parseGenericArgs(&currentTask)
	if err != nil {
		return "", err
	}
	defer removeFunc()
	args[0] = toolName

	// Output file
	if task.Options.Output != "" {
		_ = fileutil.CreateFolder(task.Options.Output)
		suffix := toolName
		if sliceutil.Contains(extraArgs, "-screenshot") {
			suffix = toolName + "-screenshot"
		}
		outputFile = filepath.Join(task.Options.Output, fmt.Sprintf("%s.output", suffix))
		args = append(args, "-o", outputFile)
	}

	// httpx/naabu always need an output file so we can read results for the next step.
	if outputFile == "" && (toolName == "httpx" || toolName == "naabu") {
		tmpOut, err := fileutil.GetTempFileName()
		if err != nil {
			return "", fmt.Errorf("create temp output file for %s: %w", toolName, err)
		}
		outputFile = tmpOut
		args = append(args, "-o", outputFile)
	}

	// Dashboard upload flags for tools that support it.
	hasDashboardUpload := stringsutil.EqualFoldAny(toolName, "httpx", "naabu", "tlsx")
	if hasDashboardUpload && (task.Options.EnumerationID != "" || task.Options.TeamID != "") {
		args = append(args,
			"-team-id", os.Getenv("PDCP_TEAM_ID"),
			"-dashboard",
			"-asset-id", *manualAssetId,
		)
	}

	// Extra tool-specific args
	args = append(args, extraArgs...)

	slog.Info("running enumeration tool", "tool", toolName, "hosts", len(hosts), "args_count", len(args))

	if _, err := runCommand(ctx, envs, args); err != nil {
		return "", err
	}

	if outputFile != "" {
		*outputFiles = append(*outputFiles, outputFile)
	}

	// Manual upload: only if we didn't pass -dashboard to the tool,
	// and only if the output file is non-empty.
	if !sliceutil.Contains(args, "-dashboard") && outputFile != "" {
		info, err := os.Stat(outputFile)
		if err == nil && info.Size() > 0 {
			assetId, err := uploadToCloudWithId(ctx, task, outputFile, task.Options.EnumerationID)
			if err == nil {
				*manualAssetId = assetId
			} else {
				assetId, err = uploadToCloud(ctx, task, outputFile)
				if err != nil {
					return outputFile, err
				}
				*manualAssetId = assetId
			}
		}
	}

	return outputFile, nil
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
	return runNaabuScan(ctx, hosts, httpPorts, enumID, "quick-filter")
}

func ExtractUnresponsiveHosts(taskResult *types.TaskResult) {
	fields := strings.Fields(taskResult.Stdout + taskResult.Stderr)
	for i := 0; i < len(fields)-1; i++ {
		if stringsutil.EqualFoldAny(fields[i], "skipped") {
			host := fields[i+1]
			// Split host:port into host only since other templates will check the same combinations
			if parts := strings.Split(host, ":"); len(parts) > 0 {
				host = parts[0]
			}
			_ = UnresponsiveHosts.Set(host, struct{}{})
		}
	}
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

func parseScanArgs(ctx context.Context, task *types.Task) (envs, args []string, outputFile string, removeFunc func(), err error) {
	args = append(args, task.Tool.String())

	tmpInputFile, tmpConfigFile, inputRemoveFunc, err := prepareInput(task)
	if err != nil {
		return nil, nil, "", nil, fmt.Errorf("failed to create temp file: %w", err)
	}

	var tmpTemplatesFile string
	if len(task.Options.Templates) > 0 {
		// Create temporary file for templates to avoid command line length limits
		tmpTemplatesFile, err = fileutil.GetTempFileName()
		if err != nil {
			inputRemoveFunc()
			return nil, nil, "", nil, fmt.Errorf("failed to create temp file for templates: %w", err)
		}

		// Write templates to file, one per line (standard format for nuclei template files)
		templatesContent := strings.Join(task.Options.Templates, "\n")
		if err := os.WriteFile(tmpTemplatesFile, conversion.Bytes(templatesContent), os.ModePerm); err != nil {
			inputRemoveFunc()
			_ = os.RemoveAll(tmpTemplatesFile)
			return nil, nil, "", nil, fmt.Errorf("failed to write templates to temp file: %w", err)
		}

		args = append(args, "-templates", tmpTemplatesFile)
	}

	if task.Options.TeamID != "" {
		args = append(args, "-team-id", task.Options.TeamID)
	}

	args = append(args, "-l", tmpInputFile)

	if tmpConfigFile != "" {
		args = append(args, "-config", tmpConfigFile)
	}

	if task.Options.ScanID != "" || task.Options.TeamID != "" {
		envs = getEnvs()
		args = append(args,
			"-dashboard",
			"-scan-id", task.Options.ScanID,
		)
	}

	if task.Tool == types.Nuclei {
		// Always add -lfa flag
		args = append(args, "-lfa")
		// Always add log upload flags
		args = append(args, "-ms")    // matcher-status
		args = append(args, "-jsonl") // JSON lines format
		// Enable -code only if there are more than 2GB of RAM
		if hasMoreThan2GBRAM() {
			args = append(args, "-code")
		}
		// Enable -headless only if there are more than 8GB of RAM and architecture is AMD64
		if hasMoreThan8GBRAM() && isAMD64() {
			args = append(args, "-headless")
		}
	}

	if task.Options.Output != "" {
		_ = fileutil.CreateFolder(task.Options.Output)
		outputFile = filepath.Join(task.Options.Output, fmt.Sprintf("%s.output", args[0]))
		args = append(args, "-o", outputFile)
	}

	// Create combined remove function that cleans up all temporary files
	// Note: outputFile is NOT deleted here - it will be processed and deleted separately
	removeFunc = func() {
		inputRemoveFunc()
		if tmpTemplatesFile != "" {
			_ = os.RemoveAll(tmpTemplatesFile)
		}
	}

	return envs, args, outputFile, removeFunc, nil
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

var UnresponsiveHosts = mapsutil.NewSyncLockMap[string, struct{}]()

func init() {
	UnresponsiveHosts = mapsutil.NewSyncLockMap[string, struct{}]()
}

func prepareInput(task *types.Task) (
	string, // input list
	string, // config
	func(), // remove function
	error, // error
) {
	tmpInputFile, err := fileutil.GetTempFileName()
	if err != nil {
		return "", "", nil, fmt.Errorf("failed to create temp file: %w", err)
	}

	var filteredHosts []string
	for _, host := range task.Options.Hosts {
		if UnresponsiveHosts.Has(host) {
			continue
		}

		filteredHosts = append(filteredHosts, host)
	}

	allTargets := strings.Join(filteredHosts, "\n")
	if err := os.WriteFile(tmpInputFile, conversion.Bytes(allTargets), os.ModePerm); err != nil {
		return "", "", nil, fmt.Errorf("failed to write to temp file: %w", err)
	}

	var tmpConfigFile string
	if task.Options.Config != "" {
		tmpConfigFile, err = fileutil.GetTempFileName()
		if err != nil {
			return "", "", nil, fmt.Errorf("failed to create temp file: %w", err)
		}
		if err := os.WriteFile(tmpConfigFile, conversion.Bytes(task.Options.Config), os.ModePerm); err != nil {
			return "", "", nil, fmt.Errorf("failed to write to temp file: %w", err)
		}
	}

	removeFunc := func() {
		_ = os.RemoveAll(tmpInputFile)
		if tmpConfigFile != "" {
			_ = os.RemoveAll(tmpConfigFile)
		}
	}
	return tmpInputFile, tmpConfigFile, removeFunc, nil
}

func getEnvs() []string {
	defaultPDCPDashboardURL := envutil.GetEnvOrDefault("PDCP_DASHBOARD_URL", "https://cloud.projectdiscovery.io")
	defaultPDCPAPIServer := envutil.GetEnvOrDefault("PDCP_API_SERVER", "https://api.projectdiscovery.io")
	envs := []string{
		"PDCP_DASHBOARD_URL=" + defaultPDCPDashboardURL,
		"PDCP_API_SERVER=" + defaultPDCPAPIServer,
		"PDCP_API_KEY=" + os.Getenv("PDCP_API_KEY"),
		"HOME=" + os.Getenv("HOME"),
		"PDCP_TEAM_ID=" + os.Getenv("PDCP_TEAM_ID"),
		"PATH=" + os.Getenv("PATH"),
	}
	return envs
}

func runCommand(ctx context.Context, envs, args []string) (*types.TaskResult, error) {
	slog.Debug("running tool", "cmd", args[0])

	// Prepare the command
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)

	cmd.Env = append(cmd.Env, envs...)

	// Set up stdin, stdout, and stderr pipes
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stdout pipe: %w", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stderr pipe: %w", err)
	}

	// Start the command
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start tool '%s': %w", args[0], err)
	}

	// Read stdout and stderr
	stdoutOutput, err := io.ReadAll(stdout)
	if err != nil {
		return nil, fmt.Errorf("failed to read stdout: %w", err)
	}

	taskResult := &types.TaskResult{
		Stdout: string(stdoutOutput),
	}

	stderrOutput, err := io.ReadAll(stderr)
	if err != nil {
		return taskResult, nil
	}

	taskResult.Stderr = string(stderrOutput)

	// Wait for the command to finish
	if err := cmd.Wait(); err != nil {
		// -----------
		// Recoverable error, return the task result with the error
		// NUCLEI
		// - [FTL] Could not run nuclei: no templates provided for scan => no templates compatible with provided flags
		if strings.Contains(taskResult.Stderr, "no templates provided for scan") {
			return taskResult, nil
		}
		return taskResult, fmt.Errorf("failed to execute tool '%s': %w\nStdout: %s\nStderr: %s", args[0], err, string(stdoutOutput), string(stderrOutput))
	}

	slog.Debug("tool execution completed", "cmd", args[0])

	return taskResult, nil
}

func parseGenericArgs(task *types.Task) (envs, args []string, outputFile string, removeFunc func(), err error) {
	envs = getEnvs()

	args = append(args, task.Tool.String())

	tmpFile, _, removeFunc, err := prepareInput(task)
	if err != nil {
		return nil, nil, "", nil, fmt.Errorf("failed to create temp file: %w", err)
	}

	args = append(args,
		"-silent",
		"-l", tmpFile,
		// "-verbose",
	)

	return envs, args, outputFile, removeFunc, nil
}
