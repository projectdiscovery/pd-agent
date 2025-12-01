package pkg

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/projectdiscovery/gologger"
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
		// run: dnsx | naabu | httpx - for now execute all the tools in parallel
		// for the time being we ignore the steps from cloud
		// uploads are performed to different ids - the api was not designed with assets associated to specific enumeration id
		tools := getToolsFromSteps(task.Options.Steps)
		// track naabu output as input to next steps
		var (
			naabuOutput     []string
			naabuOutputFile string
			manualAssetId   = task.Options.EnumerationID
			outputFiles     []string // Collect all output files from enumeration tools
		)
		for _, tool := range tools {
			// Verify tool exists in PATH
			if err := verifyToolInPath(tool.Name); err != nil {
				return nil, nil, err
			}

			// Use naabu output as input for subsequent tools (httpx, tlsx)
			currentHosts := task.Options.Hosts
			if len(naabuOutput) > 0 && tool.Name != "dnsx" && tool.Name != "naabu" {
				currentHosts = naabuOutput
			}

			// Create a temporary task with current hosts for this tool
			currentTask := *task
			currentTask.Options.Hosts = currentHosts

			// todo: remove this patch for testing
			// currentTask.Options.Hosts = []string{"192.168.179.2:8000"}
			envs, args, outputFile, removeFunc, err := parseGenericArgs(&currentTask)
			if err != nil {
				return nil, nil, err
			}
			defer removeFunc()
			args[0] = tool.Name
			// handle per tool specific args
			if task.Options.Output != "" {
				_ = fileutil.CreateFolder(task.Options.Output)
				outputFile = filepath.Join(task.Options.Output, fmt.Sprintf("%s.output", args[0]))
				args = append(args, "-o", outputFile)
			}
			hasToolDashboardUpload := stringsutil.EqualFoldAny(args[0], "httpx", "naabu", "tlsx")
			if hasToolDashboardUpload && (task.Options.EnumerationID != "" || task.Options.TeamID != "") {
				args = append(args,
					"-team-id", os.Getenv("PDCP_TEAM_ID"),
					"-dashboard",
					"-asset-id", manualAssetId,
				)
			}
			args = append(args, tool.Args...)
			if _, err := runCommand(ctx, envs, args); err != nil {
				return nil, nil, err
			}

			// Collect output file for cleanup
			if outputFile != "" {
				outputFiles = append(outputFiles, outputFile)
			}

			// if tool is naabu get the output for next steps
			if args[0] == "naabu" && outputFile != "" {
				c, err := fileutil.ReadFile(outputFile)
				if err != nil {
					return nil, nil, err
				}
				for line := range c {
					naabuOutput = append(naabuOutput, line)
				}
				naabuOutputFile = outputFile
				// attempt to update existing asset
				// upload naabu output
				assetId, err := uploadToCloudWithId(ctx, task, naabuOutputFile, task.Options.EnumerationID)
				// if updating fails, upload to a new manual asset
				if err == nil {
					manualAssetId = assetId
				} else {
					manualAssetId, err = uploadToCloud(ctx, task, naabuOutputFile)
					if err != nil {
						return nil, nil, err
					}
				}
			}
		}
		return nil, outputFiles, nil
	}

	return nil, nil, nil
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

type Tool struct {
	Name string
	Args []string
}

func getToolsFromSteps(steps []string) []Tool {
	var tools []Tool
	if sliceutil.Contains(steps, "dns_resolve") {
		tools = append(tools, Tool{Name: "dnsx"})
	}
	if sliceutil.Contains(steps, "port_scan") {
		tool := Tool{Name: "naabu"}
		if sliceutil.Contains(steps, "ports_service_scan") {
			tool.Args = append(tool.Args, "-nmap-cli", "nmap -sV -Pn")
		}
		tools = append(tools, tool)
	}
	if sliceutil.Contains(steps, "http_probe") {
		tool := Tool{Name: "httpx"}
		if sliceutil.Contains(steps, "http_screenshot") {
			tool.Args = append(tool.Args, "-screenshot")
		}
		tools = append(tools, tool)
	}
	if sliceutil.Contains(steps, "tls_scan") {
		tools = append(tools, Tool{Name: "tlsx"})
	}
	return tools
}

func uploadToCloud(ctx context.Context, _ *types.Task, outputFile string) (string, error) {
	gologger.Verbose().Msgf("uploading to cloud: %s", outputFile)
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
	fmt.Println(string(body))
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
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	fmt.Println(string(body))
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
		gologger.Verbose().Msgf("Unable to determine system RAM: %v, defaulting to disabling code templates", err)
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
		gologger.Verbose().Msgf("Unable to determine system RAM: %v, defaulting to disabling headless mode", err)
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
	gologger.Info().Msgf("Running:\nCMD: %s\nENVS: %s\nARGS: %s", args[0], envs, args)

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

	gologger.Info().Msgf("Stdout:\n%s\nStderr:\n%s", string(stdoutOutput), string(stderrOutput))

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
