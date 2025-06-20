package pkg

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/pdtm-agent/pkg/client"
	"github.com/projectdiscovery/pdtm-agent/pkg/tools"
	"github.com/projectdiscovery/pdtm-agent/pkg/types"
	"github.com/projectdiscovery/utils/conversion"
	envutil "github.com/projectdiscovery/utils/env"
	fileutil "github.com/projectdiscovery/utils/file"
	mapsutil "github.com/projectdiscovery/utils/maps"
	sliceutil "github.com/projectdiscovery/utils/slice"
	stringsutil "github.com/projectdiscovery/utils/strings"
	"github.com/tidwall/gjson"
)

func Run(ctx context.Context, task *types.Task) (*types.TaskResult, error) {
	toolList, err := tools.FetchFromCache()
	if err != nil {
		return nil, errors.New("pdtm api is down, please try again later")
	}

	var tool *types.Tool
	for _, candidateTool := range toolList {
		if candidateTool.Name == task.Tool.String() {
			tool = &candidateTool
			break
		}
	}

	if tool == nil {
		return nil, fmt.Errorf("tool '%s' not found", task.Tool.String())
	}

	if task.Options.ScanID != "" {
		envs, args, removeFunc, err := parseScanArgs(ctx, task)
		if err != nil {
			return nil, err
		}
		defer removeFunc()

		taskResult, err := runCommand(ctx, envs, args)
		if err != nil {
			log.Fatal(err)
			return nil, err
		}

		ExtractUnresponsiveHosts(taskResult)

		return taskResult, nil
	} else if task.Options.EnumerationID != "" {
		// run: dnsx | naabu | httpx - for now execute all the tools in parallel
		// for the time being we ignore the steps from cloud
		// uploads are performed to different ids - the api was not designed with assets associated to specific enumeration id
		tools := getToolsFromSteps(task.Options.Steps)
		// track naabu output as input to next steps
		var (
			naabuOutput     []string
			naabuOutputFile string
			manualAssetId   string
		)
		for _, tool := range tools {
			if len(naabuOutput) > 0 {
				task.Options.Hosts = append(task.Options.Hosts, naabuOutput...)
			}
			// todo: remove this patch for testing
			// task.Options.Hosts = []string{"192.168.179.2:8000"}
			envs, args, removeFunc, err := parseGenericArgs(task)
			if err != nil {
				return nil, err
			}
			defer removeFunc()
			args[0] = tool.Name
			var outputFile string
			// handle per tool specific args
			if task.Options.Output != "" {
				_ = fileutil.CreateFolder(task.Options.Output)
				outputFile = filepath.Join(task.Options.Output, fmt.Sprintf("%s.output", args[0]))
				args = append(args, "-o", outputFile)
			}
			if args[0] == "httpx" && (task.Options.EnumerationID != "" || task.Options.TeamID != "") {
				args = append(args,
					"-team-id", os.Getenv("PDCP_TEAM_ID"),
					"-dashboard",
					"-asset-id", manualAssetId,
				)
			}
			args = append(args, tool.Args...)
			if _, err := runCommand(ctx, envs, args); err != nil {
				return nil, err
			}
			// if tool is naabu get the output for next steps
			if args[0] == "naabu" && outputFile != "" {
				c, err := fileutil.ReadFile(outputFile)
				if err != nil {
					return nil, err
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
						return nil, err
					}
				}
			}
		}
	}

	return nil, nil
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
	log.Printf("uploading to cloud: %s", outputFile)
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

func parseScanArgs(_ context.Context, task *types.Task) (envs, args []string, removeFunc func(), err error) {
	args = append(args, task.Tool.String())
	if len(task.Options.Templates) > 0 {
		args = append(args, "-templates", strings.Join(task.Options.Templates, ","))
		// ODO: temporary to have some results
		// args = append(args, "-id", "http-missing-security-headers")
	}

	if task.Options.TeamID != "" {
		args = append(args, "-team-id", task.Options.TeamID)
	}

	tmpInputFile, tmpConfigFile, removeFunc, err := prepareInput(task)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create temp file: %w", err)
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

	if task.Options.Output != "" {
		_ = fileutil.CreateFolder(task.Options.Output)
		outputFile := filepath.Join(task.Options.Output, fmt.Sprintf("%s.output", args[0]))
		args = append(args, "-o", outputFile)
	}

	return envs, args, removeFunc, nil
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
	defaultPDCPAPIServer := envutil.GetEnvOrDefault("PDCP_API_SERVER", "https://api.dev.projectdiscovery.io")
	envs := []string{
		"PDCP_DASHBOARD_URL=" + defaultPDCPDashboardURL,
		"PDCP_API_SERVER=" + defaultPDCPAPIServer,
		"PDCP_API_KEY=" + os.Getenv("PDCP_API_KEY"),
		"HOME=" + os.Getenv("HOME"),
		"PDCP_TEAM_ID=" + os.Getenv("PDCP_TEAM_ID"),
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
		return taskResult, fmt.Errorf("failed to execute tool '%s': %w\nStdout: %s\nStderr: %s", args[0], err, string(stdoutOutput), string(stderrOutput))
	}

	gologger.Info().Msgf("Stdout:\n%s\nStderr:\n%s", string(stdoutOutput), string(stderrOutput))

	return taskResult, nil
}

func parseGenericArgs(task *types.Task) (envs, args []string, removeFunc func(), err error) {
	envs = getEnvs()

	args = append(args, task.Tool.String())

	tmpFile, _, removeFunc, err := prepareInput(task)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create temp file: %w", err)
	}

	args = append(args,
		"-silent",
		"-l", tmpFile,
	)

	return envs, args, removeFunc, nil
}
