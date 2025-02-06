package pkg

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/pdtm-agent/pkg/client"
	"github.com/projectdiscovery/pdtm-agent/pkg/tools"
	"github.com/projectdiscovery/pdtm-agent/pkg/types"
	pdcpauth "github.com/projectdiscovery/utils/auth/pdcp"
	"github.com/projectdiscovery/utils/conversion"
	fileutil "github.com/projectdiscovery/utils/file"
	sliceutil "github.com/projectdiscovery/utils/slice"
	"github.com/tidwall/gjson"
)

func Run(ctx context.Context, task *types.Task) error {
	toolList, err := tools.FetchFromCache()
	if err != nil {
		return errors.New("pdtm api is down, please try again later")
	}

	var tool *types.Tool
	for _, candidateTool := range toolList {
		if candidateTool.Name == task.Tool.String() {
			tool = &candidateTool
			break
		}
	}

	if tool == nil {
		return fmt.Errorf("tool '%s' not found", task.Tool.String())
	}

	if task.Options.ScanID != "" {
		envs, args, removeFunc, err := parseScanArgs(ctx, task)
		if err != nil {
			return err
		}
		defer removeFunc()
		return runCommand(ctx, envs, args)
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
				return err
			}
			defer removeFunc()
			args[0] = tool
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
			if err := runCommand(ctx, envs, args); err != nil {
				return err
			}
			// if tool is naabu get the output for next steps
			if args[0] == "naabu" && outputFile != "" {
				c, err := fileutil.ReadFile(outputFile)
				if err != nil {
					return err
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
						return err
					}
				}
			}
		}
	}

	return nil
}

func getToolsFromSteps(steps []string) []string {
	var tools []string
	if sliceutil.Contains(steps, "dns_resolve") {
		tools = append(tools, "dnsx")
	}
	if sliceutil.Contains(steps, "port_scan") {
		tools = append(tools, "naabu")
	}
	if sliceutil.Contains(steps, "http_probe") {
		tools = append(tools, "httpx")
	}
	if sliceutil.Contains(steps, "tls_scan") {
		tools = append(tools, "tlsx")
	}
	// todo: add dns_permute - dns_bruteforce - passive_nuclei_scan - vulnerability_scan
	return tools
}

func uploadToCloud(ctx context.Context, task *types.Task, outputFile string) (string, error) {
	f, err := os.Open(outputFile)
	if err != nil {
		return "", err
	}
	defer f.Close()
	apiURL := fmt.Sprintf("%s/v1/assets", pdcpauth.DefaultApiServer)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL, f)
	if err != nil {
		return "", err
	}
	defer req.Body.Close()

	req.Header.Set("Content-Type", "application/octet-stream")

	client, err := client.CreateAuthenticatedClient(os.Getenv("PDCP_TEAM_ID"), "", os.Getenv("PDCP_API_KEY"))
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
	defer f.Close()
	apiURL := fmt.Sprintf("%s/v1/assets/%s/contents?upload_type=append", pdcpauth.DefaultApiServer, assetId)
	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, apiURL, f)
	if err != nil {
		return "", err
	}
	defer req.Body.Close()

	req.Header.Set("Content-Type", "application/octet-stream")

	client, err := client.CreateAuthenticatedClient(os.Getenv("PDCP_TEAM_ID"), "", os.Getenv("PDCP_API_KEY"))
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
	}

	if task.Options.TeamID != "" {
		args = append(args, "-team-id", task.Options.TeamID)
	}

	tmpFile, removeFunc, err := prepareInput(task)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create temp file: %w", err)
	}

	args = append(args, "-l", tmpFile)

	if task.Options.ScanID != "" || task.Options.TeamID != "" {
		envs = getEnvs(task)
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

func prepareInput(task *types.Task) (string, func(), error) {
	tmpFile, err := fileutil.GetTempFileName()
	if err != nil {
		return "", nil, fmt.Errorf("failed to create temp file: %w", err)
	}
	allTargets := strings.Join(task.Options.Hosts, "\n")
	if err := os.WriteFile(tmpFile, conversion.Bytes(allTargets), os.ModePerm); err != nil {
		return "", nil, fmt.Errorf("failed to write to temp file: %w", err)
	}
	removeFunc := func() {
		os.RemoveAll(tmpFile)
	}
	return tmpFile, removeFunc, nil
}

func getEnvs(task *types.Task) []string {
	envs := []string{
		"PDCP_DASHBOARD_URL=https://cloud.projectdiscovery.io",
		"PDCP_API_SERVER=https://api.dev.projectdiscovery.io",
		"PDCP_API_KEY=" + os.Getenv("PDCP_API_KEY"),
		"HOME=" + os.Getenv("HOME"),
		"PDCP_TEAM_ID=" + os.Getenv("PDCP_TEAM_ID"),
	}
	return envs
}

func runCommand(ctx context.Context, envs, args []string) error {
	gologger.Info().Msgf("Running:\nCMD: %s\nENVS: %s\nARGS: %s", args[0], envs, args)

	// Prepare the command
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)

	cmd.Env = append(cmd.Env, envs...)

	// Set up stdin, stdout, and stderr pipes
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("failed to create stdout pipe: %w", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("failed to create stderr pipe: %w", err)
	}

	// Start the command
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start tool '%s': %w", args[0], err)
	}

	// Read stdout and stderr
	stdoutOutput, err := io.ReadAll(stdout)
	if err != nil {
		return fmt.Errorf("failed to read stdout: %w", err)
	}
	stderrOutput, err := io.ReadAll(stderr)
	if err != nil {
		return fmt.Errorf("failed to read stderr: %w", err)
	}

	// Wait for the command to finish
	if err := cmd.Wait(); err != nil {
		return fmt.Errorf("failed to execute tool '%s': %w\nStderr: %s", args[0], err, string(stderrOutput))
	}

	gologger.Info().Msgf("Stdout:\n%s\nStderr:\n%s", string(stdoutOutput), string(stderrOutput))

	return nil
}

func parseGenericArgs(task *types.Task) (envs, args []string, removeFunc func(), err error) {
	envs = getEnvs(task)

	args = append(args, task.Tool.String())

	tmpFile, removeFunc, err := prepareInput(task)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create temp file: %w", err)
	}

	args = append(args,
		"-silent",
		"-l", tmpFile,
	)

	return envs, args, removeFunc, nil
}
