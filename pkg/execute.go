package pkg

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/projectdiscovery/pdtm-agent/pkg/tools"
	"github.com/projectdiscovery/pdtm-agent/pkg/types"
	"github.com/projectdiscovery/utils/conversion"
	fileutil "github.com/projectdiscovery/utils/file"
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
		tools := []string{"dnsx", "naabu", "httpx", "tlsx"}
		// track naabu output as input to next steps
		var naabuOutput []string
		for _, tool := range tools {
			if len(naabuOutput) > 0 {
				task.Options.Hosts = append(task.Options.Hosts, naabuOutput...)
			}
			envs, args, removeFunc, err := parseGenericArgs(task)
			if err != nil {
				return err
			}
			defer removeFunc()
			args[0] = tool
			var outputFile string
			if task.Options.Output != "" {
				_ = fileutil.CreateFolder(task.Options.Output)
				outputFile = filepath.Join(task.Options.Output, fmt.Sprintf("%s.output", args[0]))
				args = append(args, "-o", outputFile)
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
			}
		}
	}

	return nil
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
		"PDCP_TEAM_ID=" + task.Options.TeamID,
	}
	return envs
}

func runCommand(ctx context.Context, envs, args []string) error {
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

	// Print the output
	fmt.Println("Stdout:")
	fmt.Println(string(stdoutOutput))
	fmt.Println("Stderr:")
	fmt.Println(string(stderrOutput))

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
