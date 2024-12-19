package pkg

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
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

	args := []string{
		task.Tool.String(),
	}

	var (
		isScan bool // TODO: temporary helper boolean
	)

	var id string
	switch {
	case task.Options.ScanID != "":
		id = task.Options.ScanID
		isScan = true
	case task.Options.EnumerationID != "":
		id = task.Options.EnumerationID
	}

	if isScan && len(task.Options.Templates) > 0 {
		args = append(args, "-templates", strings.Join(task.Options.Templates, ","))
	}

	if task.Options.TeamID != "" {
		args = append(args, "-team-id", task.Options.TeamID)
	}

	tmpFile, err := fileutil.GetTempFileName()
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	allTargets := strings.Join(task.Options.Hosts, "\n")
	if err := os.WriteFile(tmpFile, conversion.Bytes(allTargets), os.ModePerm); err != nil {
		return fmt.Errorf("failed to write to temp file: %w", err)
	}
	defer os.RemoveAll(tmpFile)

	args = append(args, "-l", tmpFile)

	var envs []string
	if id != "" || task.Options.TeamID != "" {
		envs = append(envs,
			"PDCP_DASHBOARD_URL=https://cloud.projectdiscovery.io",
			"PDCP_API_SERVER=https://api.dev.projectdiscovery.io",
			"PDCP_API_KEY="+os.Getenv("PDCP_API_KEY"),
			"PDCP_TEAM_ID="+task.Options.TeamID,
		)
		args = append(args, "-dashboard",
			"-scan-id", id,
		)
	}

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
		return fmt.Errorf("failed to start tool '%s': %w", tool.Name, err)
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
		return fmt.Errorf("failed to execute tool '%s': %w\nStderr: %s", tool.Name, err, string(stderrOutput))
	}

	// Print the output
	fmt.Println("Stdout:")
	fmt.Println(string(stdoutOutput))
	fmt.Println("Stderr:")
	fmt.Println(string(stderrOutput))

	return nil
}
