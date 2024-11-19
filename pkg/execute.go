package pkg

import (
	"errors"
	"fmt"
	"io"
	"os/exec"

	"github.com/projectdiscovery/pdtm-agent/pkg/tools"
	"github.com/projectdiscovery/pdtm-agent/pkg/types"
)

func Run(task *types.Task) error {
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

	var id string
	switch {
	case task.Options.ScanID != "":
		id = task.Options.ScanID
	case task.Options.EnumerationID != "":
		id = task.Options.EnumerationID
	}

	if id != "" {
		args = append(args, "-cloud-upload", id)
	}

	if task.Options.TeamID != "" {
		args = append(args, "-team-id", task.Options.TeamID)
	}

	// Prepare the command
	cmd := exec.Command(args[0], args[1:]...)

	// Set up stdin, stdout, and stderr pipes
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("failed to create stdin pipe: %w", err)
	}
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

	// Write input to stdin if provided
	for _, host := range task.Options.Hosts {
		if _, err := stdin.Write([]byte(host + "\n")); err != nil {
			return fmt.Errorf("failed to write to stdin: %w", err)
		}
	}
	stdin.Close()

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
