//go:build windows
// +build windows

package supervisor

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/projectdiscovery/gologger"
)

// installDockerWindows is not implemented - Docker must be installed manually on Windows
func (i *Installer) installDockerWindows() error {
	return fmt.Errorf("Docker installation is not supported on Windows. Please install Docker Desktop manually")
}

// updateDockerWindows is not implemented - Docker updates must be done manually on Windows
func (i *Installer) updateDockerWindows() error {
	gologger.Info().Msg("Docker Desktop updates must be done manually. Please update Docker Desktop from the application.")
	return nil
}

// startDockerWindows starts Docker Desktop on Windows
func (i *Installer) startDockerWindows() error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Check if Docker Desktop is already running
	if running, _ := i.CheckDockerRunning(); running {
		return nil
	}

	// Try to start Docker Desktop
	dockerPath := filepath.Join(os.Getenv("ProgramFiles"), "Docker", "Docker", "Docker Desktop.exe")
	if _, err := os.Stat(dockerPath); os.IsNotExist(err) {
		return fmt.Errorf("Docker Desktop not found at %s. Please install Docker Desktop first", dockerPath)
	}

	cmd := exec.CommandContext(ctx, dockerPath)
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start Docker Desktop: %w. Please start Docker Desktop manually", err)
	}

	return i.waitForDockerWindows(ctx)
}

// waitForDockerWindows waits for Docker to become available on Windows
func (i *Installer) waitForDockerWindows(ctx context.Context) error {
	timeout := time.After(2 * time.Minute)
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timeout:
			return fmt.Errorf("timeout waiting for Docker to start")
		case <-ticker.C:
			if running, _ := i.CheckDockerRunning(); running {
				return nil
			}
		}
	}
}
