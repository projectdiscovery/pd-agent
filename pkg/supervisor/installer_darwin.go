//go:build darwin
// +build darwin

package supervisor

import (
	"context"
	"fmt"
	"os/exec"
	"time"

	"github.com/projectdiscovery/gologger"
)

// installDockerDarwin is not implemented - Docker must be installed manually on macOS
func (i *Installer) installDockerDarwin() error {
	return fmt.Errorf("docker installation is not supported on macOS. Please install Docker Desktop manually")
}


// updateDockerDarwin is not implemented - Docker updates must be done manually on macOS
func (i *Installer) updateDockerDarwin() error {
	gologger.Info().Msg("docker Desktop updates must be done manually. Please update Docker Desktop from the application.")
	return nil
}

// startDockerDarwin starts Docker Desktop on macOS
func (i *Installer) startDockerDarwin() error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Check if Docker Desktop is already running
	if running, _ := i.CheckDockerRunning(); running {
		return nil
	}

	// Try to start Docker Desktop
	cmd := exec.CommandContext(ctx, "open", "-a", "Docker")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to start Docker Desktop: %w. Please start it manually from Applications", err)
	}

	return i.waitForDocker(ctx)
}

// waitForDocker waits for Docker to become available
func (i *Installer) waitForDocker(ctx context.Context) error {
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
