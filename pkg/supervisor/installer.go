package supervisor

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/projectdiscovery/gologger"
)

// Installer handles Docker installation and updates
type Installer struct {
	platform string
}

// NewInstaller creates a new installer for the current platform
func NewInstaller() *Installer {
	return &Installer{
		platform: runtime.GOOS,
	}
}

// CheckDockerInstalled checks if Docker is installed
func (i *Installer) CheckDockerInstalled() (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "docker", "version")
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	return err == nil, nil
}

// CheckDockerRunning checks if Docker daemon is running
func (i *Installer) CheckDockerRunning() (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "docker", "info")
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	return err == nil, nil
}

// InstallDocker installs Docker based on the platform
func (i *Installer) InstallDocker() error {
	switch i.platform {
	case "linux":
		return i.installDockerLinux()
	case "darwin":
		return i.installDockerDarwin()
	case "windows":
		return i.installDockerWindows()
	default:
		return fmt.Errorf("unsupported platform: %s", i.platform)
	}
}

// UpdateDocker updates Docker if outdated
func (i *Installer) UpdateDocker() error {
	switch i.platform {
	case "linux":
		return i.updateDockerLinux()
	case "darwin":
		return i.updateDockerDarwin()
	case "windows":
		return i.updateDockerWindows()
	default:
		return fmt.Errorf("unsupported platform: %s", i.platform)
	}
}

// EnsureDocker ensures Docker is installed and running
func (i *Installer) EnsureDocker() error {
	// Check if Docker is installed
	installed, err := i.CheckDockerInstalled()
	if err != nil {
		return fmt.Errorf("failed to check Docker installation: %w", err)
	}

	if !installed {
		// On Linux, try to install automatically
		// On macOS/Windows, provide instructions
		if i.platform == "linux" {
			gologger.Info().Msg("Docker is not installed. Installing Docker...")
			if err := i.InstallDocker(); err != nil {
				return fmt.Errorf("failed to install Docker: %w", err)
			}
			gologger.Info().Msg("Docker installed successfully")
		} else {
			// macOS or Windows - provide installation instructions
			return i.getInstallationInstructions()
		}
	} else {
		gologger.Info().Msg("Docker is already installed")
	}

	// Check if Docker is running
	running, err := i.CheckDockerRunning()
	if err != nil {
		return fmt.Errorf("failed to check Docker daemon: %w", err)
	}

	if !running {
		if i.platform == "linux" {
			gologger.Info().Msg("Docker daemon is not running. Starting Docker...")
			if err := i.StartDocker(); err != nil {
				return fmt.Errorf("failed to start Docker: %w", err)
			}
			gologger.Info().Msg("Docker daemon started successfully")
		} else {
			// macOS or Windows - provide start instructions
			return i.getStartInstructions()
		}
	} else {
		gologger.Info().Msg("Docker daemon is running")
	}

	// Check and update Docker if needed (Linux only)
	if i.platform == "linux" {
		if err := i.UpdateDocker(); err != nil {
			gologger.Warning().Msgf("Failed to update Docker: %v", err)
			// Don't fail if update fails, Docker might already be up to date
		}
	}

	return nil
}

// StartDocker starts the Docker daemon
func (i *Installer) StartDocker() error {
	switch i.platform {
	case "linux":
		return i.startDockerLinux()
	case "darwin":
		return i.startDockerDarwin()
	case "windows":
		return i.startDockerWindows()
	default:
		return fmt.Errorf("unsupported platform: %s", i.platform)
	}
}

// GetDockerVersion gets the installed Docker version
func (i *Installer) GetDockerVersion() (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "docker", "version", "--format", "{{.Server.Version}}")
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(output)), nil
}

// getInstallationInstructions returns an error with installation instructions for macOS/Windows
func (i *Installer) getInstallationInstructions() error {
	var url string
	var platform string

	switch i.platform {
	case "darwin":
		url = "https://docs.docker.com/desktop/install/mac-install/"
		platform = "macOS"
	case "windows":
		url = "https://docs.docker.com/desktop/install/windows-install/"
		platform = "Windows"
	default:
		url = "https://docs.docker.com/get-docker/"
		platform = i.platform
	}

	return fmt.Errorf("docker is not installed. Docker Desktop is required for supervisor mode on %s. Please install Docker Desktop from: %s", platform, url)
}

// getStartInstructions returns an error with start instructions for macOS/Windows
func (i *Installer) getStartInstructions() error {
	var platform string

	switch i.platform {
	case "darwin":
		platform = "macOS"
	case "windows":
		platform = "Windows"
	default:
		platform = i.platform
	}

	return fmt.Errorf("docker daemon is not running. Please start Docker Desktop manually on %s", platform)
}
