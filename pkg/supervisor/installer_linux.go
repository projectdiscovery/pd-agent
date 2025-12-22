//go:build linux
// +build linux

package supervisor

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"strings"
	"time"

	"github.com/projectdiscovery/gologger"
)

// installDockerLinux installs Docker on Linux
func (i *Installer) installDockerLinux() error {
	// Detect package manager
	packageManager, err := i.detectPackageManager()
	if err != nil {
		return fmt.Errorf("failed to detect package manager: %w", err)
	}

	gologger.Info().Msgf("Detected package manager: %s", packageManager)

	// Check if running as root
	if os.Geteuid() != 0 {
		return fmt.Errorf("Docker installation requires root privileges. Please run with sudo")
	}

	// Install Docker based on package manager
	switch packageManager {
	case "apt":
		return i.installDockerApt()
	case "yum":
		return i.installDockerYum()
	case "dnf":
		return i.installDockerDnf()
	default:
		return fmt.Errorf("unsupported package manager: %s", packageManager)
	}
}

// updateDockerLinux updates Docker on Linux
func (i *Installer) updateDockerLinux() error {
	packageManager, err := i.detectPackageManager()
	if err != nil {
		return err
	}

	if os.Geteuid() != 0 {
		gologger.Warning().Msg("Docker update requires root privileges. Skipping update.")
		return nil
	}

	switch packageManager {
	case "apt":
		return i.updateDockerApt()
	case "yum", "dnf":
		return i.updateDockerYumDnf()
	default:
		return nil
	}
}

// startDockerLinux starts Docker daemon on Linux
func (i *Installer) startDockerLinux() error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Try systemd first
	cmd := exec.CommandContext(ctx, "systemctl", "start", "docker")
	if err := cmd.Run(); err == nil {
		// Enable Docker to start on boot
		_ = exec.Command("systemctl", "enable", "docker").Run()
		return nil
	}

	// Fallback to service command
	cmd = exec.CommandContext(ctx, "service", "docker", "start")
	return cmd.Run()
}

// detectPackageManager detects the Linux package manager
func (i *Installer) detectPackageManager() (string, error) {
	// Check for apt
	if _, err := exec.LookPath("apt-get"); err == nil {
		return "apt", nil
	}

	// Check for yum
	if _, err := exec.LookPath("yum"); err == nil {
		return "yum", nil
	}

	// Check for dnf
	if _, err := exec.LookPath("dnf"); err == nil {
		return "dnf", nil
	}

	return "", fmt.Errorf("no supported package manager found (apt, yum, or dnf)")
}

// installDockerApt installs Docker on Debian/Ubuntu using apt
func (i *Installer) installDockerApt() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	// Update package index
	gologger.Info().Msg("Updating package index...")
	cmd := exec.CommandContext(ctx, "apt-get", "update", "-y")
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to update package index: %w", err)
	}

	// Install prerequisites
	gologger.Info().Msg("Installing prerequisites...")
	cmd = exec.CommandContext(ctx, "apt-get", "install", "-y",
		"ca-certificates",
		"curl",
		"gnupg",
		"lsb-release")
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to install prerequisites: %w", err)
	}

	// Add Docker's official GPG key
	gologger.Info().Msg("Adding Docker's GPG key...")
	cmd = exec.CommandContext(ctx, "sh", "-c", "curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg")
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		// Try alternative method
		cmd = exec.CommandContext(ctx, "sh", "-c", "curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg")
		cmd.Stdout = os.Stderr
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to add Docker GPG key: %w", err)
		}
	}

	// Detect distribution
	distro := "ubuntu"
	if _, err := os.Stat("/etc/debian_version"); err == nil {
		// Check if it's actually Debian
		if content, err := os.ReadFile("/etc/os-release"); err == nil {
			if strings.Contains(strings.ToLower(string(content)), "debian") {
				distro = "debian"
			}
		}
	}

	// Detect architecture
	arch := "amd64"
	if runtime.GOARCH == "arm64" {
		arch = "arm64"
	}

	// Add Docker repository
	gologger.Info().Msgf("Adding Docker repository for %s/%s...", distro, arch)
	repo := fmt.Sprintf("deb [arch=%s signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/%s $(lsb_release -cs) stable", arch, distro)
	cmd = exec.CommandContext(ctx, "sh", "-c", fmt.Sprintf("echo %q >> /etc/apt/sources.list.d/docker.list", repo))
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to add Docker repository: %w", err)
	}

	// Update package index again
	gologger.Info().Msg("Updating package index with Docker repository...")
	cmd = exec.CommandContext(ctx, "apt-get", "update", "-y")
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to update package index: %w", err)
	}

	// Install Docker
	gologger.Info().Msg("Installing Docker...")
	cmd = exec.CommandContext(ctx, "apt-get", "install", "-y",
		"docker-ce",
		"docker-ce-cli",
		"containerd.io",
		"docker-buildx-plugin",
		"docker-compose-plugin")
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to install Docker: %w", err)
	}

	// Add current user to docker group
	if err := i.addUserToDockerGroup(); err != nil {
		gologger.Warning().Msgf("Failed to add user to docker group: %v", err)
	}

	// Start Docker service
	if err := i.startDockerLinux(); err != nil {
		return fmt.Errorf("failed to start Docker service: %w", err)
	}

	gologger.Info().Msg("Docker installed successfully")
	return nil
}

// installDockerYum installs Docker on RHEL/CentOS using yum
func (i *Installer) installDockerYum() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	// Install prerequisites
	gologger.Info().Msg("Installing prerequisites...")
	cmd := exec.CommandContext(ctx, "yum", "install", "-y",
		"yum-utils",
		"device-mapper-persistent-data",
		"lvm2")
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to install prerequisites: %w", err)
	}

	// Add Docker repository
	gologger.Info().Msg("Adding Docker repository...")
	cmd = exec.CommandContext(ctx, "yum-config-manager", "--add-repo", "https://download.docker.com/linux/centos/docker-ce.repo")
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to add Docker repository: %w", err)
	}

	// Install Docker
	gologger.Info().Msg("Installing Docker...")
	cmd = exec.CommandContext(ctx, "yum", "install", "-y",
		"docker-ce",
		"docker-ce-cli",
		"containerd.io",
		"docker-buildx-plugin",
		"docker-compose-plugin")
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to install Docker: %w", err)
	}

	// Add current user to docker group
	if err := i.addUserToDockerGroup(); err != nil {
		gologger.Warning().Msgf("Failed to add user to docker group: %v", err)
	}

	// Start Docker service
	if err := i.startDockerLinux(); err != nil {
		return fmt.Errorf("failed to start Docker service: %w", err)
	}

	gologger.Info().Msg("Docker installed successfully")
	return nil
}

// installDockerDnf installs Docker on Fedora using dnf
func (i *Installer) installDockerDnf() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	// Install prerequisites
	gologger.Info().Msg("Installing prerequisites...")
	cmd := exec.CommandContext(ctx, "dnf", "install", "-y",
		"dnf-plugins-core")
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to install prerequisites: %w", err)
	}

	// Add Docker repository
	gologger.Info().Msg("Adding Docker repository...")
	cmd = exec.CommandContext(ctx, "dnf", "config-manager", "--add-repo", "https://download.docker.com/linux/fedora/docker-ce.repo")
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to add Docker repository: %w", err)
	}

	// Install Docker
	gologger.Info().Msg("Installing Docker...")
	cmd = exec.CommandContext(ctx, "dnf", "install", "-y",
		"docker-ce",
		"docker-ce-cli",
		"containerd.io",
		"docker-buildx-plugin",
		"docker-compose-plugin")
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to install Docker: %w", err)
	}

	// Add current user to docker group
	if err := i.addUserToDockerGroup(); err != nil {
		gologger.Warning().Msgf("Failed to add user to docker group: %v", err)
	}

	// Start Docker service
	if err := i.startDockerLinux(); err != nil {
		return fmt.Errorf("failed to start Docker service: %w", err)
	}

	gologger.Info().Msg("Docker installed successfully")
	return nil
}

// updateDockerApt updates Docker on Debian/Ubuntu
func (i *Installer) updateDockerApt() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	gologger.Info().Msg("Updating Docker packages...")
	cmd := exec.CommandContext(ctx, "apt-get", "update", "-y")
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return err
	}

	cmd = exec.CommandContext(ctx, "apt-get", "upgrade", "-y",
		"docker-ce",
		"docker-ce-cli",
		"containerd.io",
		"docker-buildx-plugin",
		"docker-compose-plugin")
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// updateDockerYumDnf updates Docker on RHEL/CentOS/Fedora
func (i *Installer) updateDockerYumDnf() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	packageManager := "yum"
	if _, err := exec.LookPath("dnf"); err == nil {
		packageManager = "dnf"
	}

	gologger.Info().Msgf("Updating Docker packages using %s...", packageManager)
	cmd := exec.CommandContext(ctx, packageManager, "update", "-y",
		"docker-ce",
		"docker-ce-cli",
		"containerd.io",
		"docker-buildx-plugin",
		"docker-compose-plugin")
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// addUserToDockerGroup adds the current user to the docker group
func (i *Installer) addUserToDockerGroup() error {
	currentUser, err := user.Current()
	if err != nil {
		return err
	}

	// Check if user is already in docker group
	cmd := exec.Command("groups", currentUser.Username)
	output, err := cmd.Output()
	if err == nil && strings.Contains(string(output), "docker") {
		return nil // Already in group
	}

	// Add user to docker group
	cmd = exec.Command("usermod", "-aG", "docker", currentUser.Username)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return err
	}

	gologger.Info().Msgf("Added user %s to docker group. You may need to log out and back in for changes to take effect.", currentUser.Username)
	return nil
}

