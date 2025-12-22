//go:build !windows
// +build !windows

package supervisor

import "fmt"

func (i *Installer) installDockerWindows() error {
	return fmt.Errorf("docker installation not supported on this platform")
}

func (i *Installer) updateDockerWindows() error {
	return fmt.Errorf("docker update not supported on this platform")
}

func (i *Installer) startDockerWindows() error {
	return fmt.Errorf("docker start not supported on this platform")
}

