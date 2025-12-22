//go:build !linux
// +build !linux

package supervisor

import "fmt"

func (i *Installer) installDockerLinux() error {
	return fmt.Errorf("docker installation not supported on this platform")
}

func (i *Installer) updateDockerLinux() error {
	return fmt.Errorf("docker update not supported on this platform")
}

func (i *Installer) startDockerLinux() error {
	return fmt.Errorf("docker start not supported on this platform")
}

