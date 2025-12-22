//go:build !darwin
// +build !darwin

package supervisor

import "fmt"

func (i *Installer) installDockerDarwin() error {
	return fmt.Errorf("Docker installation not supported on this platform")
}

func (i *Installer) updateDockerDarwin() error {
	return fmt.Errorf("Docker update not supported on this platform")
}

func (i *Installer) startDockerDarwin() error {
	return fmt.Errorf("Docker start not supported on this platform")
}

