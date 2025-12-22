package supervisor

import (
	"context"
	"fmt"
	"io"
)

// DockerProvider implements the Provider interface for Docker deployments
type DockerProvider struct {
	client *DockerClient
}

// NewDockerProvider creates a new Docker provider
func NewDockerProvider() (*DockerProvider, error) {
	client, err := NewDockerClient()
	if err != nil {
		return nil, fmt.Errorf("failed to create Docker client: %w", err)
	}

	return &DockerProvider{client: client}, nil
}

// Name returns the provider name
func (d *DockerProvider) Name() string {
	return "docker"
}

// IsAvailable checks if Docker is installed and running
func (d *DockerProvider) IsAvailable(ctx context.Context) bool {
	if d.client == nil {
		return false
	}
	return d.client.IsDockerRunning()
}

// PullImage pulls a Docker image
func (d *DockerProvider) PullImage(ctx context.Context, image string) error {
	return d.client.PullImage(ctx, image)
}

// Deploy deploys a Docker container
func (d *DockerProvider) Deploy(ctx context.Context, config *DeploymentConfig) (string, error) {
	// Convert DeploymentConfig to ContainerConfig
	containerConfig := &ContainerConfig{
		Image:       config.Image,
		Name:        config.Name,
		Env:         config.Env,
		Volumes:     config.Volumes,
		NetworkMode: config.NetworkMode,
		CapAdd:      config.CapAdd,
		Cmd:         config.Cmd,
		Restart:     config.Restart,
	}

	return d.client.RunContainer(ctx, containerConfig)
}

// Stop stops a Docker container
func (d *DockerProvider) Stop(ctx context.Context, deploymentID string, timeout *int) error {
	return d.client.StopContainer(ctx, deploymentID, timeout)
}

// Remove removes a Docker container
func (d *DockerProvider) Remove(ctx context.Context, deploymentID string) error {
	return d.client.RemoveContainer(ctx, deploymentID)
}

// Start starts an existing Docker container
func (d *DockerProvider) Start(ctx context.Context, deploymentID string) error {
	return d.client.StartContainer(ctx, deploymentID)
}

// Inspect inspects a Docker container
func (d *DockerProvider) Inspect(ctx context.Context, deploymentID string) (*DeploymentInfo, error) {
	info, err := d.client.InspectContainer(ctx, deploymentID)
	if err != nil {
		return nil, err
	}

	return &DeploymentInfo{
		ID:       info.ID,
		Status:   info.Status,
		Running:  info.Running,
		ExitCode: info.ExitCode,
		ImageID:  info.ImageID,
	}, nil
}

// GetLogs gets container logs
func (d *DockerProvider) GetLogs(ctx context.Context, deploymentID string, follow bool) (io.ReadCloser, error) {
	return d.client.GetContainerLogs(ctx, deploymentID, follow)
}

// FindByName finds a container by name
func (d *DockerProvider) FindByName(ctx context.Context, name string) (string, error) {
	return d.client.FindContainerByName(ctx, name)
}

// Exists checks if a container exists
func (d *DockerProvider) Exists(ctx context.Context, name string) bool {
	return d.client.ContainerExists(ctx, name)
}

// GetImageID gets the current image ID for a given image reference
func (d *DockerProvider) GetImageID(ctx context.Context, imageRef string) (string, error) {
	return d.client.GetImageID(ctx, imageRef)
}

// FindByPrefix finds all containers with names starting with the given prefix
func (d *DockerProvider) FindByPrefix(ctx context.Context, prefix string) ([]string, error) {
	return d.client.FindContainersByPrefix(ctx, prefix)
}

