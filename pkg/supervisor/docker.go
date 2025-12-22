package supervisor

import (
	"context"
	"fmt"
	"io"
	"time"

	mobyclient "github.com/moby/moby/client"
	mobyimage "github.com/moby/moby/api/types/image"
	dockersdk "github.com/docker/go-sdk/client"
	"github.com/projectdiscovery/gologger"
)

// DockerClient wraps the Docker API client
type DockerClient struct {
	client dockersdk.SDKClient
}

// ContainerInfo represents container inspection information
type ContainerInfo struct {
	ID       string
	Status   string
	Running  bool
	ExitCode int
	ImageID  string // Image ID the container is using
}

// NewDockerClient creates a new Docker client
func NewDockerClient() (*DockerClient, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	dockerClient, err := dockersdk.New(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create Docker client: %w", err)
	}

	// Test connection
	_, err = dockerClient.Ping(ctx, mobyclient.PingOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Docker daemon: %w", err)
	}

	return &DockerClient{client: dockerClient}, nil
}

// IsDockerInstalled checks if Docker is installed
func (d *DockerClient) IsDockerInstalled() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := dockersdk.New(ctx)
	return err == nil
}

// IsDockerRunning checks if Docker daemon is running
func (d *DockerClient) IsDockerRunning() bool {
	if d == nil || d.client == nil {
		return false
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := d.client.Ping(ctx, mobyclient.PingOptions{})
	return err == nil
}

// PullImage pulls a Docker image
func (d *DockerClient) PullImage(ctx context.Context, img string) error {
	gologger.Info().Msgf("Pulling Docker image: %s", img)

	reader, err := d.client.ImagePull(ctx, img, mobyclient.ImagePullOptions{})
	if err != nil {
		return fmt.Errorf("failed to pull image: %w", err)
	}
	defer func() {
		_ = reader.Close()
	}()

	// Read the output to completion
	_, err = io.Copy(io.Discard, reader)
	if err != nil {
		return fmt.Errorf("failed to read pull output: %w", err)
	}

	gologger.Info().Msgf("Successfully pulled image: %s", img)
	return nil
}

// RunContainer runs a Docker container
func (d *DockerClient) RunContainer(ctx context.Context, config *ContainerConfig) (string, error) {
	containerConfig, hostConfig := config.ToDockerConfig()

	// Create container
	resp, err := d.client.ContainerCreate(ctx, mobyclient.ContainerCreateOptions{
		Config:     containerConfig,
		HostConfig: hostConfig,
		Name:       config.Name,
	})
	if err != nil {
		return "", fmt.Errorf("failed to create container: %w", err)
	}

	// Start container
	if _, err := d.client.ContainerStart(ctx, resp.ID, mobyclient.ContainerStartOptions{}); err != nil {
		// Clean up container if start fails
		_, _ = d.client.ContainerRemove(ctx, resp.ID, mobyclient.ContainerRemoveOptions{Force: true})
		return "", fmt.Errorf("failed to start container: %w", err)
	}

	gologger.Info().Msgf("Started container: %s (ID: %s)", config.Name, resp.ID[:12])
	return resp.ID, nil
}

// StopContainer stops a Docker container
func (d *DockerClient) StopContainer(ctx context.Context, containerID string, timeout *int) error {
	if timeout == nil {
		defaultTimeout := 10
		timeout = &defaultTimeout
	}

	gologger.Info().Msgf("Stopping container: %s", containerID[:12])
	_, err := d.client.ContainerStop(ctx, containerID, mobyclient.ContainerStopOptions{Timeout: timeout})
	if err != nil {
		return fmt.Errorf("failed to stop container: %w", err)
	}

	gologger.Info().Msgf("Stopped container: %s", containerID[:12])
	return nil
}

// RemoveContainer removes a Docker container
func (d *DockerClient) RemoveContainer(ctx context.Context, containerID string) error {
	gologger.Info().Msgf("Removing container: %s", containerID[:12])
	_, err := d.client.ContainerRemove(ctx, containerID, mobyclient.ContainerRemoveOptions{Force: true})
	if err != nil {
		return fmt.Errorf("failed to remove container: %w", err)
	}

	gologger.Info().Msgf("Removed container: %s", containerID[:12])
	return nil
}

// InspectContainer inspects a Docker container
func (d *DockerClient) InspectContainer(ctx context.Context, containerID string) (*ContainerInfo, error) {
	info, err := d.client.ContainerInspect(ctx, containerID, mobyclient.ContainerInspectOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to inspect container: %w", err)
	}

	exitCode := info.Container.State.ExitCode

	return &ContainerInfo{
		ID:       info.Container.ID,
		Status:   string(info.Container.State.Status),
		Running:  info.Container.State.Running,
		ExitCode: exitCode,
		ImageID:  info.Container.Image, // Full image ID (digest)
	}, nil
}

// GetContainerLogs gets container logs
func (d *DockerClient) GetContainerLogs(ctx context.Context, containerID string, follow bool) (io.ReadCloser, error) {
	options := mobyclient.ContainerLogsOptions{
		ShowStdout: true,
		ShowStderr: true,
		Follow:     follow,
		Tail:       "100",
	}

	return d.client.ContainerLogs(ctx, containerID, options)
}

// FindContainerByName finds a container by name
func (d *DockerClient) FindContainerByName(ctx context.Context, name string) (string, error) {
	filter := mobyclient.Filters{}
	filter.Add("name", name)

	result, err := d.client.ContainerList(ctx, mobyclient.ContainerListOptions{
		All:     true,
		Filters: filter,
	})
	if err != nil {
		return "", fmt.Errorf("failed to list containers: %w", err)
	}

	if len(result.Items) == 0 {
		return "", fmt.Errorf("container not found: %s", name)
	}

	return result.Items[0].ID, nil
}

// ContainerExists checks if a container exists
func (d *DockerClient) ContainerExists(ctx context.Context, name string) bool {
	_, err := d.FindContainerByName(ctx, name)
	return err == nil
}

// ImageList lists Docker images
func (d *DockerClient) ImageList(ctx context.Context, options mobyclient.ImageListOptions) ([]mobyimage.Summary, error) {
	result, err := d.client.ImageList(ctx, options)
	if err != nil {
		return nil, err
	}
	return result.Items, nil
}

// FindContainersByPrefix finds all containers with names starting with the given prefix
func (d *DockerClient) FindContainersByPrefix(ctx context.Context, prefix string) ([]string, error) {
	filter := mobyclient.Filters{}
	filter.Add("name", prefix)

	result, err := d.client.ContainerList(ctx, mobyclient.ContainerListOptions{
		All:     true,
		Filters: filter,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list containers: %w", err)
	}

	var containerIDs []string
	for _, c := range result.Items {
		// Check if any of the container names start with the prefix
		for _, name := range c.Names {
			if len(name) > 0 && name[0] == '/' {
				name = name[1:] // Remove leading slash
			}
			if len(name) >= len(prefix) && name[:len(prefix)] == prefix {
				containerIDs = append(containerIDs, c.ID)
				break
			}
		}
	}

	return containerIDs, nil
}

// GetImageID gets the current image ID for a given image reference
func (d *DockerClient) GetImageID(ctx context.Context, imageRef string) (string, error) {
	filterArgs := mobyclient.Filters{}
	filterArgs.Add("reference", imageRef)
	
	result, err := d.client.ImageList(ctx, mobyclient.ImageListOptions{
		Filters: filterArgs,
	})
	if err != nil {
		return "", fmt.Errorf("failed to list images: %w", err)
	}
	
	if len(result.Items) == 0 {
		return "", fmt.Errorf("image not found: %s", imageRef)
	}
	
	// Return the most recent image ID (first in list, typically sorted by creation time)
	return result.Items[0].ID, nil
}

// StartContainer starts an existing container
func (d *DockerClient) StartContainer(ctx context.Context, containerID string) error {
	_, err := d.client.ContainerStart(ctx, containerID, mobyclient.ContainerStartOptions{})
	return err
}

