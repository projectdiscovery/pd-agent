package supervisor

import (
	"context"
	"io"
)

// Provider defines the interface for deployment providers (Docker, Kubernetes, ECS, etc.)
type Provider interface {
	// Name returns the provider name (e.g., "docker", "kubernetes", "ecs")
	Name() string

	// IsAvailable checks if the provider is available/installed
	IsAvailable(ctx context.Context) bool

	// PullImage pulls the latest image for the deployment
	PullImage(ctx context.Context, image string) error

	// Deploy deploys/runs a container/workload with the given configuration
	// Returns the deployment ID (container ID, pod name, task ARN, etc.)
	Deploy(ctx context.Context, config *DeploymentConfig) (string, error)

	// Stop stops a running deployment
	Stop(ctx context.Context, deploymentID string, timeout *int) error

	// Remove removes a deployment
	Remove(ctx context.Context, deploymentID string) error

	// Start starts an existing deployment
	Start(ctx context.Context, deploymentID string) error

	// Inspect gets information about a deployment
	Inspect(ctx context.Context, deploymentID string) (*DeploymentInfo, error)

	// GetLogs retrieves logs from a deployment
	GetLogs(ctx context.Context, deploymentID string, follow bool) (io.ReadCloser, error)

	// FindByName finds a deployment by name
	FindByName(ctx context.Context, name string) (string, error)

	// Exists checks if a deployment exists
	Exists(ctx context.Context, name string) bool

	// GetImageID gets the current image ID for a given image reference
	GetImageID(ctx context.Context, imageRef string) (string, error)

	// FindByPrefix finds all deployments with names starting with the given prefix
	FindByPrefix(ctx context.Context, prefix string) ([]string, error)
}

// DeploymentInfo represents deployment inspection information
type DeploymentInfo struct {
	ID       string
	Status   string
	Running  bool
	ExitCode int
	ImageID  string // Image ID the deployment is using
}

// DeploymentConfig represents a generic deployment configuration
// Provider implementations should convert this to their specific format
type DeploymentConfig struct {
	Image       string
	Name        string
	Env         []string
	Volumes     []string
	NetworkMode string
	CapAdd      []string
	Cmd         []string
	Restart     string
}

