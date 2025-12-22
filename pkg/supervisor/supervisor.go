package supervisor

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/projectdiscovery/gologger"
)

// Supervisor manages the deployment running pd-agent
type Supervisor struct {
	config          *AgentOptions
	provider        Provider
	updater         *Updater
	binaryUpdater   *BinaryUpdater
	monitor         *Monitor
	deploymentID    string
	deploymentConfig *DeploymentConfig
}

// NewSupervisor creates a new supervisor instance (defaults to Docker provider)
func NewSupervisor(config *AgentOptions) (*Supervisor, error) {
	return NewSupervisorWithProvider(config, "docker")
}

// NewSupervisorWithProvider creates a new supervisor instance with specified provider
func NewSupervisorWithProvider(config *AgentOptions, providerType string) (*Supervisor, error) {
	// Initialize provider
	var provider Provider
	var err error

	switch providerType {
	case "kubernetes":
		provider, err = NewKubernetesProvider()
		if err != nil {
			return nil, fmt.Errorf("failed to initialize Kubernetes provider: %w", err)
		}
	case "docker":
		fallthrough
	default:
		provider, err = NewDockerProvider()
		if err != nil {
			return nil, fmt.Errorf("failed to initialize Docker provider: %w", err)
		}
	}

	// Build deployment configuration
	deploymentConfig := BuildDeploymentConfig(config, config.AgentID)

	// Initialize updater
	updateInterval := 24 * time.Hour
	updater := NewUpdater(provider, deploymentConfig.Image, updateInterval)

	// Initialize monitor
	maxRestarts := 5
	monitor := NewMonitor(provider, maxRestarts)

	// Initialize binary updater
	binaryUpdater := NewBinaryUpdater("projectdiscovery", "pd-agent")

	return &Supervisor{
		config:           config,
		provider:         provider,
		updater:          updater,
		binaryUpdater:    binaryUpdater,
		monitor:          monitor,
		deploymentConfig: deploymentConfig,
	}, nil
}

// Run starts the supervisor and manages the container lifecycle
func (s *Supervisor) Run(ctx context.Context) error {
	gologger.Info().Msg("Starting pd-agent supervisor")

	// Ensure provider is available
	if !s.provider.IsAvailable(ctx) {
		// For Docker, check installation
		if s.provider.Name() == "docker" {
			installer := NewInstaller()
			if err := installer.EnsureDocker(); err != nil {
				return fmt.Errorf("failed to ensure Docker is installed and running: %w", err)
			}
		} else {
			return fmt.Errorf("deployment provider %s is not available", s.provider.Name())
		}
	}

	// Start Docker image update loop in background
	// The update loop will handle the initial image pull
	updateCtx, updateCancel := context.WithCancel(context.Background())
	defer updateCancel()

	go s.updater.StartUpdateLoop(updateCtx, func() error {
		// Restart container with new image
		return s.restartContainer(ctx)
	})

	// Start binary update loop in background
	binaryUpdateCtx, binaryUpdateCancel := context.WithCancel(context.Background())
	defer binaryUpdateCancel()

	go s.binaryUpdater.StartUpdateLoop(binaryUpdateCtx, nil)

	// Main loop: ensure container is running
	for {
		select {
		case <-ctx.Done():
			gologger.Info().Msg("Shutting down supervisor")
			// Use a background context with timeout for shutdown to avoid context canceled error
			stopCtx, stopCancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer stopCancel()
			return s.Stop(stopCtx)
		default:
			// Check if deployment exists and is running
			exists := s.provider.Exists(ctx, s.deploymentConfig.Name)

			if !exists || s.deploymentID == "" {
				// Deployment doesn't exist, create and start it
				if err := s.Start(ctx); err != nil {
					gologger.Error().Msgf("Failed to start deployment: %v", err)
					time.Sleep(10 * time.Second) // Wait before retry
					continue
				}
			} else {
				// Check deployment health
				info, err := s.provider.Inspect(ctx, s.deploymentID)
				if err != nil {
					gologger.Warning().Msgf("Failed to inspect deployment: %v", err)
					s.deploymentID = "" // Reset to trigger restart
					continue
				}

				if !info.Running {
					gologger.Warning().Msgf("Deployment is not running, status: %s", info.Status)
					s.deploymentID = "" // Reset to trigger restart
					continue
				}
			}

			// Sleep before next check
			time.Sleep(30 * time.Second)
		}
	}
}

// Start starts the deployment
func (s *Supervisor) Start(ctx context.Context) error {
	// Get current image ID
	currentImageID, err := s.provider.GetImageID(ctx, s.deploymentConfig.Image)
	if err != nil {
		gologger.Warning().Msgf("Failed to get current image ID: %v, proceeding with cleanup", err)
		currentImageID = ""
	}

	// Check existing deployments and compare image versions
	existingDeployments, err := s.provider.FindByPrefix(ctx, "pd-agent-")
	if err == nil && len(existingDeployments) > 0 {
		// Check if any deployment is using an outdated image
		hasOutdatedDeployments := false
		if currentImageID != "" {
			for _, deploymentID := range existingDeployments {
				deploymentInfo, err := s.provider.Inspect(ctx, deploymentID)
				if err == nil && deploymentInfo.ImageID != currentImageID {
					hasOutdatedDeployments = true
					gologger.Info().Msgf("Found deployment %s using outdated image (current: %s, deployment: %s)",
						deploymentID[:12], currentImageID[:12], deploymentInfo.ImageID[:12])
					break
				}
			}
		}

		// Only clean up if image was updated (outdated deployments found) or if we couldn't check image version
		if hasOutdatedDeployments || currentImageID == "" {
			gologger.Info().Msgf("Found %d existing pd-agent deployment(s), cleaning up...", len(existingDeployments))
			for _, deploymentID := range existingDeployments {
				// Stop deployment if running
				_ = s.provider.Stop(ctx, deploymentID, nil)
				// Remove deployment
				_ = s.provider.Remove(ctx, deploymentID)
			}
		} else {
			// Image is up to date, check if we have a running deployment with the current image
			for _, deploymentID := range existingDeployments {
				deploymentInfo, err := s.provider.Inspect(ctx, deploymentID)
				if err == nil && deploymentInfo.ImageID == currentImageID {
					if deploymentInfo.Running {
						// Deployment is running with current image, nothing to do
						// Only log if deploymentID changed (first time we find it)
						if s.deploymentID != deploymentID {
							gologger.Info().Msgf("Deployment %s is already running with current image", deploymentID[:12])
						}
						s.deploymentID = deploymentID
						s.monitor.ResetRestartCount()
						return nil
					} else {
						// Deployment exists but not running, restart it
						gologger.Info().Msgf("Deployment %s exists with current image but is not running, restarting...", deploymentID[:12])
						s.deploymentID = deploymentID
						// Start the existing deployment
						if err := s.provider.Start(ctx, deploymentID); err != nil {
							gologger.Warning().Msgf("Failed to start existing deployment: %v, will create new one", err)
							// Fall through to create new deployment
						} else {
							s.monitor.ResetRestartCount()
							gologger.Info().Msgf("Restarted deployment: %s", deploymentID[:12])
							return nil
						}
					}
				}
			}
		}
	}

	// Create and start deployment
	deploymentID, err := s.provider.Deploy(ctx, s.deploymentConfig)
	if err != nil {
		return fmt.Errorf("failed to deploy: %w", err)
	}

	s.deploymentID = deploymentID
	s.monitor.ResetRestartCount()

	gologger.Info().Msgf("Deployment started successfully: %s", deploymentID[:12])
	return nil
}

// Stop stops the deployment
func (s *Supervisor) Stop(ctx context.Context) error {
	if s.deploymentID == "" {
		return nil
	}

	gologger.Info().Msg("Stopping deployment")
	timeout := 30
	if err := s.provider.Stop(ctx, s.deploymentID, &timeout); err != nil {
		// If context was canceled, try with a background context
		if ctx.Err() == context.Canceled {
			stopCtx, stopCancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
			defer stopCancel()
			if err := s.provider.Stop(stopCtx, s.deploymentID, &timeout); err != nil {
				return fmt.Errorf("failed to stop deployment: %w", err)
			}
			return nil
		}
		return fmt.Errorf("failed to stop deployment: %w", err)
	}

	return nil
}

// Restart restarts the container
func (s *Supervisor) Restart(ctx context.Context) error {
	if err := s.Stop(ctx); err != nil {
		return err
	}

	time.Sleep(2 * time.Second)

	return s.Start(ctx)
}

// restartContainer restarts the deployment (used by updater)
func (s *Supervisor) restartContainer(ctx context.Context) error {
	gologger.Info().Msg("Restarting deployment with updated image")
	return s.Restart(ctx)
}

// Update triggers a manual update
func (s *Supervisor) Update(ctx context.Context) error {
	wasUpdated, err := s.updater.Update(ctx)
	if err != nil {
		return err
	}

	// Only restart if image was actually updated
	if wasUpdated {
		return s.restartContainer(ctx)
	}

	return nil
}

// GetDeploymentID returns the current deployment ID
func (s *Supervisor) GetDeploymentID() string {
	return s.deploymentID
}

// GetContainerID returns the current container ID (deprecated, use GetDeploymentID)
func (s *Supervisor) GetContainerID() string {
	return s.deploymentID
}

// SetupSignalHandlers sets up signal handlers for graceful shutdown and manual updates
func (s *Supervisor) SetupSignalHandlers(ctx context.Context) context.Context {
	sigChan := make(chan os.Signal, 1)
	signals := []os.Signal{os.Interrupt, syscall.SIGTERM}
	signals = appendUnixSignals(signals)
	signal.Notify(sigChan, signals...)

	ctx, cancel := context.WithCancel(ctx)

	go func() {
		for sig := range sigChan {
			// Handle Unix-specific signals
			if handleUnixSignal(s, ctx, sig) {
				continue
			}

			// Handle shutdown signals
			switch sig {
			case os.Interrupt, syscall.SIGTERM:
				// Graceful shutdown
				gologger.Info().Msg("Shutdown signal received")
				cancel()
				return
			}
		}
	}()

	return ctx
}
