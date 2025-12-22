package supervisor

import (
	"context"
	"fmt"
	"time"

	"github.com/projectdiscovery/gologger"
)

// Monitor monitors deployment health and manages restarts
type Monitor struct {
	provider      Provider
	deploymentID  string
	restartCount  int
	maxRestarts   int
	checkInterval time.Duration
}

// HealthStatus represents deployment health status
type HealthStatus struct {
	Running  bool
	ExitCode int
	Status   string
}

// NewMonitor creates a new deployment monitor
func NewMonitor(provider Provider, maxRestarts int) *Monitor {
	return &Monitor{
		provider:      provider,
		maxRestarts:   maxRestarts,
		checkInterval: 30 * time.Second,
	}
}

// StartMonitoring starts monitoring a deployment
func (m *Monitor) StartMonitoring(ctx context.Context, deploymentID string) {
	m.deploymentID = deploymentID

	ticker := time.NewTicker(m.checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			health, err := m.CheckHealth(ctx, deploymentID)
			if err != nil {
				gologger.Warning().Msgf("Failed to check deployment health: %v", err)
				continue
			}

			if !health.Running && health.ExitCode != 0 {
				gologger.Warning().Msgf("Deployment exited with code %d, status: %s", health.ExitCode, health.Status)
				
				if m.restartCount < m.maxRestarts {
					m.restartCount++
					gologger.Info().Msgf("Restarting deployment (attempt %d/%d)", m.restartCount, m.maxRestarts)
					
					if err := m.RestartDeployment(ctx, deploymentID); err != nil {
						gologger.Error().Msgf("Failed to restart deployment: %v", err)
					}
				} else {
					gologger.Error().Msgf("Max restart attempts (%d) reached, stopping monitoring", m.maxRestarts)
					return
				}
			}
		}
	}
}

// CheckHealth checks deployment health
func (m *Monitor) CheckHealth(ctx context.Context, deploymentID string) (*HealthStatus, error) {
	info, err := m.provider.Inspect(ctx, deploymentID)
	if err != nil {
		return nil, fmt.Errorf("failed to inspect deployment: %w", err)
	}

	return &HealthStatus{
		Running:  info.Running,
		ExitCode: info.ExitCode,
		Status:   info.Status,
	}, nil
}

// RestartDeployment restarts a deployment
func (m *Monitor) RestartDeployment(ctx context.Context, deploymentID string) error {
	// Stop deployment
	timeout := 10
	if err := m.provider.Stop(ctx, deploymentID, &timeout); err != nil {
		return fmt.Errorf("failed to stop deployment: %w", err)
	}

	// Remove deployment
	if err := m.provider.Remove(ctx, deploymentID); err != nil {
		return fmt.Errorf("failed to remove deployment: %w", err)
	}

	// Note: Deployment will be recreated by supervisor's Run loop
	return nil
}

// RestartContainer restarts a container (deprecated, use RestartDeployment)
func (m *Monitor) RestartContainer(ctx context.Context, containerID string) error {
	return m.RestartDeployment(ctx, containerID)
}

// GetRestartCount returns the current restart count
func (m *Monitor) GetRestartCount() int {
	return m.restartCount
}

// ResetRestartCount resets the restart count
func (m *Monitor) ResetRestartCount() {
	m.restartCount = 0
}

