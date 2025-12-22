package supervisor

import (
	"fmt"
	"os"
	"strings"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/mount"
)

// ContainerConfig represents Docker container configuration
type ContainerConfig struct {
	Image       string
	Name        string
	Env         []string
	Volumes     []string
	NetworkMode string
	CapAdd      []string
	Cmd         []string
	Restart     string
}

// AgentOptions represents agent configuration options for supervisor
type AgentOptions struct {
	TeamID                 string
	AgentID                string
	AgentTags              []string
	AgentNetworks          []string
	AgentOutput            string
	AgentName              string
	Verbose                bool
	PassiveDiscovery       bool
	ChunkParallelism       int
	ScanParallelism        int
	EnumerationParallelism int
	KeepOutputFiles        bool
}

// BuildContainerConfig builds container configuration from agent options
func BuildContainerConfig(options *AgentOptions, agentID string) *ContainerConfig {
	deploymentConfig := BuildDeploymentConfig(options, agentID)
	return deploymentConfig.ToContainerConfig()
}

// BuildDeploymentConfig builds deployment configuration from agent options
func BuildDeploymentConfig(options *AgentOptions, agentID string) *DeploymentConfig {
	// Use hardcoded Docker image
	image := "projectdiscovery/pd-agent:latest"

	// Generate container name using xid (same approach as agent ID)
	containerName := fmt.Sprintf("pd-agent-%s", agentID)

	// Build environment variables
	env := buildEnvVars(options)

	// Build volumes
	volumes := buildVolumes(options)

	// Build command arguments (excluding supervisor-mode flag)
	cmd := buildCommandArgs(options)

	config := &DeploymentConfig{
		Image:       image,
		Name:        containerName,
		Env:         env,
		Volumes:     volumes,
		NetworkMode: "host", // Required for subnet discovery
		CapAdd:      []string{"NET_RAW", "NET_ADMIN"},
		Cmd:         cmd,
		Restart:     "no", // We manage restart ourselves
	}

	return config
}

// ToContainerConfig converts DeploymentConfig to ContainerConfig
func (d *DeploymentConfig) ToContainerConfig() *ContainerConfig {
	return &ContainerConfig{
		Image:       d.Image,
		Name:        d.Name,
		Env:         d.Env,
		Volumes:     d.Volumes,
		NetworkMode: d.NetworkMode,
		CapAdd:      d.CapAdd,
		Cmd:         d.Cmd,
		Restart:     d.Restart,
	}
}

// ToDockerConfig converts ContainerConfig to Docker API types
func (c *ContainerConfig) ToDockerConfig() (*container.Config, *container.HostConfig) {
	containerConfig := &container.Config{
		Image: c.Image,
		Env:   c.Env,
		Cmd:   c.Cmd,
	}

	hostConfig := &container.HostConfig{
		NetworkMode: container.NetworkMode(c.NetworkMode),
		CapAdd:      c.CapAdd,
		RestartPolicy: container.RestartPolicy{
			Name: container.RestartPolicyMode(c.Restart),
		},
	}

	// Add volume mounts
	if len(c.Volumes) > 0 {
		mounts := make([]mount.Mount, 0)
		for _, vol := range c.Volumes {
			parts := strings.Split(vol, ":")
			if len(parts) == 2 {
				mounts = append(mounts, mount.Mount{
					Type:   mount.TypeBind,
					Source: parts[0],
					Target: parts[1],
				})
			}
		}
		hostConfig.Mounts = mounts
	}

	return containerConfig, hostConfig
}

// buildEnvVars builds environment variables for container
func buildEnvVars(options *AgentOptions) []string {
	env := []string{}

	// Pass through all PDCP_* environment variables
	for _, e := range os.Environ() {
		if strings.HasPrefix(e, "PDCP_") {
			env = append(env, e)
		}
	}

	// Add agent-specific environment variables if not already set
	addEnvIfNotExists(&env, "PDCP_API_KEY", os.Getenv("PDCP_API_KEY"))
	addEnvIfNotExists(&env, "PDCP_TEAM_ID", options.TeamID)

	if len(options.AgentTags) > 0 {
		addEnvIfNotExists(&env, "PDCP_AGENT_TAGS", strings.Join(options.AgentTags, ","))
	}

	if len(options.AgentNetworks) > 0 {
		addEnvIfNotExists(&env, "PDCP_AGENT_NETWORKS", strings.Join(options.AgentNetworks, ","))
	}

	if options.AgentName != "" {
		addEnvIfNotExists(&env, "PDCP_AGENT_NAME", options.AgentName)
	}

	if options.AgentOutput != "" {
		addEnvIfNotExists(&env, "PDCP_AGENT_OUTPUT", options.AgentOutput)
	}

	if options.Verbose {
		addEnvIfNotExists(&env, "PDCP_VERBOSE", "true")
	}

	// Add parallelism settings
	if options.ChunkParallelism > 0 {
		addEnvIfNotExists(&env, "PDCP_CHUNK_PARALLELISM", fmt.Sprintf("%d", options.ChunkParallelism))
	}
	if options.ScanParallelism > 0 {
		addEnvIfNotExists(&env, "PDCP_SCAN_PARALLELISM", fmt.Sprintf("%d", options.ScanParallelism))
	}
	if options.EnumerationParallelism > 0 {
		addEnvIfNotExists(&env, "PDCP_ENUMERATION_PARALLELISM", fmt.Sprintf("%d", options.EnumerationParallelism))
	}

	// Pass through PROXY_URL if set
	addEnvIfNotExists(&env, "PROXY_URL", os.Getenv("PROXY_URL"))

	return env
}

// addEnvIfNotExists adds environment variable if not already present
func addEnvIfNotExists(env *[]string, key, value string) {
	if value == "" {
		return
	}

	// Check if already exists
	for _, e := range *env {
		if strings.HasPrefix(e, key+"=") {
			return
		}
	}

	*env = append(*env, fmt.Sprintf("%s=%s", key, value))
}

// buildVolumes builds volume mounts for container
func buildVolumes(options *AgentOptions) []string {
	volumes := []string{}

	// Mount output directory if specified
	if options.AgentOutput != "" {
		// Ensure the directory exists
		if err := os.MkdirAll(options.AgentOutput, 0755); err == nil {
			volumes = append(volumes, fmt.Sprintf("%s:%s", options.AgentOutput, options.AgentOutput))
		}
	}

	return volumes
}

// buildCommandArgs builds command arguments for container (excluding supervisor-mode)
func buildCommandArgs(options *AgentOptions) []string {
	args := []string{}

	// Add verbose flag
	if options.Verbose {
		args = append(args, "-verbose")
	}

	// Add keep-output-files flag
	if options.KeepOutputFiles {
		args = append(args, "-keep-output-files")
	}

	// Add agent output
	if options.AgentOutput != "" {
		args = append(args, "-agent-output", options.AgentOutput)
	}

	// Add agent tags
	if len(options.AgentTags) > 0 {
		args = append(args, "-agent-tags", strings.Join(options.AgentTags, ","))
	}

	// Add agent networks
	if len(options.AgentNetworks) > 0 {
		args = append(args, "-agent-networks", strings.Join(options.AgentNetworks, ","))
	}

	// Add agent name
	if options.AgentName != "" {
		args = append(args, "-agent-name", options.AgentName)
	}

	// Add parallelism flags
	if options.ChunkParallelism > 0 {
		args = append(args, "-chunk-parallelism", fmt.Sprintf("%d", options.ChunkParallelism))
	}
	if options.ScanParallelism > 0 {
		args = append(args, "-scan-parallelism", fmt.Sprintf("%d", options.ScanParallelism))
	}
	if options.EnumerationParallelism > 0 {
		args = append(args, "-enumeration-parallelism", fmt.Sprintf("%d", options.EnumerationParallelism))
	}

	// Add passive discovery if enabled
	if options.PassiveDiscovery {
		args = append(args, "-passive-discovery")
	}

	// Note: We explicitly exclude -supervisor-mode flag

	return args
}
