

<h4 align="center">ProjectDiscovery Cloud - Agent</h4>

<p align="center">
<a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/license-MIT-_red.svg"></a>
<a href="https://goreportcard.com/badge/github.com/projectdiscovery/pd-agent"><img src="https://goreportcard.com/badge/github.com/projectdiscovery/pd-agent"></a>
<a href="https://github.com/projectdiscovery/pd-agent/releases"><img src="https://img.shields.io/github/release/projectdiscovery/pd-agent"></a>
<a href="https://twitter.com/pdiscoveryio"><img src="https://img.shields.io/twitter/follow/pdiscoveryio.svg?logo=twitter"></a>
<a href="https://discord.gg/projectdiscovery"><img src="https://img.shields.io/discord/695645237418131507.svg?logo=discord"></a>
</p>

<p align="center">
  <a href="#pd-agent">PD Agent</a> •
  <a href="#installation">Installation</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="#supervisor-mode">Supervisor Mode</a> •
  <a href="#system-installation">System Installation</a> •
  <a href="https://discord.gg/projectdiscovery">Join Discord</a>

</p>


**pd-agent** is an agent for ProjectDiscovery Cloud Platform that executes internal discovery and scans remotely. It connects to the PDCP platform, receives scan configurations, executes them locally using ProjectDiscovery tools, and uploads results back to the cloud platform.

### Features

- **Remote Execution**: Connect to PDCP platform and execute scans remotely.
- **Workload Distribution**: Support workload distribution acrsso multiple agents when available 
- **Agent Tagging**: Organize agents with tags and networks for targeted execution.

### Installation

#### Go Install
```bash
go install github.com/projectdiscovery/pd-agent/cmd/pd-agent@latest
```

#### Docker
```bash
docker run -d --name pd-agent \
  --network host --cap-add NET_RAW --cap-add NET_ADMIN \
  -e PDCP_API_KEY=your-api-key \
  -e PDCP_TEAM_ID=your-team-id \
  projectdiscovery/pd-agent:latest \
  -agent-tags production
```

#### Kubernetes
```bash
# Create namespace
kubectl create namespace pd-agent

# Create secret with credentials
kubectl create secret generic pd-agent-secret \
  --namespace pd-agent \
  --from-literal=PDCP_API_KEY=your-api-key \
  --from-literal=PDCP_TEAM_ID=your-team-id

# Deploy the agent
kubectl apply -f https://raw.githubusercontent.com/projectdiscovery/pd-agent/main/examples/pd-agent-deployment.yaml

# Check status
kubectl get pods -n pd-agent -l app=pd-agent
```

The agent automatically discovers Kubernetes cluster subnets (nodes, pods, services) for scanning. See [examples/README.md](examples/README.md) for detailed instructions and customization options.

### Supervisor Mode

Supervisor mode allows pd-agent to manage its own deployment in Docker or Kubernetes, automatically handling updates, restarts, and lifecycle management.

#### Prerequisites

- **macOS/Windows**: Docker Desktop must be installed and running
  - On Windows, Docker Desktop has automatic integration with WSL2
- **Linux**: Docker must be installed and running

#### Usage

Run pd-agent in supervisor mode with Docker (default):

```bash
pd-agent -supervisor-mode docker
```

Or use Kubernetes:

```bash
pd-agent -supervisor-mode kubernetes
```

The supervisor will:
- Automatically pull and deploy the latest pd-agent Docker image
- Monitor the deployment and restart if it crashes
- Handle image updates automatically
- Manage the container/pod lifecycle

**Note**: Supervisor mode requires Docker or Kubernetes to be available and properly configured. The supervisor runs the agent in a container/pod, so all agent configuration (environment variables, flags) should be passed as normal.

### Network Discovery

The agent automatically discovers local network subnets and reports them to the platform:
- **Local networks:** Discovers private IP ranges from network interfaces and routing tables
- **Kubernetes:** Automatically discovers and aggregates cluster subnets (node IPs, pod CIDRs, service CIDRs)
- **Docker:** Use `--network host` and network capabilities (`NET_RAW`, `NET_ADMIN`) to enable discovery

For Kubernetes deployments, the agent requires `ClusterRole` permissions to discover cluster resources (included in the deployment manifest).

### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `PDCP_API_KEY` | Yes | - | API key for authentication |
| `PDCP_TEAM_ID` | Yes | - | Team identifier |
| `PDCP_AGENT_NETWORKS` | No | - | Comma-separated network identifiers |
| `PDCP_AGENT_TAGS` | No | - | Comma-separated agent tags |
| `PDCP_AGENT_NAME` | No | Hostname | Agent display name |

### Usage

```bash
# Basic usage
pd-agent -agent-networks internal
```

### Configuration

The agent uses environment variables or command-line flags for configuration. See the Environment Variables table above for all available options.

### Troubleshooting

#### Common Issues

**Agent not connecting:**
- Verify `PDCP_API_KEY` and `PDCP_TEAM_ID` are correct
- Check network connectivity to `PDCP_API_SERVER`
- Ensure proxy settings are correct if using a proxy

**Scans not executing:**
- Check agent tags match scan configuration tags
- Verify agent ID is correct
- Check verbose logs for error messages
- Ensure output directory is writable

**Permission errors:**
- Verify the user running the agent has write permissions to output directory
- On Linux, check SELinux/AppArmor policies
- On Windows, ensure service account has necessary permissions

#### Log Locations

- **Linux (systemd):** `journalctl -u pd-agent -f`
- **macOS (launchd):** `~/.pd-agent/logs/stdout.log` and `stderr.log`
- **Windows:** Event Viewer → Windows Logs → Application
- **Docker:** `docker logs pd-agent -f`
- **Kubernetes:** `kubectl logs -n pd-agent -l app=pd-agent -f`

#### Enable Verbose Logging

Add `-verbose` flag or set environment variable:
```bash
export PDCP_VERBOSE=true
# or
PDCP_VERBOSE=1 pd-agent ...
```

### Best Practices

1. **Agent Tagging:** Use descriptive tags to organize agents (e.g., `production`, `staging`, `scanner-1`)
2. **Network Segmentation:** Use `-agent-networks` to assign agents to specific networks
3. **Resource Management:** Monitor agent resource usage and adjust accordingly
4. **Security:** Always run agents with low privileges, never as root/Administrator
5. **Monitoring:** Set up monitoring and alerting for agent health
6. **Output Management:** Regularly clean up output directories to prevent disk space issues
7. **Agent IDs:** Use unique, descriptive agent IDs for easy identification
8. **Kubernetes:** For K8s deployments, use one agent per cluster to efficiently discover and scan cluster subnets

### Advanced Configuration

#### Custom Proxy Configuration

Configure a custom proxy for agent communication:

```bash
export PROXY_URL=http://proxy.example.com:8080
pd-agent -verbose
```

#### Agent Grouping

Use tags and networks to group agents:

```bash
# Production agents
pd-agent -agent-tags production,us-east -agent-networks prod-network

# Staging agents
pd-agent -agent-tags staging,us-west -agent-networks staging-network
```

--------

<div align="center">

**pd-agent** is made with ❤️ by the [projectdiscovery](https://projectdiscovery.io) team and distributed under [MIT License](LICENSE).


<a href="https://discord.gg/projectdiscovery"><img src="https://raw.githubusercontent.com/projectdiscovery/nuclei-burp-plugin/main/static/join-discord.png" width="300" alt="Join Discord"></a>

</div>