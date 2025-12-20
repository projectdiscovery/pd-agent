

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

**Note:** Go must be pre-installed on your system. Download Go from [golang.org](https://golang.org/dl/) if needed.

```bash
go install github.com/projectdiscovery/pd-agent/cmd/pd-agent@latest
```

The binary will be installed in your Go bin directory:
- **Linux/macOS:** `$HOME/go/bin/pd-agent` (or `$GOPATH/bin/pd-agent` if `GOPATH` is set)
- **Windows:** `%USERPROFILE%\go\bin\pd-agent.exe` (or `%GOPATH%\bin\pd-agent.exe` if `GOPATH` is set)

Ensure this directory is in your PATH to run `pd-agent` (or `pd-agent.exe` on Windows) from anywhere.

#### Docker

**Note:** Docker must be installed on your system. Download Docker from [docker.com](https://www.docker.com/products/docker-desktop/) if needed.

**Linux/macOS:**
```bash
docker run -d --name pd-agent \
  --network host --cap-add NET_RAW --cap-add NET_ADMIN \
  -e PDCP_API_KEY=your-api-key \
  -e PDCP_TEAM_ID=your-team-id \
  projectdiscovery/pd-agent:latest \
  -agent-tags production
```

**Windows (Docker Desktop):**
```powershell
docker run -d --name pd-agent \
  -e PDCP_API_KEY=your-api-key \
  -e PDCP_TEAM_ID=your-team-id \
  projectdiscovery/pd-agent:latest \
  -agent-tags production
```

**Note:** On Windows, `--network host` and `--cap-add` flags are not supported by Docker Desktop. Only passive discovery features are affected; all other agent functionality works normally.

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

### Network Discovery

The agent automatically discovers local network subnets and reports them to the platform:
- **Local networks:** Discovers private IP ranges from network interfaces and routing tables
- **Kubernetes:** Automatically discovers and aggregates cluster subnets (node IPs, pod CIDRs, service CIDRs)
- **Docker (Linux/macOS only):** Use `--network host` and network capabilities (`NET_RAW`, `NET_ADMIN`) to enable passive discovery. On Windows Docker Desktop, these flags are not supported and passive discovery will be unavailable.

For Kubernetes deployments, the agent requires `ClusterRole` permissions to discover cluster resources (included in the deployment manifest).

### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `PDCP_API_KEY` | Yes | - | API key for authentication |
| `PDCP_TEAM_ID` | Yes | - | Team identifier |
| `PDCP_AGENT_NETWORKS` | No | - | Comma-separated network identifiers |
| `PDCP_AGENT_TAGS` | No | - | Comma-separated agent tags |
| `PDCP_AGENT_NAME` | No | Hostname | Agent display name |

#### Setting Environment Variables

**Linux/macOS (bash/zsh):**
```bash
export PDCP_API_KEY=your-api-key
export PDCP_TEAM_ID=your-team-id
export PDCP_AGENT_TAGS=production,staging
```

**Windows (PowerShell):**
```powershell
$env:PDCP_API_KEY="your-api-key"
$env:PDCP_TEAM_ID="your-team-id"
$env:PDCP_AGENT_TAGS="production,staging"
```

**Windows (Command Prompt):**
```cmd
set PDCP_API_KEY=your-api-key
set PDCP_TEAM_ID=your-team-id
set PDCP_AGENT_TAGS=production,staging
```

**Windows (Permanent - System Environment Variables):**
1. Open System Properties → Advanced → Environment Variables
2. Add variables under User or System variables
3. Restart the terminal/service for changes to take effect

**Windows (WSL2):**
Follow Linux instructions - WSL2 uses Linux environment variable syntax.

### Usage

**Linux/macOS:**
```bash
# Basic usage
pd-agent -agent-networks internal

# With tags
pd-agent -agent-tags production,staging -agent-networks internal
```

**Windows (PowerShell):**
```powershell
# Basic usage
pd-agent.exe -agent-networks internal

# With tags
pd-agent.exe -agent-tags production,staging -agent-networks internal
```

**Windows (Command Prompt):**
```cmd
# Basic usage
pd-agent.exe -agent-networks internal

# With tags
pd-agent.exe -agent-tags production,staging -agent-networks internal
```

**Windows (WSL2):**
Follow Linux instructions - commands are identical to Linux/macOS.

**Note:** On Windows, if `pd-agent.exe` is in your PATH, you can use `pd-agent` instead of `pd-agent.exe`. The `.exe` extension is optional in PowerShell and required in Command Prompt.

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

**Linux/macOS:**
```bash
# Using flag
pd-agent -verbose

# Using environment variable
export PDCP_VERBOSE=true
pd-agent ...

# Or inline
PDCP_VERBOSE=1 pd-agent ...
```

**Windows (PowerShell):**
```powershell
# Using flag
pd-agent.exe -verbose

# Using environment variable
$env:PDCP_VERBOSE="true"
pd-agent.exe ...

# Or inline
$env:PDCP_VERBOSE="1"; pd-agent.exe ...
```

**Windows (Command Prompt):**
```cmd
# Using flag
pd-agent.exe -verbose

# Using environment variable
set PDCP_VERBOSE=true
pd-agent.exe ...

# Or inline (requires separate commands)
set PDCP_VERBOSE=1 && pd-agent.exe ...
```

**Windows (WSL2):**
Follow Linux instructions - use Linux syntax.

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

**Linux/macOS:**
```bash
export PROXY_URL=http://proxy.example.com:8080
pd-agent -verbose
```

**Windows (PowerShell):**
```powershell
$env:PROXY_URL="http://proxy.example.com:8080"
pd-agent.exe -verbose
```

**Windows (Command Prompt):**
```cmd
set PROXY_URL=http://proxy.example.com:8080
pd-agent.exe -verbose
```

**Windows (WSL2):**
Follow Linux instructions - use Linux syntax.

#### Agent Grouping

Use tags and networks to group agents:

**Linux/macOS:**
```bash
# Production agents
pd-agent -agent-tags production,us-east -agent-networks prod-network

# Staging agents
pd-agent -agent-tags staging,us-west -agent-networks staging-network
```

**Windows (PowerShell/Command Prompt):**
```powershell
# Production agents
pd-agent.exe -agent-tags production,us-east -agent-networks prod-network

# Staging agents
pd-agent.exe -agent-tags staging,us-west -agent-networks staging-network
```

**Windows (WSL2):**
Follow Linux instructions - commands are identical to Linux/macOS.

--------

<div align="center">

**pd-agent** is made with ❤️ by the [projectdiscovery](https://projectdiscovery.io) team and distributed under [MIT License](LICENSE).


<a href="https://discord.gg/projectdiscovery"><img src="https://raw.githubusercontent.com/projectdiscovery/nuclei-burp-plugin/main/static/join-discord.png" width="300" alt="Join Discord"></a>

</div>