<h1 align="center">
<img src="https://user-images.githubusercontent.com/8293321/211602034-411e38e9-e5df-429e-89ee-a97e3e09ebf0.png" width="200px">
<br>
</h1>

<h4 align="center">ProjectDiscovery Cloud Platform Agent</h4>

<p align="center">
<a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/license-MIT-_red.svg"></a>
<a href="https://goreportcard.com/badge/github.com/projectdiscovery/pdtm-agent"><img src="https://goreportcard.com/badge/github.com/projectdiscovery/pdtm-agent"></a>
<a href="https://github.com/projectdiscovery/pdtm-agent/releases"><img src="https://img.shields.io/github/release/projectdiscovery/pdtm-agent"></a>
<a href="https://twitter.com/pdiscoveryio"><img src="https://img.shields.io/twitter/follow/pdiscoveryio.svg?logo=twitter"></a>
<a href="https://discord.gg/projectdiscovery"><img src="https://img.shields.io/discord/695645237418131507.svg?logo=discord"></a>
</p>

<p align="center">
  <a href="#pdcp-agent">PDCP Agent</a> •
  <a href="#installation">Installation</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="#system-installation">System Installation</a> •
  <a href="https://discord.gg/projectdiscovery">Join Discord</a>

**pdcp-agent** is an agent for ProjectDiscovery Cloud Platform that executes scans and enumerations remotely.

</p>

## PDCP Agent

**pdcp-agent** is an agent for ProjectDiscovery Cloud Platform that executes scans and enumerations remotely. It connects to the PDCP platform, receives scan configurations, and executes them locally using ProjectDiscovery tools.

### Features

- **Remote Execution**: Connect to PDCP platform and execute scans remotely
- **Distributed & Mirror Modes**: Support for both distributed workload splitting and mirror execution
- **Agent Tagging**: Organize agents with tags and networks for targeted execution
- **Passive Discovery**: Optional passive network discovery via libpcap/gopacket
- **Local Template Support**: Execute local templates like privilege escalation checks
- **Automatic Updates**: Receive and execute new scan configurations automatically

### Installation

#### Binary Installation

Download the latest binary from [releases](https://github.com/projectdiscovery/pdtm-agent/releases):

```bash
# Linux
wget https://github.com/projectdiscovery/pdtm-agent/releases/latest/download/pdcp-agent-linux-amd64 -O pdcp-agent
chmod +x pdcp-agent

# macOS
wget https://github.com/projectdiscovery/pdtm-agent/releases/latest/download/pdcp-agent-darwin-amd64 -O pdcp-agent
chmod +x pdcp-agent

# Windows
# Download pdcp-agent-windows-amd64.exe and rename to pdcp-agent.exe
```

#### Docker Installation

Build the Docker image:

```bash
docker build -t pdcp-agent:latest .
```

Or pull from registry (if available):

```bash
docker pull pdcp-agent:latest
```

### Quick Start

#### One-liner: Direct Binary Execution

```bash
PDCP_API_KEY=your-api-key \
PDCP_API_SERVER=https://api.projectdiscovery.io \
PUNCH_HOLE_HOST=proxy.projectdiscovery.io \
PUNCH_HOLE_HTTP_PORT=8880 \
PDCP_TEAM_ID=your-team-id \
PROXY_URL=http://127.0.0.1:8080 \
pdcp-agent -agent-output /path/to/output -verbose -agent-tags production -agent-id unique-agent-id
```

#### One-liner: Docker Execution

```bash
docker run -d --name pdcp-agent \
  -e PDCP_API_KEY=your-api-key \
  -e PDCP_API_SERVER=https://api.projectdiscovery.io \
  -e PUNCH_HOLE_HOST=proxy.projectdiscovery.io \
  -e PUNCH_HOLE_HTTP_PORT=8880 \
  -e PDCP_TEAM_ID=your-team-id \
  -e PROXY_URL=http://127.0.0.1:8080 \
  -v /path/to/output:/output \
  pdcp-agent:latest \
  -agent-output /output -verbose -agent-tags production -agent-id unique-agent-id
```

#### Docker Compose

Create a `docker-compose.yml` file:

```yaml
version: '3.8'
services:
  pdcp-agent:
    image: pdcp-agent:latest
    container_name: pdcp-agent
    restart: unless-stopped
    environment:
      - PDCP_API_KEY=your-api-key
      - PDCP_API_SERVER=https://api.projectdiscovery.io
      - PUNCH_HOLE_HOST=proxy.projectdiscovery.io
      - PUNCH_HOLE_HTTP_PORT=8880
      - PDCP_TEAM_ID=your-team-id
      - PROXY_URL=http://127.0.0.1:8080
    volumes:
      - ./output:/output
    command: -agent-output /output -verbose -agent-tags production -agent-id unique-agent-id
```

Then run:

```bash
docker-compose up -d
```

### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `PDCP_API_KEY` | Yes | - | API key for authentication |
| `PDCP_API_SERVER` | No | `https://api.dev.projectdiscovery.io` | API server URL |
| `PUNCH_HOLE_HOST` | No | `proxy-dev.projectdiscovery.io` | Proxy host for punch hole |
| `PUNCH_HOLE_HTTP_PORT` | No | `8880` | Proxy HTTP port |
| `PDCP_TEAM_ID` | Yes | - | Team identifier |
| `PROXY_URL` | No | `http://127.0.0.1:8080` | Local proxy URL |
| `PDCP_AGENT_ID` | No | Auto-generated | Agent identifier |
| `PDCP_AGENT_TAGS` | No | - | Comma-separated agent tags |
| `PDCP_AGENT_NETWORKS` | No | - | Comma-separated network identifiers |
| `PDCP_AGENT_OUTPUT` | No | - | Output directory path |
| `PDCP_AGENT_NAME` | No | Hostname | Agent display name |
| `PDCP_VERBOSE` | No | `false` | Enable verbose logging (`true`/`1`) |
| `PASSIVE_DISCOVERY` | No | `false` | Enable passive discovery (`true`/`1`) |

### Command-Line Flags

| Flag | Short | Description |
|------|-------|-------------|
| `-verbose` | - | Show verbose output |
| `-agent-output <path>` | - | Agent output folder |
| `-agent-id <id>` | - | Specify the ID for the agent |
| `-agent-tags <tags>` | `-at` | Specify tags for the agent (comma-separated) |
| `-agent-networks <networks>` | `-an` | Specify networks for the agent (comma-separated) |
| `-agent-name <name>` | - | Specify the name for the agent |
| `-passive-discovery` | - | Enable passive discovery via libpcap/gopacket |

### Execution Modes

#### Distributed Mode (`worker_behavior: "distribute"`)

In **distributed mode**, the scan/enumeration workload is split across multiple agents. Each agent processes a portion of the work, allowing for parallel execution and faster completion times.

**Use Cases:**
- Large-scale scans with many targets
- Time-sensitive operations
- Resource-intensive enumerations
- When you have multiple agents available

**How it works:**
- The platform divides the work into chunks
- Each agent receives and processes specific chunks
- Results are aggregated on the platform
- No duplicate work between agents

**Example:**
```bash
# Multiple agents with same tags will share the workload
# Agent 1
pdcp-agent -agent-tags production,scanner-1 -agent-id agent-1

# Agent 2
pdcp-agent -agent-tags production,scanner-2 -agent-id agent-2

# Both agents will process different chunks of the same scan
```

#### Mirror Mode (default)

In **mirror mode**, every agent executes the complete scan/enumeration independently. All agents run the same work, which is useful for redundancy, local template execution, and privilege escalation scenarios.

**Use Cases:**
- **Local templates** (e.g., privilege escalation checks)
- Redundancy and fault tolerance
- When each agent needs to run the full scan
- Security assessments that require local context

**How it works:**
- All agents receive the complete scan/enumeration configuration
- Each agent executes the full scan independently
- Results from all agents are collected
- Useful for local context-dependent scans

**Example:**
```bash
# All agents execute the same scan
# Agent 1 (on server-1)
pdcp-agent -agent-tags production,server-1 -agent-id agent-1

# Agent 2 (on server-2)
pdcp-agent -agent-tags production,server-2 -agent-id agent-2

# Both agents execute the complete scan, useful for local privilege escalation checks
```

**When to use Mirror Mode:**
- **Privilege Escalation Templates:** These require local execution on each target system
- **Local Security Audits:** Templates that check local system configuration
- **Redundancy:** When you want multiple agents to verify results
- **Network Segmentation:** When agents are in different network segments and need to scan their local networks

**When to use Distributed Mode:**
- **Large Target Lists:** When you have many targets to scan
- **Resource Optimization:** To utilize multiple agents efficiently
- **Time-Sensitive Scans:** When you need results quickly
- **External Scans:** When scanning external targets that don't require local context

### System Installation

#### Linux (systemd)

**1. Download and install the binary:**

```bash
# Download binary
wget https://github.com/projectdiscovery/pdtm-agent/releases/latest/download/pdcp-agent-linux-amd64 -O /usr/local/bin/pdcp-agent
chmod +x /usr/local/bin/pdcp-agent
```

**2. Create a dedicated user:**

```bash
# Create user with low privileges
sudo useradd -r -s /bin/false -d /var/lib/pdcp-agent pdcp-agent
sudo mkdir -p /var/lib/pdcp-agent/output
sudo chown -R pdcp-agent:pdcp-agent /var/lib/pdcp-agent
```

**3. Create systemd service file** `/etc/systemd/system/pdcp-agent.service`:

```ini
[Unit]
Description=PDCP Agent
After=network.target

[Service]
Type=simple
User=pdcp-agent
Group=pdcp-agent
Environment="PDCP_API_KEY=your-api-key"
Environment="PDCP_API_SERVER=https://api.projectdiscovery.io"
Environment="PUNCH_HOLE_HOST=proxy.projectdiscovery.io"
Environment="PUNCH_HOLE_HTTP_PORT=8880"
Environment="PDCP_TEAM_ID=your-team-id"
Environment="PROXY_URL=http://127.0.0.1:8080"
Environment="PDCP_AGENT_TAGS=production"
Environment="PDCP_AGENT_ID=unique-agent-id"
ExecStart=/usr/local/bin/pdcp-agent -agent-output /var/lib/pdcp-agent/output -verbose
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

**4. Enable and start the service:**

```bash
# Reload systemd
sudo systemctl daemon-reload

# Enable service to start on boot
sudo systemctl enable pdcp-agent

# Start the service
sudo systemctl start pdcp-agent

# Check status
sudo systemctl status pdcp-agent

# View logs
sudo journalctl -u pdcp-agent -f
```

**Security considerations:**
- Run as non-root user (`pdcp-agent`)
- Limit file system access to necessary directories
- Use AppArmor/SELinux if available
- Set appropriate file permissions (output directory)

#### macOS (launchd)

**1. Download and install the binary:**

```bash
# Download binary
curl -L https://github.com/projectdiscovery/pdtm-agent/releases/latest/download/pdcp-agent-darwin-amd64 -o /usr/local/bin/pdcp-agent
chmod +x /usr/local/bin/pdcp-agent
```

**2. Create directories:**

```bash
mkdir -p ~/.pdcp-agent/{output,logs}
```

**3. Create launchd plist** `~/Library/LaunchAgents/com.projectdiscovery.pdcp-agent.plist`:

> **Note:** Replace `YOUR_USERNAME` in the plist file with your actual macOS username.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.projectdiscovery.pdcp-agent</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/pdcp-agent</string>
        <string>-agent-output</string>
        <string>/Users/YOUR_USERNAME/.pdcp-agent/output</string>
        <string>-verbose</string>
        <string>-agent-tags</string>
        <string>production</string>
        <string>-agent-id</string>
        <string>unique-agent-id</string>
    </array>
    <key>EnvironmentVariables</key>
    <dict>
        <key>PDCP_API_KEY</key>
        <string>your-api-key</string>
        <key>PDCP_API_SERVER</key>
        <string>https://api.projectdiscovery.io</string>
        <key>PUNCH_HOLE_HOST</key>
        <string>proxy.projectdiscovery.io</string>
        <key>PUNCH_HOLE_HTTP_PORT</key>
        <string>8880</string>
        <key>PDCP_TEAM_ID</key>
        <string>your-team-id</string>
        <key>PROXY_URL</key>
        <string>http://127.0.0.1:8080</string>
    </dict>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/Users/YOUR_USERNAME/.pdcp-agent/logs/stdout.log</string>
    <key>StandardErrorPath</key>
    <string>/Users/YOUR_USERNAME/.pdcp-agent/logs/stderr.log</string>
</dict>
</plist>
```

**4. Load and start the service:**

```bash
# Load service
launchctl load ~/Library/LaunchAgents/com.projectdiscovery.pdcp-agent.plist

# Start service
launchctl start com.projectdiscovery.pdcp-agent

# Check status
launchctl list | grep pdcp-agent

# View logs
tail -f ~/.pdcp-agent/logs/stdout.log
tail -f ~/.pdcp-agent/logs/stderr.log
```

**Security considerations:**
- Run as regular user (not root)
- Use keychain for sensitive credentials if needed
- Limit network access if required

#### Windows

**Option A: Using NSSM (Non-Sucking Service Manager)**

**1. Download and install:**

```powershell
# Create directory
New-Item -ItemType Directory -Path "C:\Program Files\pdcp-agent" -Force

# Download binary
Invoke-WebRequest -Uri "https://github.com/projectdiscovery/pdtm-agent/releases/latest/download/pdcp-agent-windows-amd64.exe" -OutFile "C:\Program Files\pdcp-agent\pdcp-agent.exe"

# Download NSSM
Invoke-WebRequest -Uri "https://nssm.cc/release/nssm-2.24.zip" -OutFile "$env:TEMP\nssm.zip"
Expand-Archive -Path "$env:TEMP\nssm.zip" -DestinationPath "C:\nssm" -Force
```

**2. Create output directory:**

```powershell
New-Item -ItemType Directory -Path "C:\ProgramData\pdcp-agent\output" -Force
```

**3. Install service:**

```powershell
# Install service
C:\nssm\nssm-2.24\win64\nssm.exe install pdcp-agent "C:\Program Files\pdcp-agent\pdcp-agent.exe"

# Set arguments
C:\nssm\nssm-2.24\win64\nssm.exe set pdcp-agent AppParameters "-agent-output C:\ProgramData\pdcp-agent\output -verbose -agent-tags production -agent-id unique-agent-id"

# Set environment variables
C:\nssm\nssm-2.24\win64\nssm.exe set pdcp-agent AppEnvironmentExtra "PDCP_API_KEY=your-api-key" "PDCP_API_SERVER=https://api.projectdiscovery.io" "PUNCH_HOLE_HOST=proxy.projectdiscovery.io" "PUNCH_HOLE_HTTP_PORT=8880" "PDCP_TEAM_ID=your-team-id" "PROXY_URL=http://127.0.0.1:8080"

# Set service account (use low-privilege account)
C:\nssm\nssm-2.24\win64\nssm.exe set pdcp-agent ObjectName "NT AUTHORITY\LOCAL SERVICE"

# Set startup type
C:\nssm\nssm-2.24\win64\nssm.exe set pdcp-agent Start SERVICE_AUTO_START

# Start service
C:\nssm\nssm-2.24\win64\nssm.exe start pdcp-agent

# Check status
Get-Service pdcp-agent
```

**Option B: Using Task Scheduler**

**1. Open Task Scheduler** and create a new task

**2. General tab:**
- Name: `PDCP Agent`
- Run whether user is logged on or not
- Run with highest privileges: **Unchecked** (use low privileges)

**3. Triggers tab:**
- New trigger: At startup

**4. Actions tab:**
- New action: Start a program
- Program: `C:\Program Files\pdcp-agent\pdcp-agent.exe`
- Arguments: `-agent-output C:\ProgramData\pdcp-agent\output -verbose -agent-tags production -agent-id unique-agent-id`

**5. Conditions tab:**
- Uncheck "Start the task only if the computer is on AC power"

**6. Settings tab:**
- Check "If the task fails, restart every: 10 minutes"
- Check "If the running task does not end when requested, force it to stop"

**7. Environment variables:**
Create a batch file wrapper or use Task Scheduler's environment variable support to set:
- `PDCP_API_KEY`
- `PDCP_API_SERVER`
- `PUNCH_HOLE_HOST`
- `PUNCH_HOLE_HTTP_PORT`
- `PDCP_TEAM_ID`
- `PROXY_URL`

**Security considerations:**
- Use `LOCAL SERVICE` or a dedicated low-privilege account
- Limit file system access to necessary directories
- Use Windows Firewall to restrict network access if needed

#### Kubernetes

**Quick Start (One-liner):**

```bash
# Create secret and configmap
kubectl create secret generic pdcp-agent-secret \
  --from-literal=PDCP_API_KEY=your-api-key \
  --from-literal=PDCP_TEAM_ID=your-team-id

kubectl create configmap pdcp-agent-config \
  --from-literal=PDCP_API_SERVER=https://api.projectdiscovery.io \
  --from-literal=PUNCH_HOLE_HOST=proxy.projectdiscovery.io \
  --from-literal=PUNCH_HOLE_HTTP_PORT=8880 \
  --from-literal=PROXY_URL=http://127.0.0.1:8080

# Deploy using the manifest file
kubectl apply -f examples/pdcp-agent-deployment.yaml
```

> **Note:** For a production-ready deployment, use the full deployment manifest below which properly references Secrets and ConfigMaps.

**Full Deployment Manifest:**

Create a Kubernetes deployment with proper configuration:

**1. Create a Secret for sensitive data:**

```bash
kubectl create secret generic pdcp-agent-secret \
  --from-literal=PDCP_API_KEY=your-api-key \
  --from-literal=PDCP_TEAM_ID=your-team-id
```

**2. Create a ConfigMap for configuration:**

```bash
kubectl create configmap pdcp-agent-config \
  --from-literal=PDCP_API_SERVER=https://api.projectdiscovery.io \
  --from-literal=PUNCH_HOLE_HOST=proxy.projectdiscovery.io \
  --from-literal=PUNCH_HOLE_HTTP_PORT=8880 \
  --from-literal=PROXY_URL=http://127.0.0.1:8080
```

**3. Create deployment manifest** `pdcp-agent-deployment.yaml`:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: pdcp-agent
  labels:
    app: pdcp-agent
spec:
  replicas: 1
  selector:
    matchLabels:
      app: pdcp-agent
  template:
    metadata:
      labels:
        app: pdcp-agent
    spec:
      # Run as non-root user for security
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        fsGroup: 1000
      containers:
      - name: pdcp-agent
        image: pdcp-agent:latest
        imagePullPolicy: IfNotPresent
        args:
          - -agent-output
          - /output
          - -verbose
          - -agent-tags
          - production
          - -agent-id
          - unique-agent-id
        env:
          # Sensitive data from Secret
          - name: PDCP_API_KEY
            valueFrom:
              secretKeyRef:
                name: pdcp-agent-secret
                key: PDCP_API_KEY
          - name: PDCP_TEAM_ID
            valueFrom:
              secretKeyRef:
                name: pdcp-agent-secret
                key: PDCP_TEAM_ID
          # Configuration from ConfigMap
          - name: PDCP_API_SERVER
            valueFrom:
              configMapKeyRef:
                name: pdcp-agent-config
                key: PDCP_API_SERVER
          - name: PUNCH_HOLE_HOST
            valueFrom:
              configMapKeyRef:
                name: pdcp-agent-config
                key: PUNCH_HOLE_HOST
          - name: PUNCH_HOLE_HTTP_PORT
            valueFrom:
              configMapKeyRef:
                name: pdcp-agent-config
                key: PUNCH_HOLE_HTTP_PORT
          - name: PROXY_URL
            valueFrom:
              configMapKeyRef:
                name: pdcp-agent-config
                key: PROXY_URL
          # Agent-specific configuration
          - name: PDCP_AGENT_ID
            value: "unique-agent-id"
          - name: PDCP_AGENT_TAGS
            value: "production"
          - name: PDCP_VERBOSE
            value: "true"
        volumeMounts:
          - name: output
            mountPath: /output
        resources:
          requests:
            memory: "256Mi"
            cpu: "100m"
          limits:
            memory: "2Gi"
            cpu: "1000m"
        # Health checks (optional)
        livenessProbe:
          exec:
            command:
              - /bin/sh
              - -c
              - "pgrep pdcp-agent || exit 1"
          initialDelaySeconds: 30
          periodSeconds: 30
        readinessProbe:
          exec:
            command:
              - /bin/sh
              - -c
              - "pgrep pdcp-agent || exit 1"
          initialDelaySeconds: 10
          periodSeconds: 10
      volumes:
        - name: output
          emptyDir: {}
      # Optional: For passive discovery, you may need host network
      # hostNetwork: true
      # For passive discovery, you may need additional capabilities
      # securityContext:
      #   capabilities:
      #     add:
      #       - NET_RAW
      #       - NET_ADMIN
```

**4. Deploy to Kubernetes:**

```bash
# Apply the deployment
kubectl apply -f pdcp-agent-deployment.yaml

# Check deployment status
kubectl get deployments pdcp-agent

# Check pods
kubectl get pods -l app=pdcp-agent

# View logs
kubectl logs -l app=pdcp-agent -f

# Describe pod for troubleshooting
kubectl describe pod -l app=pdcp-agent
```

**5. Scale the deployment (for multiple agents):**

```bash
# Scale to 3 replicas
kubectl scale deployment pdcp-agent --replicas=3

# Or update the replicas in the YAML and reapply
kubectl apply -f pdcp-agent-deployment.yaml
```

**Using Helm (Optional):**

Create a `values.yaml` for Helm:

```yaml
replicaCount: 1

image:
  repository: pdcp-agent
  tag: latest
  pullPolicy: IfNotPresent

agent:
  id: unique-agent-id
  tags: production
  output: /output

env:
  apiServer: https://api.projectdiscovery.io
  punchHoleHost: proxy.projectdiscovery.io
  punchHoleHttpPort: "8880"
  proxyUrl: http://127.0.0.1:8080

secret:
  apiKey: your-api-key
  teamId: your-team-id

resources:
  requests:
    memory: "256Mi"
    cpu: "100m"
  limits:
    memory: "2Gi"
    cpu: "1000m"

securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  fsGroup: 1000
```

**Security considerations:**
- Use Secrets for sensitive data (API keys, team IDs)
- Run containers as non-root user
- Set appropriate resource limits
- Use NetworkPolicies to restrict network access if needed
- For passive discovery, consider using `hostNetwork: true` and additional capabilities
- Use Pod Security Standards/Policies to enforce security constraints
- Consider using a dedicated ServiceAccount with minimal permissions

**Storage options:**
- **emptyDir:** Temporary storage (data lost on pod restart) - good for testing
- **PersistentVolumeClaim:** Persistent storage - recommended for production
- **HostPath:** Direct host access - use with caution

**Example with PersistentVolumeClaim:**

```yaml
# Add to deployment spec
volumes:
  - name: output
    persistentVolumeClaim:
      claimName: pdcp-agent-pvc
```

Create the PVC:

```yaml
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: pdcp-agent-pvc
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 10Gi
```

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

- **Linux (systemd):** `journalctl -u pdcp-agent -f`
- **macOS (launchd):** `~/.pdcp-agent/logs/stdout.log` and `stderr.log`
- **Windows:** Event Viewer → Windows Logs → Application
- **Docker:** `docker logs pdcp-agent -f`
- **Kubernetes:** `kubectl logs -l app=pdcp-agent -f`

#### Enable Verbose Logging

Add `-verbose` flag or set environment variable:
```bash
export PDCP_VERBOSE=true
# or
PDCP_VERBOSE=1 pdcp-agent ...
```

### Best Practices

1. **Agent Tagging:** Use descriptive tags to organize agents (e.g., `production`, `staging`, `scanner-1`)
2. **Network Segmentation:** Use `-agent-networks` to assign agents to specific networks
3. **Resource Management:** Monitor agent resource usage and adjust accordingly
4. **Security:** Always run agents with low privileges, never as root/Administrator
5. **Monitoring:** Set up monitoring and alerting for agent health
6. **Output Management:** Regularly clean up output directories to prevent disk space issues
7. **Agent IDs:** Use unique, descriptive agent IDs for easy identification

### Advanced Configuration

#### Passive Discovery

Enable passive network discovery to automatically discover IPs from network traffic:

```bash
# Using flag
pdcp-agent -passive-discovery -verbose

# Using environment variable
PASSIVE_DISCOVERY=true pdcp-agent -verbose
```

**Requirements:**
- Linux: Requires `libpcap-dev` and appropriate permissions (may need `CAP_NET_RAW`)
- macOS: Requires appropriate permissions
- Windows: May require WinPcap or Npcap

#### Custom Proxy Configuration

Configure a custom proxy for agent communication:

```bash
export PROXY_URL=http://proxy.example.com:8080
pdcp-agent -verbose
```

#### Agent Grouping

Use tags and networks to group agents:

```bash
# Production agents
pdcp-agent -agent-tags production,us-east -agent-networks prod-network

# Staging agents
pdcp-agent -agent-tags staging,us-west -agent-networks staging-network
```

--------

<div align="center">

**pdcp-agent** is made with ❤️ by the [projectdiscovery](https://projectdiscovery.io) team and distributed under [MIT License](LICENSE).


<a href="https://discord.gg/projectdiscovery"><img src="https://raw.githubusercontent.com/projectdiscovery/nuclei-burp-plugin/main/static/join-discord.png" width="300" alt="Join Discord"></a>

</div>