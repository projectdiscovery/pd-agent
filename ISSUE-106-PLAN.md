# Issue #106: Documentation for pdcp-agent One-liner Execution

## Overview
This plan outlines the steps needed to add comprehensive documentation for executing `pdcp-agent` with one-liner commands, including Docker execution and system-level installation instructions for Linux, macOS, and Windows.

## Goals
1. Ensure Dockerfile is production-ready
2. Add one-liner execution examples to documentation
3. Add Docker-based execution examples
4. Add system installation and configuration examples for Linux, macOS, and Windows
5. Explain distributed vs mirror mode execution

---

## Task Breakdown

### 1. Dockerfile Review and Verification
**Status:** ✅ Dockerfile exists and appears ready

**Actions:**
- [x] Verify Dockerfile builds successfully
- [ ] Test Docker image execution with sample environment variables
- [ ] Verify all required tools (dnsx, naabu, httpx, tlsx, nuclei) are properly included
- [ ] Ensure ENTRYPOINT allows command-line arguments to be passed
- [ ] Verify environment variable defaults are appropriate

**Current Dockerfile Status:**
- ✅ Multi-stage build with golang builder
- ✅ Includes all required tools (dnsx, naabu, httpx, tlsx, nuclei)
- ✅ Sets up Chrome for headless browsing
- ✅ ENTRYPOINT configured to accept arguments
- ✅ Environment variables defined with defaults

**Verification Commands:**
```bash
# Build the image
docker build -t pdcp-agent:latest .

# Test run with environment variables
docker run --rm -e PDCP_API_KEY="your-key" -e PDCP_TEAM_ID="your-team" pdcp-agent:latest -verbose
```

---

### 2. Update README.md with pdcp-agent Documentation

**Location:** `/Users/mzack/go/src/github.com/projectdiscovery/pdtm-agent/README.md`

**Current State:** README focuses on `pdtm` tool, needs new section for `pdcp-agent`

**Required Sections:**

#### 2.1. Add New Section: "PDCP Agent"
Add a new major section after the existing `pdtm` documentation covering:
- What is pdcp-agent
- Use cases
- Key features

#### 2.2. Installation Methods
- Binary installation
- Docker installation
- System service installation (Linux/macOS/Windows)

#### 2.3. Quick Start - One-liner Examples

**2.3.1. Direct Binary Execution**
```bash
PDCP_API_KEY=your-api-key \
PDCP_API_SERVER=https://api.projectdiscovery.io \
PUNCH_HOLE_HOST=proxy.projectdiscovery.io \
PUNCH_HOLE_HTTP_PORT=8880 \
PDCP_TEAM_ID=your-team-id \
PROXY_URL=http://127.0.0.1:8080 \
pdcp-agent -agent-output /path/to/output -verbose -agent-tags production -agent-id unique-agent-id
```

**2.3.2. Docker Execution**
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

**2.3.3. Docker Compose Example**
Create a `docker-compose.yml` example for easier deployment.

#### 2.4. Environment Variables Reference
Document all environment variables:
- `PDCP_API_KEY` (required) - API key for authentication
- `PDCP_API_SERVER` (optional) - API server URL (default: https://api.dev.projectdiscovery.io)
- `PUNCH_HOLE_HOST` (optional) - Proxy host (default: proxy-dev.projectdiscovery.io)
- `PUNCH_HOLE_HTTP_PORT` (optional) - Proxy HTTP port (default: 8880)
- `PDCP_TEAM_ID` (required) - Team identifier
- `PROXY_URL` (optional) - Local proxy URL (default: http://127.0.0.1:8080)
- `PDCP_AGENT_ID` (optional) - Agent identifier (auto-generated if not provided)
- `PDCP_AGENT_TAGS` (optional) - Comma-separated agent tags
- `PDCP_AGENT_NETWORKS` (optional) - Comma-separated network identifiers
- `PDCP_AGENT_OUTPUT` (optional) - Output directory path
- `PDCP_AGENT_NAME` (optional) - Agent display name
- `PDCP_VERBOSE` (optional) - Enable verbose logging (true/1)
- `PASSIVE_DISCOVERY` (optional) - Enable passive discovery (true/1)

#### 2.5. Command-Line Flags Reference
Document all command-line flags:
- `-verbose` - Show verbose output
- `-agent-output <path>` - Agent output folder
- `-agent-id <id>` - Specify the ID for the agent
- `-agent-tags <tags>` - Specify tags for the agent (comma-separated)
- `-agent-networks <networks>` - Specify networks for the agent (comma-separated)
- `-agent-name <name>` - Specify the name for the agent
- `-passive-discovery` - Enable passive discovery via libpcap/gopacket

---

### 3. System Installation and Configuration

#### 3.1. Linux (systemd)

**Installation:**
```bash
# Download binary
wget https://github.com/projectdiscovery/pdtm-agent/releases/latest/download/pdcp-agent-linux-amd64 -O /usr/local/bin/pdcp-agent
chmod +x /usr/local/bin/pdcp-agent
```

**Create systemd service file:** `/etc/systemd/system/pdcp-agent.service`
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

**Setup steps:**
```bash
# Create user with low privileges
sudo useradd -r -s /bin/false -d /var/lib/pdcp-agent pdcp-agent
sudo mkdir -p /var/lib/pdcp-agent/output
sudo chown -R pdcp-agent:pdcp-agent /var/lib/pdcp-agent

# Enable and start service
sudo systemctl daemon-reload
sudo systemctl enable pdcp-agent
sudo systemctl start pdcp-agent
sudo systemctl status pdcp-agent
```

**Security considerations:**
- Run as non-root user
- Limit file system access
- Use AppArmor/SELinux if available
- Set appropriate file permissions

#### 3.2. macOS (launchd)

**Installation:**
```bash
# Download binary
curl -L https://github.com/projectdiscovery/pdtm-agent/releases/latest/download/pdcp-agent-darwin-amd64 -o /usr/local/bin/pdcp-agent
chmod +x /usr/local/bin/pdcp-agent
```

**Create launchd plist:** `~/Library/LaunchAgents/com.projectdiscovery.pdcp-agent.plist`
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
        <string>/Users/$(whoami)/.pdcp-agent/output</string>
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
    <string>/Users/$(whoami)/.pdcp-agent/logs/stdout.log</string>
    <key>StandardErrorPath</key>
    <string>/Users/$(whoami)/.pdcp-agent/logs/stderr.log</string>
</dict>
</plist>
```

**Setup steps:**
```bash
# Create directories
mkdir -p ~/.pdcp-agent/{output,logs}

# Load service
launchctl load ~/Library/LaunchAgents/com.projectdiscovery.pdcp-agent.plist

# Start service
launchctl start com.projectdiscovery.pdcp-agent

# Check status
launchctl list | grep pdcp-agent
```

**Security considerations:**
- Run as regular user (not root)
- Use keychain for sensitive credentials if needed
- Limit network access if required

#### 3.3. Windows (NSSM or Task Scheduler)

**Option A: Using NSSM (Non-Sucking Service Manager)**

**Installation:**
```powershell
# Download binary
Invoke-WebRequest -Uri "https://github.com/projectdiscovery/pdtm-agent/releases/latest/download/pdcp-agent-windows-amd64.exe" -OutFile "C:\Program Files\pdcp-agent\pdcp-agent.exe"

# Download NSSM
Invoke-WebRequest -Uri "https://nssm.cc/release/nssm-2.24.zip" -OutFile "nssm.zip"
Expand-Archive -Path "nssm.zip" -DestinationPath "C:\nssm"
```

**Service Installation:**
```powershell
# Install service
C:\nssm\nssm-2.24\win64\nssm.exe install pdcp-agent "C:\Program Files\pdcp-agent\pdcp-agent.exe"

# Set arguments
C:\nssm\nssm-2.24\win64\nssm.exe set pdcp-agent AppParameters "-agent-output C:\ProgramData\pdcp-agent\output -verbose -agent-tags production -agent-id unique-agent-id"

# Set environment variables
C:\nssm\nssm-2.24\win64\nssm.exe set pdcp-agent AppEnvironmentExtra "PDCP_API_KEY=your-api-key" "PDCP_API_SERVER=https://api.projectdiscovery.io" "PUNCH_HOLE_HOST=proxy.projectdiscovery.io" "PUNCH_HOLE_HTTP_PORT=8880" "PDCP_TEAM_ID=your-team-id" "PROXY_URL=http://127.0.0.1:8080"

# Set service account (use low-privilege account)
C:\nssm\nssm-2.24\win64\nssm.exe set pdcp-agent ObjectName "NT AUTHORITY\LOCAL SERVICE"

# Start service
C:\nssm\nssm-2.24\win64\nssm.exe start pdcp-agent
```

**Option B: Using Task Scheduler**

Create a scheduled task that runs at system startup with low privileges.

**Security considerations:**
- Use LOCAL SERVICE or a dedicated low-privilege account
- Limit file system access
- Use Windows Firewall to restrict network access if needed

---

### 4. Execution Modes Documentation

#### 4.1. Distributed Mode (worker_behavior: "distribute")
**Description:** In distributed mode, the scan/enumeration workload is split across multiple agents. Each agent processes a portion of the work, allowing for parallel execution and faster completion times.

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

#### 4.2. Mirror Mode (default, worker_behavior: not "distribute")
**Description:** In mirror mode, every agent executes the complete scan/enumeration independently. All agents run the same work, which is useful for redundancy, local template execution, and privilege escalation scenarios.

**Use Cases:**
- Local templates (e.g., privilege escalation checks)
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

---

### 5. Additional Documentation Sections

#### 5.1. Troubleshooting
- Common issues and solutions
- Log file locations
- How to enable verbose logging
- Network connectivity issues
- Authentication problems

#### 5.2. Best Practices
- Agent tagging strategies
- Network segmentation
- Resource management
- Security considerations
- Monitoring and alerting

#### 5.3. Advanced Configuration
- Passive discovery setup
- Custom proxy configuration
- Output management
- Agent grouping strategies

---

## Implementation Checklist

### Phase 1: Dockerfile Verification
- [ ] Test Dockerfile build
- [ ] Verify all tools are included
- [ ] Test Docker execution with sample config
- [ ] Document any required changes

### Phase 2: README Updates
- [ ] Add pdcp-agent section to README
- [ ] Add one-liner examples (binary)
- [ ] Add one-liner examples (Docker)
- [ ] Add environment variables documentation
- [ ] Add command-line flags documentation
- [ ] Add execution modes explanation (distributed vs mirror)

### Phase 3: System Installation Guides
- [ ] Linux systemd service guide
- [ ] macOS launchd guide
- [ ] Windows NSSM guide
- [ ] Windows Task Scheduler guide
- [ ] Security best practices for each platform

### Phase 4: Additional Documentation
- [ ] Troubleshooting section
- [ ] Best practices section
- [ ] Advanced configuration section
- [ ] Docker Compose example file

### Phase 5: Review and Testing
- [ ] Review all documentation for accuracy
- [ ] Test all one-liner examples
- [ ] Verify system installation guides work
- [ ] Get feedback from team
- [ ] Final documentation polish

---

## Example Commands (Placeholder Format)

### Direct Binary Execution
```bash
PDCP_API_KEY=your-api-key \
PDCP_API_SERVER=https://api.projectdiscovery.io \
PUNCH_HOLE_HOST=proxy.projectdiscovery.io \
PUNCH_HOLE_HTTP_PORT=8880 \
PDCP_TEAM_ID=your-team-id \
PROXY_URL=http://127.0.0.1:8080 \
pdcp-agent -agent-output /path/to/output -verbose -agent-tags production -agent-id unique-agent-id
```

### Docker Execution
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

### Docker Compose
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

---

## Notes

1. **Security:** All examples use placeholder values. Users must replace with actual credentials.
2. **Platforms:** Focus on Linux, macOS, and Windows as primary platforms.
3. **Privileges:** All system service examples use low-privilege accounts.
4. **Mode Explanation:** Clearly explain when to use distributed vs mirror mode.
5. **Local Templates:** Emphasize that mirror mode is recommended for local templates like privilege escalation.

---

## Timeline Estimate

- **Phase 1:** 1-2 hours (Dockerfile verification)
- **Phase 2:** 3-4 hours (README updates)
- **Phase 3:** 4-5 hours (System installation guides)
- **Phase 4:** 2-3 hours (Additional documentation)
- **Phase 5:** 2-3 hours (Review and testing)

**Total:** 12-17 hours

---

## Success Criteria

1. ✅ Dockerfile is verified and working
2. ✅ One-liner examples are documented and tested
3. ✅ Docker execution is documented with examples
4. ✅ System installation guides exist for Linux, macOS, and Windows
5. ✅ Distributed vs mirror mode is clearly explained
6. ✅ All examples use placeholders instead of real credentials
7. ✅ Security best practices are included
8. ✅ Documentation is clear and easy to follow

