# Install

Install `pd-agent` on a machine inside the network you want to scan. Once it's running and registered with your ProjectDiscovery Cloud team, you launch scans from the cloud UI and the agent runs them locally.

**Before you start:** grab your `PDCP_API_KEY` and `PDCP_TEAM_ID` from <https://cloud.projectdiscovery.io>.

Pick the install path that matches where the agent will live:

| Method | Best for |
| --- | --- |
| [Docker](#docker) | Single host, fastest way to get going. |
| [Kubernetes](#kubernetes) | Scanning a cluster from inside the cluster (auto-discovers pod/service CIDRs). |
| [Binary + systemd](#linux-binary--systemd) | Linux VMs / servers managed as a real service. |
| [Binary + launchd](#macos-binary--launchd) | macOS workstations and build hosts. |
| [Binary + NSSM](#windows-binary--nssm) | Windows hosts. Includes a Defender prereq script. |
| [`go install`](#go-install-dev-only) | Local dev — building from source. |

---

## Docker

```bash
docker run -d --name pd-agent \
  --network host --cap-add NET_RAW --cap-add NET_ADMIN \
  -e PDCP_API_KEY=your-api-key \
  -e PDCP_TEAM_ID=your-team-id \
  projectdiscovery/pd-agent:latest \
  -agent-network prod-vpc
```

- `--network host` is required so the agent can see your real network interfaces for subnet discovery.
- `NET_RAW` / `NET_ADMIN` enable `naabu` SYN scanning. Drop them if you only need full-connect scans.
- Image ships with Chrome (for `nuclei` / `httpx` headless screenshots) and trusts the system CA bundle.

Image: <https://hub.docker.com/r/projectdiscovery/pd-agent>

---

## Kubernetes

The repo ships a complete manifest at [`examples/pd-agent-deployment.yaml`](../examples/pd-agent-deployment.yaml): namespace, `ServiceAccount`, `ClusterRole` (read-only on nodes/pods/services/ingresses), `ClusterRoleBinding`, and a `Deployment` with `hostNetwork: true`.

```bash
kubectl create namespace pd-agent

kubectl create secret generic pd-agent-secret \
  --namespace pd-agent \
  --from-literal=PDCP_API_KEY=your-api-key \
  --from-literal=PDCP_TEAM_ID=your-team-id

kubectl apply -f examples/pd-agent-deployment.yaml

kubectl -n pd-agent logs -l app=pd-agent -f
```

Before applying, open the manifest and adjust:

- `args:` — set `-agent-network` to the name you want to route scans to (e.g. the cluster identifier).
- `replicas:` — start with 1, scale based on [`docs/scaling.md`](scaling.md).
- `resources:` — defaults are fine for ≤100 hosts; large scans benefit from more memory.

The agent auto-discovers node IPs, pod CIDRs, and service CIDRs and registers them with the platform.

---

## Linux (binary + systemd)

```bash
# 1. Download the release binary
curl -L -o pd-agent.zip \
  https://github.com/projectdiscovery/pd-agent/releases/latest/download/pd-agent_linux_amd64.zip
unzip pd-agent.zip
sudo install -m 0755 pd-agent /usr/local/bin/pd-agent

# 2. Install the unit file
sudo cp examples/pd-agent.service /etc/systemd/system/
sudo systemctl edit pd-agent   # paste PDCP_API_KEY / PDCP_TEAM_ID overrides

# 3. Enable + start
sudo systemctl daemon-reload
sudo systemctl enable --now pd-agent
sudo journalctl -u pd-agent -f
```

Unit file: [`examples/pd-agent.service`](../examples/pd-agent.service). Replace the placeholder env vars before enabling.

---

## macOS (binary + launchd)

```bash
# 1. Download the release binary (Apple Silicon shown; use _amd64 on Intel)
curl -L -o pd-agent.zip \
  https://github.com/projectdiscovery/pd-agent/releases/latest/download/pd-agent_macOS_arm64.zip
unzip pd-agent.zip
sudo install -m 0755 pd-agent /usr/local/bin/pd-agent

# 2. Install the LaunchAgent
mkdir -p ~/.pd-agent/{output,logs}
cp examples/com.projectdiscovery.pd-agent.plist ~/Library/LaunchAgents/
sed -i '' "s/YOUR_USERNAME/$USER/g" ~/Library/LaunchAgents/com.projectdiscovery.pd-agent.plist
# edit the plist and replace the PDCP_* placeholders

# 3. Load it
launchctl load ~/Library/LaunchAgents/com.projectdiscovery.pd-agent.plist
tail -f ~/.pd-agent/logs/stdout.log
```

Plist: [`examples/com.projectdiscovery.pd-agent.plist`](../examples/com.projectdiscovery.pd-agent.plist).

---

## Windows (binary + NSSM)

Windows hosts running real-time AV need exclusions first — `nuclei-templates` is full of literal exploit payloads and Defender will quarantine them mid-scan.

```powershell
# Run elevated (Win+R → powershell → Ctrl+Shift+Enter)
.\scripts\prereq-windows.ps1
```

Then install as a service:

```powershell
# Edit examples\windows-install-nssm.ps1 first — set PDCP_API_KEY / PDCP_TEAM_ID
.\examples\windows-install-nssm.ps1
```

The script:

1. Downloads `pd-agent-windows-amd64.exe` from the latest GitHub release to `C:\Program Files\pd-agent\`.
2. Downloads and unpacks NSSM.
3. Registers `pd-agent` as an auto-start Windows service running as `LOCAL SERVICE`.

Logs go to Event Viewer → Windows Logs → Application. Manage with `Start-Service pd-agent` / `Stop-Service pd-agent` / `Get-Service pd-agent`.

Files:

- Defender prereq → [`scripts/prereq-windows.ps1`](../scripts/prereq-windows.ps1)
- Service installer → [`examples/windows-install-nssm.ps1`](../examples/windows-install-nssm.ps1)

---

## `go install` (dev only)

```bash
go install github.com/projectdiscovery/pd-agent/cmd/pd-agent@latest
```

Or build from a clone:

```bash
git clone https://github.com/projectdiscovery/pd-agent.git
cd pd-agent
make build               # produces ./pd-agent
make build-linux-amd64   # cross-compile, see Makefile for the full matrix
```

No C toolchain or libpcap headers required to build. If libpcap isn't installed on the host at runtime, SYN-scan (`naabu`) warns and skips — install `libpcap` if you need it.

---

## Verifying the install

```bash
pd-agent -version
# prints a semver tag, e.g. v0.0.16
```

When the agent connects, it appears in the cloud UI's **Agents** tab within a few seconds, along with the subnets it has discovered on the host. You can now launch scans from the cloud and route them to this agent's network — see [docs/configuration.md](configuration.md) for how `-agent-network` works.
