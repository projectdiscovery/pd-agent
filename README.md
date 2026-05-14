<h4 align="center">ProjectDiscovery Cloud Platform — Agent</h4>

<p align="center">
<a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/license-MIT-_red.svg"></a>
<a href="https://goreportcard.com/badge/github.com/projectdiscovery/pd-agent"><img src="https://goreportcard.com/badge/github.com/projectdiscovery/pd-agent"></a>
<a href="https://github.com/projectdiscovery/pd-agent/releases"><img src="https://img.shields.io/github/release/projectdiscovery/pd-agent"></a>
<a href="https://discord.gg/projectdiscovery"><img src="https://img.shields.io/discord/695645237418131507.svg?logo=discord"></a>
</p>

<p align="center">
  <a href="#what-it-does">What it does</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="docs/install.md">Install</a> •
  <a href="docs/configuration.md">Configuration</a> •
  <a href="docs/scaling.md">Scaling</a>
</p>

## What it does

`pd-agent` lets you scan your **own** internal networks from the [ProjectDiscovery Cloud Platform](https://cloud.projectdiscovery.io).

Install the agent on a machine inside the network you want to scan — a VM, a server, a workstation, a Kubernetes pod — and connect it to your PDCP team. From the cloud UI you can then launch scans against private IPs, internal hostnames, VPC ranges, or Kubernetes clusters, and the agent will run them locally and stream results back. Nothing in your network needs to be exposed publicly.

Nuclei, httpx, naabu, dnsx, and tlsx are all built into the agent — there's nothing else to install on the host.

## Quick Start

1. **Get credentials.** Sign in at <https://cloud.projectdiscovery.io>, copy your **API key** and **team ID**.
2. **Run the agent** on the machine that has access to the network you want to scan:

   ```bash
   docker run -d --name pd-agent \
     --network host --cap-add NET_RAW --cap-add NET_ADMIN \
     -e PDCP_API_KEY=your-api-key \
     -e PDCP_TEAM_ID=your-team-id \
     projectdiscovery/pd-agent:latest \
     -agent-network prod-vpc
   ```

3. **Verify.** Open the cloud UI's **Agents** tab — the agent appears within a few seconds with its discovered subnets.
4. **Scan.** Launch a scan from the UI and route it to your agent's network (`prod-vpc` above). The agent runs it locally and streams results back.

Other install paths (Kubernetes, native binary, systemd, launchd, Windows service) → [docs/install.md](docs/install.md).

## What you can do with it

- Reach **private targets** the cloud platform can't see directly — `10.0.0.0/8`, `192.168.0.0/16`, internal DNS, VPN-only services.
- Scan a **Kubernetes cluster from inside**. The agent auto-discovers node IPs, pod CIDRs, and service CIDRs and reports them to the platform.
- Route scans to **specific sites** by assigning each agent a network name (`-agent-network`) — e.g. one or more agents per data centre, region, or VPC.
- Run **everything PDCP can run in the cloud**, against internal assets — vulnerability scans (nuclei), port discovery (naabu), HTTP probing (httpx), DNS enumeration (dnsx), TLS inspection (tlsx).

## Documentation

| Topic | When to read |
| --- | --- |
| [docs/install.md](docs/install.md) | First-time install on Linux, macOS, Windows, Docker, or Kubernetes. |
| [docs/configuration.md](docs/configuration.md) | Every env var and CLI flag the agent accepts, and what they control. |
| [docs/scaling.md](docs/scaling.md) | When to add more agents and which metric to drive autoscaling from. |

## License

Distributed under the [MIT License](LICENSE.md). Built with ❤️ by [ProjectDiscovery](https://projectdiscovery.io).

<a href="https://discord.gg/projectdiscovery"><img src="https://raw.githubusercontent.com/projectdiscovery/nuclei-burp-plugin/main/static/join-discord.png" width="280" alt="Join Discord"></a>
