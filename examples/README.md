# PDCP Agent Installation Examples

This directory contains example configuration files for installing and running `pd-agent` as a system service on different platforms.

## Files

- **pd-agent.service** - systemd service file for Linux
- **com.projectdiscovery.pd-agent.plist** - launchd plist file for macOS
- **windows-install-nssm.ps1** - PowerShell script for Windows installation using NSSM
- **pd-agent-deployment.yaml** - Kubernetes Deployment manifest
- **pd-agent-pvc.yaml** - Kubernetes PersistentVolumeClaim for persistent storage

## Usage

### Linux (systemd)

1. Copy the service file to `/etc/systemd/system/`:
   ```bash
   sudo cp pd-agent.service /etc/systemd/system/
   ```

2. Edit the service file and update the environment variables with your actual values:
   ```bash
   sudo nano /etc/systemd/system/pd-agent.service
   ```

3. Follow the installation steps in the main README.md

### macOS (launchd)

1. Copy the plist file to your LaunchAgents directory:
   ```bash
   cp com.projectdiscovery.pd-agent.plist ~/Library/LaunchAgents/
   ```

2. Edit the plist file and replace `YOUR_USERNAME` with your actual macOS username:
   ```bash
   nano ~/Library/LaunchAgents/com.projectdiscovery.pd-agent.plist
   ```

3. Update all placeholder values (API keys, team ID, etc.)

4. Follow the installation steps in the main README.md

### Windows (NSSM)

1. Review and update the PowerShell script with your configuration values

2. Run the script as Administrator:
   ```powershell
   .\windows-install-nssm.ps1
   ```

3. The script will automatically download the binary and NSSM, install the service, and start it

### Kubernetes

The deployment manifest includes everything needed: namespace, service account, RBAC permissions, and deployment configuration. The agent automatically discovers Kubernetes cluster CIDRs (nodes, pods, services) for scanning.

**1. (Optional) Customize the deployment:**

Edit `pd-agent-deployment.yaml` to update:
- **Namespace**: Change `pd-agent` to your desired namespace (update in all resources)
- **Agent tags** (line 72): Change `production` to your desired tag
- **Agent networks** (line 74): Change `kube-prod-cluster` to your cluster identifier
- **Replicas**: Change `1` to your desired number of replicas

**2. Create secret:**

```bash
# Create namespace (should be the same as the namespace in the deployment file)
kubectl create namespace pd-agent

# Create secret with your PDCP credentials (update namespace if customized)
kubectl create secret generic pd-agent-secret \
  --namespace pd-agent \
  --from-literal=PDCP_API_KEY=your-api-key \
  --from-literal=PDCP_TEAM_ID=your-team-id
```

**3. Deploy:**

```bash
# Deploy the agent (creates namespace, RBAC, and deployment)
kubectl apply -f pd-agent-deployment.yaml

# Check status
kubectl get pods -n pd-agent

# View logs
kubectl logs -n pd-agent -l app=pd-agent -f
```

**Notes:**
- The agent requires `ClusterRole` permissions to discover cluster subnets (nodes, pods, service CIDRs)
- Uses `hostNetwork: true` for network discovery and scanning
- Agent automatically caches and aggregates discovered subnets for efficient scanning

## Important Notes

- **Never commit real API keys or credentials** - all example files use placeholder values
- Replace all placeholder values (`your-api-key`, `your-team-id`, etc.) with actual values
- Ensure the user/service account has appropriate permissions
- Review security considerations in the main README.md

