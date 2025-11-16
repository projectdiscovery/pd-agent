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

**1. Create Secret and ConfigMap:**

```bash
# Create secret for sensitive data
kubectl create secret generic pd-agent-secret \
  --from-literal=PDCP_API_KEY=your-api-key \
  --from-literal=PDCP_TEAM_ID=your-team-id

# Create configmap for configuration
kubectl create configmap pd-agent-config \
# No additional configmap needed - using defaults
```

**2. Edit the deployment file** command line arguments:
- Update agent tags to your desired tags
- Update agent networks to your desired networks

**3. Deploy:**

```bash
# Optional: Create PVC for persistent storage
kubectl apply -f pd-agent-pvc.yaml

# Deploy the agent
kubectl apply -f pd-agent-deployment.yaml

# Check status
kubectl get pods -l app=pd-agent

# View logs
kubectl logs -l app=pd-agent -f
```

**4. Scale deployment:**

```bash
# Scale to multiple replicas
kubectl scale deployment pd-agent --replicas=3
```

## Important Notes

- **Never commit real API keys or credentials** - all example files use placeholder values
- Replace all placeholder values (`your-api-key`, `your-team-id`, etc.) with actual values
- Ensure the user/service account has appropriate permissions
- Review security considerations in the main README.md

