# PowerShell script to install pd-agent as a Windows service using NSSM
# Run this script as Administrator

# Configuration - Update these values
$AgentBinaryPath = "C:\Program Files\pd-agent\pd-agent.exe"
$OutputPath = "C:\ProgramData\pd-agent\output"
$AgentTags = "production"
$NSSMPath = "C:\nssm\nssm-2.24\win64\nssm.exe"

# Environment variables - Update these values
$EnvVars = @{
    "PDCP_API_KEY" = "your-api-key"
    "PDCP_TEAM_ID" = "your-team-id"
}

# Check if running as Administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "This script must be run as Administrator"
    exit 1
}

# Create directories
Write-Host "Creating directories..."
New-Item -ItemType Directory -Path "C:\Program Files\pd-agent" -Force | Out-Null
New-Item -ItemType Directory -Path "C:\ProgramData\pd-agent\output" -Force | Out-Null

# Download binary if not exists
if (-not (Test-Path $AgentBinaryPath)) {
    Write-Host "Downloading pd-agent binary..."
    $DownloadUrl = "https://github.com/projectdiscovery/pd-agent/releases/latest/download/pd-agent-windows-amd64.exe"
    Invoke-WebRequest -Uri $DownloadUrl -OutFile $AgentBinaryPath
    Write-Host "Binary downloaded successfully"
} else {
    Write-Host "Binary already exists, skipping download"
}

# Download NSSM if not exists
if (-not (Test-Path $NSSMPath)) {
    Write-Host "Downloading NSSM..."
    $NSSMZip = "$env:TEMP\nssm.zip"
    Invoke-WebRequest -Uri "https://nssm.cc/release/nssm-2.24.zip" -OutFile $NSSMZip
    Expand-Archive -Path $NSSMZip -DestinationPath "C:\nssm" -Force
    Remove-Item $NSSMZip
    Write-Host "NSSM downloaded and extracted"
} else {
    Write-Host "NSSM already exists, skipping download"
}

# Stop and remove existing service if it exists
$service = Get-Service -Name "pd-agent" -ErrorAction SilentlyContinue
if ($service) {
    Write-Host "Stopping existing service..."
    Stop-Service -Name "pd-agent" -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    Write-Host "Removing existing service..."
    & $NSSMPath remove pd-agent confirm
    Start-Sleep -Seconds 2
}

# Install service
Write-Host "Installing pd-agent service..."
& $NSSMPath install pd-agent $AgentBinaryPath

# Set arguments
$Arguments = "-agent-output $OutputPath -verbose -agent-tags $AgentTags"
& $NSSMPath set pd-agent AppParameters $Arguments

# Set environment variables
$EnvVarString = ($EnvVars.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join " "
& $NSSMPath set pd-agent AppEnvironmentExtra $EnvVarString

# Set service account (use low-privilege account)
& $NSSMPath set pd-agent ObjectName "NT AUTHORITY\LOCAL SERVICE"

# Set startup type
& $NSSMPath set pd-agent Start SERVICE_AUTO_START

# Set description
& $NSSMPath set pd-agent Description "PDCP Agent - ProjectDiscovery Cloud Platform Agent"

# Start service
Write-Host "Starting service..."
Start-Service -Name "pd-agent"

# Check status
Start-Sleep -Seconds 2
$service = Get-Service -Name "pd-agent"
Write-Host ""
Write-Host "Service Status: $($service.Status)"
Write-Host ""
Write-Host "Installation complete!"
Write-Host "To view logs, check Event Viewer -> Windows Logs -> Application"
Write-Host "To manage the service:"
Write-Host "  Start:   Start-Service pd-agent"
Write-Host "  Stop:    Stop-Service pd-agent"
Write-Host "  Status:  Get-Service pd-agent"

