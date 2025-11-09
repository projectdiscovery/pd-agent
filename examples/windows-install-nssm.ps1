# PowerShell script to install pdcp-agent as a Windows service using NSSM
# Run this script as Administrator

# Configuration - Update these values
$AgentBinaryPath = "C:\Program Files\pdcp-agent\pdcp-agent.exe"
$OutputPath = "C:\ProgramData\pdcp-agent\output"
$AgentID = "unique-agent-id"
$AgentTags = "production"
$NSSMPath = "C:\nssm\nssm-2.24\win64\nssm.exe"

# Environment variables - Update these values
$EnvVars = @{
    "PDCP_API_KEY" = "your-api-key"
    "PDCP_API_SERVER" = "https://api.projectdiscovery.io"
    "PUNCH_HOLE_HOST" = "proxy.projectdiscovery.io"
    "PUNCH_HOLE_HTTP_PORT" = "8880"
    "PDCP_TEAM_ID" = "your-team-id"
    "PROXY_URL" = "http://127.0.0.1:8080"
}

# Check if running as Administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "This script must be run as Administrator"
    exit 1
}

# Create directories
Write-Host "Creating directories..."
New-Item -ItemType Directory -Path "C:\Program Files\pdcp-agent" -Force | Out-Null
New-Item -ItemType Directory -Path "C:\ProgramData\pdcp-agent\output" -Force | Out-Null

# Download binary if not exists
if (-not (Test-Path $AgentBinaryPath)) {
    Write-Host "Downloading pdcp-agent binary..."
    $DownloadUrl = "https://github.com/projectdiscovery/pdtm-agent/releases/latest/download/pdcp-agent-windows-amd64.exe"
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
$service = Get-Service -Name "pdcp-agent" -ErrorAction SilentlyContinue
if ($service) {
    Write-Host "Stopping existing service..."
    Stop-Service -Name "pdcp-agent" -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    Write-Host "Removing existing service..."
    & $NSSMPath remove pdcp-agent confirm
    Start-Sleep -Seconds 2
}

# Install service
Write-Host "Installing pdcp-agent service..."
& $NSSMPath install pdcp-agent $AgentBinaryPath

# Set arguments
$Arguments = "-agent-output $OutputPath -verbose -agent-tags $AgentTags -agent-id $AgentID"
& $NSSMPath set pdcp-agent AppParameters $Arguments

# Set environment variables
$EnvVarString = ($EnvVars.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join " "
& $NSSMPath set pdcp-agent AppEnvironmentExtra $EnvVarString

# Set service account (use low-privilege account)
& $NSSMPath set pdcp-agent ObjectName "NT AUTHORITY\LOCAL SERVICE"

# Set startup type
& $NSSMPath set pdcp-agent Start SERVICE_AUTO_START

# Set description
& $NSSMPath set pdcp-agent Description "PDCP Agent - ProjectDiscovery Cloud Platform Agent"

# Start service
Write-Host "Starting service..."
Start-Service -Name "pdcp-agent"

# Check status
Start-Sleep -Seconds 2
$service = Get-Service -Name "pdcp-agent"
Write-Host ""
Write-Host "Service Status: $($service.Status)"
Write-Host ""
Write-Host "Installation complete!"
Write-Host "To view logs, check Event Viewer -> Windows Logs -> Application"
Write-Host "To manage the service:"
Write-Host "  Start:   Start-Service pdcp-agent"
Write-Host "  Stop:    Stop-Service pdcp-agent"
Write-Host "  Status:  Get-Service pdcp-agent"

