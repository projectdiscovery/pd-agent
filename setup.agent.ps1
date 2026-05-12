#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Automated deployment and update script for pd-agent Docker container

.DESCRIPTION
    This script:
    - Installs or updates Docker Desktop
    - Optionally installs Go
    - Pulls the latest pd-agent Docker image
    - Stops idle running containers
    - Starts a new container with the same configuration
    - Skips update if image is already up to date
#>

param(
    [switch]$InstallGo,
    [string]$ContainerName = "pd-agent",
    [string]$ImageName = "projectdiscovery/pd-agent:latest"
)

$ErrorActionPreference = "Stop"

# Check if running as Administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "This script must be run as Administrator. Please run PowerShell as Administrator and try again."
    exit 1
}

Write-Host "=== PD-Agent Deployment Script ===" -ForegroundColor Cyan
Write-Host ""

# Function to test if Docker is running
function Test-DockerRunning {
    try {
        $null = docker version 2>$null
        return ($LASTEXITCODE -eq 0)
    } catch {
        return $false
    }
}

# Function to wait for Docker daemon
function Wait-Docker {
    Write-Host "Waiting for Docker daemon..." -ForegroundColor Cyan
    $maxWaitMinutes = 2
    $startTime = Get-Date

    while (-not (Test-DockerRunning)) {
        $timeElapsed = $(Get-Date) - $startTime
        if ($timeElapsed.TotalMinutes -ge $maxWaitMinutes) {
            throw "Docker daemon did not become ready within $maxWaitMinutes minutes."
        }
        Start-Sleep -Seconds 2
    }
    Write-Host "Docker daemon is ready." -ForegroundColor Green
}

# Install or update Docker
Write-Host "[1/5] Checking Docker installation..." -ForegroundColor Cyan

# Try to detect if we're on Windows Server or Desktop
$isWindowsServer = $false
try {
    $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem
    if ($osInfo.ProductType -eq 3) {
        $isWindowsServer = $true
    }
} catch {
    # Assume desktop if we can't determine
}

# Choose appropriate Docker setup script
if ($isWindowsServer) {
    $dockerScript = Join-Path $PSScriptRoot "setup.windows.server.ps1"
    Write-Host "Detected Windows Server. Using server binary installation." -ForegroundColor Gray
} else {
    $dockerScript = Join-Path $PSScriptRoot "setup.windows.desktop.ps1"
    Write-Host "Detected Windows Desktop. Using Desktop installation." -ForegroundColor Gray
}

if (Test-Path $dockerScript) {
    Write-Host "Running Docker setup script..." -ForegroundColor Gray
    & $dockerScript
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Docker setup failed. Please check the Docker setup script."
        exit 1
    }
} else {
    Write-Warning "Docker setup script not found at $dockerScript"
    Write-Host "Checking if Docker is installed..." -ForegroundColor Cyan
    if (-not (Test-DockerRunning)) {
        Write-Error "Docker is not running. Please install Docker first or ensure the Docker setup script is in the same directory."
        exit 1
    }
}

Wait-Docker
Write-Host "Docker is ready." -ForegroundColor Green
Write-Host ""

# Optionally install Go
if ($InstallGo) {
    Write-Host "[2/5] Installing/updating Go..." -ForegroundColor Cyan
    $goScript = Join-Path $PSScriptRoot "setup.go.ps1"
    if (Test-Path $goScript) {
        Write-Host "Running Go setup script..." -ForegroundColor Gray
        & $goScript
        if ($LASTEXITCODE -ne 0) {
            Write-Warning "Go setup had issues, but continuing with Docker deployment..."
        }
    } else {
        Write-Warning "Go setup script not found at $goScript"
    }
    Write-Host ""
} else {
    Write-Host "[2/5] Skipping Go installation (use -InstallGo to enable)" -ForegroundColor Gray
    Write-Host ""
}

# Check current image version
Write-Host "[3/5] Checking current Docker image..." -ForegroundColor Cyan
$currentImageId = $null
$imageExists = $false

try {
    $imageInfo = docker images $ImageName --format "{{.ID}}" 2>$null
    if ($imageInfo) {
        $imageExists = $true
        $currentImageId = $imageInfo.Trim()
        Write-Host "Current image ID: $currentImageId" -ForegroundColor Gray
    }
} catch {
    Write-Host "No local image found." -ForegroundColor Gray
}

# Pull latest image
Write-Host "[4/5] Pulling latest pd-agent image..." -ForegroundColor Cyan
try {
    docker pull $ImageName
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to pull Docker image"
    }
    
    $newImageId = (docker images $ImageName --format "{{.ID}}" 2>$null).Trim()
    
    if ($imageExists -and $currentImageId -eq $newImageId) {
        Write-Host "Image is already up to date (ID: $newImageId)" -ForegroundColor Green
        Write-Host "Skipping container restart." -ForegroundColor Yellow
        Write-Host ""
        Write-Host "=== Deployment completed - no changes needed ===" -ForegroundColor Green
        exit 0
    } else {
        if ($imageExists) {
            Write-Host "New image pulled (old: $currentImageId, new: $newImageId)" -ForegroundColor Green
        } else {
            Write-Host "Image pulled successfully (ID: $newImageId)" -ForegroundColor Green
        }
    }
} catch {
    Write-Error "Failed to pull Docker image: $_"
    exit 1
}
Write-Host ""

# Handle existing container
Write-Host "[5/5] Managing container..." -ForegroundColor Cyan

$containerExists = $false
$containerRunning = $false
$containerId = $null

try {
    $containerInfo = docker ps -a --filter "name=$ContainerName" --format "{{.ID}}|{{.Status}}" 2>$null
    if ($containerInfo) {
        $containerExists = $true
        $parts = $containerInfo -split '\|'
        $containerId = $parts[0]
        $status = $parts[1]
        
        if ($status -like "*Up*") {
            $containerRunning = $true
            Write-Host "Container '$ContainerName' is running (ID: $containerId)" -ForegroundColor Yellow
        } else {
            Write-Host "Container '$ContainerName' exists but is stopped (ID: $containerId)" -ForegroundColor Gray
        }
    }
} catch {
    Write-Host "No existing container found." -ForegroundColor Gray
}

# Get original container configuration BEFORE stopping/removing
Write-Host "Retrieving original container configuration..." -ForegroundColor Cyan

$envVars = @()
$volumes = @()
$networkMode = $null
$capAdd = @()
$command = @()
$restartPolicy = $null

if ($containerId) {
    try {
        # Get container configuration before we stop/remove it
        $inspectOutput = docker inspect $ContainerName 2>$null
        if ($inspectOutput) {
            $inspect = $inspectOutput | ConvertFrom-Json
            if ($inspect) {
            # Get environment variables
            if ($inspect[0].Config.Env) {
                $envVars = $inspect[0].Config.Env
            }
            
            # Get volumes
            if ($inspect[0].Mounts) {
                foreach ($mount in $inspect[0].Mounts) {
                    if ($mount.Type -eq "volume" -or $mount.Type -eq "bind") {
                        $volumes += "${($mount.Source)}:$($mount.Destination)"
                    }
                }
            }
            
            # Get network mode
            if ($inspect[0].HostConfig.NetworkMode) {
                $networkMode = $inspect[0].HostConfig.NetworkMode
            }
            
            # Get capabilities
            if ($inspect[0].HostConfig.CapAdd) {
                $capAdd = $inspect[0].HostConfig.CapAdd
            }
            
            # Get restart policy
            if ($inspect[0].HostConfig.RestartPolicy.Name) {
                $restartPolicy = $inspect[0].HostConfig.RestartPolicy.Name
            }
            
            # Get command/args
            if ($inspect[0].Config.Cmd) {
                $command = $inspect[0].Config.Cmd
            }
            if ($inspect[0].Config.Entrypoint) {
                $entrypoint = $inspect[0].Config.Entrypoint
            }
            }
        }
    } catch {
        Write-Warning "Could not retrieve full container configuration: $_"
        Write-Host "Will use default configuration." -ForegroundColor Yellow
    }
}

# Stop and remove existing container
if ($containerRunning) {
    # Check if container is idle (low CPU/memory usage)
    Write-Host "Checking if container is idle..." -ForegroundColor Cyan
    $isIdle = $false
    
    try {
        $stats = docker stats $ContainerName --no-stream --format "{{.CPUPerc}}|{{.MemUsage}}" 2>$null
        if ($stats) {
            $parts = $stats -split '\|'
            $cpuPerc = $parts[0] -replace '%', ''
            $memUsage = $parts[1]
            
            Write-Host "Container stats - CPU: $cpuPerc%, Memory: $memUsage" -ForegroundColor Gray
            
            # Consider idle if CPU < 1% (can be adjusted)
            if ([double]$cpuPerc -lt 1.0) {
                $isIdle = $true
                Write-Host "Container appears to be idle (CPU < 1%)." -ForegroundColor Yellow
            } else {
                Write-Host "Container is active (CPU: $cpuPerc%)." -ForegroundColor Yellow
            }
        } else {
            Write-Warning "Could not get container stats. Assuming container is active."
        }
    } catch {
        Write-Warning "Could not check container stats: $_"
        Write-Warning "Assuming container is active."
    }
    
    # Stop container for update
    if ($isIdle) {
        Write-Host "Stopping idle container for update..." -ForegroundColor Yellow
    } else {
        Write-Host "Stopping active container for update..." -ForegroundColor Yellow
    }
    docker stop $ContainerName
    Start-Sleep -Seconds 2
}

if ($containerExists) {
    Write-Host "Removing old container..." -ForegroundColor Cyan
    docker rm $ContainerName 2>$null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "Old container removed." -ForegroundColor Green
    }
    Start-Sleep -Seconds 1
}

# Build docker run command and start new container
Write-Host "Starting new container with configuration..." -ForegroundColor Cyan

$dockerArgs = @("run", "-d", "--name", $ContainerName)

# Add restart policy
if ($restartPolicy) {
    $dockerArgs += "--restart"
    $dockerArgs += $restartPolicy
} else {
    $dockerArgs += "--restart"
    $dockerArgs += "unless-stopped"
}

# Add environment variables
if ($envVars.Count -gt 0) {
    foreach ($env in $envVars) {
        $dockerArgs += "-e"
        $dockerArgs += $env
    }
} else {
    # Default environment variables if none found
    Write-Host "No environment variables found. Using defaults." -ForegroundColor Yellow
    Write-Host "Note: You may need to set PDCP_API_KEY and PDCP_TEAM_ID manually." -ForegroundColor Yellow
}

# Add volumes
if ($volumes.Count -gt 0) {
    foreach ($vol in $volumes) {
        $dockerArgs += "-v"
        $dockerArgs += $vol
    }
}

# Add network mode (Windows doesn't support host mode, so skip it)
if ($networkMode -and $networkMode -ne "host") {
    $dockerArgs += "--network"
    $dockerArgs += $networkMode
}

# Add capabilities (Windows doesn't support these, but include for compatibility)
if ($capAdd.Count -gt 0 -and $IsLinux) {
    foreach ($cap in $capAdd) {
        $dockerArgs += "--cap-add"
        $dockerArgs += $cap
    }
}

# Add image
$dockerArgs += $ImageName

# Add command/arguments
if ($command.Count -gt 0) {
    $dockerArgs += $command
}

# Execute docker run
Write-Host "Executing: docker $($dockerArgs -join ' ')" -ForegroundColor Gray
try {
    $newContainerId = docker $dockerArgs 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to start container: $newContainerId"
    }
    
    $newContainerId = $newContainerId.Trim()
    Write-Host "Container started successfully (ID: $newContainerId)" -ForegroundColor Green
    
    # Wait a moment and verify
    Start-Sleep -Seconds 2
    $status = docker ps --filter "name=$ContainerName" --format "{{.Status}}" 2>$null
    if ($status) {
        Write-Host "Container status: $status" -ForegroundColor Green
    }
    
} catch {
    Write-Error "Failed to start container: $_"
    Write-Host ""
    Write-Host "You may need to manually start the container with:" -ForegroundColor Yellow
    Write-Host "  docker run -d --name $ContainerName -e PDCP_API_KEY=your-key -e PDCP_TEAM_ID=your-id $ImageName" -ForegroundColor Gray
    exit 1
}

Write-Host ""
Write-Host "=== Deployment completed successfully ===" -ForegroundColor Green
Write-Host ""
Write-Host "Container Name: $ContainerName" -ForegroundColor Cyan
Write-Host "Image: $ImageName" -ForegroundColor Cyan
Write-Host "Container ID: $newContainerId" -ForegroundColor Cyan
Write-Host ""
Write-Host "Useful commands:" -ForegroundColor Yellow
Write-Host "  docker logs $ContainerName -f    # View logs" -ForegroundColor Gray
Write-Host "  docker stop $ContainerName        # Stop container" -ForegroundColor Gray
Write-Host "  docker restart $ContainerName     # Restart container" -ForegroundColor Gray
Write-Host "  docker ps                          # List running containers" -ForegroundColor Gray

