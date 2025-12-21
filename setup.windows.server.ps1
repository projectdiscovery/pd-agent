#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Automated silent installation and update of Docker Engine from binaries for Windows Server

.DESCRIPTION
    This script downloads and installs Docker Engine from static binaries for Windows Server.
    It follows the official Docker documentation for binary installation:
    https://docs.docker.com/engine/install/binaries/
    
    Note: This installs Docker for Windows containers only (not Linux containers).
    For Windows 10/11, use setup.windows.desktop.ps1 instead.
#>

$ErrorActionPreference = "Stop"

# Check if running as Administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "This script must be run as Administrator. Please run PowerShell as Administrator and try again."
    exit 1
}

# Docker installation paths
$dockerInstallPath = Join-Path $env:ProgramFiles "Docker"
$dockerExePath = Join-Path $dockerInstallPath "docker.exe"
$dockerdExePath = Join-Path $dockerInstallPath "dockerd.exe"

# Global flag for restart requirement
$script:RebootRequired = $false

# Check if this is a resume after restart (optional marker file)
$resumeMarker = Join-Path $env:TEMP "docker-setup-resume.txt"

# Function to check if Windows Containers feature is installed
function Test-ContainersFeature {
    try {
        if (Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue) {
            # Windows Server with Server Manager
            $feature = Get-WindowsFeature -Name Containers -ErrorAction SilentlyContinue
            if ($feature) {
                return $feature.Installed
            }
        } else {
            # Windows Server Core or newer versions
            $feature = Get-WindowsOptionalFeature -Online -FeatureName Containers -ErrorAction SilentlyContinue
            if ($feature) {
                return ($feature.State -eq "Enabled")
            }
        }
    } catch {
        Write-Warning "Could not check Containers feature status: $_"
    }
    return $false
}

# Function to install Windows Containers feature
function Install-ContainersFeature {
    Write-Host "Checking Windows Containers feature..." -ForegroundColor Cyan
    
    if (Test-ContainersFeature) {
        Write-Host "Windows Containers feature is already installed." -ForegroundColor Green
        return
    }
    
    Write-Host "Installing Windows Containers feature..." -ForegroundColor Cyan
    Write-Host "This may take several minutes and may require a system restart." -ForegroundColor Yellow
    
    try {
        if (Get-Command Install-WindowsFeature -ErrorAction SilentlyContinue) {
            # Windows Server with Server Manager
            $result = Install-WindowsFeature -Name Containers -IncludeManagementTools
            
            if ($result.RestartNeeded -eq "Yes") {
                $script:RebootRequired = $true
                Write-Host "A system restart is required to complete the Containers feature installation." -ForegroundColor Yellow
            }
            
            if ($result.Success) {
                Write-Host "Windows Containers feature installed successfully." -ForegroundColor Green
            } else {
                throw "Failed to install Containers feature"
            }
        } else {
            # Windows Server Core or newer versions
            $result = Enable-WindowsOptionalFeature -Online -FeatureName Containers -All -NoRestart
            
            if ($result.RestartNeeded -eq $true) {
                $script:RebootRequired = $true
                Write-Host "A system restart is required to complete the Containers feature installation." -ForegroundColor Yellow
            }
            
            Write-Host "Windows Containers feature installed successfully." -ForegroundColor Green
        }
    } catch {
        Write-Error "Failed to install Containers feature: $_"
        throw
    }
}

# Function to check if restart is required and handle it
function Test-AndHandleRestart {
    param(
        [switch]$Silent
    )
    
    if ($script:RebootRequired) {
        Write-Host ""
        Write-Host "=== RESTART REQUIRED ===" -ForegroundColor Yellow
        Write-Host "A system restart is required to complete the installation." -ForegroundColor Yellow
        Write-Host "Please restart your computer and then run this script again to continue." -ForegroundColor Yellow
        Write-Host ""
        
        # Create resume marker
        "Resume after restart" | Out-File -FilePath $resumeMarker -Force
        
        if (-not $Silent) {
            $restart = Read-Host "Would you like to restart now? (Y/N)"
            if ($restart -eq "Y" -or $restart -eq "y") {
                Write-Host "Restarting computer in 10 seconds..." -ForegroundColor Cyan
                Write-Host "Press Ctrl+C to cancel" -ForegroundColor Gray
                Start-Sleep -Seconds 10
                Restart-Computer -Force
            } else {
                Write-Host "Please restart your computer manually and run this script again." -ForegroundColor Yellow
                Write-Host "The script will automatically resume after restart." -ForegroundColor Gray
                exit 0
            }
        } else {
            Write-Host "Please restart your computer manually and run this script again." -ForegroundColor Yellow
            Write-Host "The script will automatically resume after restart." -ForegroundColor Gray
            exit 0
        }
    }
}

# Function to check if Docker is already installed
function Test-DockerInstalled {
    try {
        $dockerVersion = docker --version 2>$null
        if ($dockerVersion) {
            return @{ Installed = $true; Version = $dockerVersion }
        }
    } catch {
        # Docker not found
    }
    
    # Check for Docker service
    $dockerService = Get-Service -Name "docker" -ErrorAction SilentlyContinue
    if ($dockerService) {
        return @{ Installed = $true; Version = "Unknown (service exists)" }
    }
    
    # Check for Docker binaries
    if (Test-Path $dockerExePath) {
        return @{ Installed = $true; Version = "Unknown (binary exists)" }
    }
    
    return @{ Installed = $false; Version = $null }
}

# Function to wait for Docker daemon to be ready
function Wait-Docker {
    Write-Host "Waiting for Docker daemon to be ready..." -ForegroundColor Cyan
    $dockerReady = $false
    $startTime = Get-Date
    $maxWaitMinutes = 2

    while (-not $dockerReady) {
        try {
            $null = docker version 2>$null
            if ($LASTEXITCODE -eq 0) {
                $dockerReady = $true
                Write-Host "Docker daemon is ready." -ForegroundColor Green
                return $true
            }
        } catch {
            # Docker not ready yet
        }
        
        $timeElapsed = $(Get-Date) - $startTime
        if ($timeElapsed.TotalMinutes -ge $maxWaitMinutes) {
            Write-Warning "Docker daemon did not become ready within $maxWaitMinutes minutes."
            return $false
        }
        
        Start-Sleep -Seconds 2
    }
    
    return $false
}

# Function to test if Docker is running and accessible
function Test-DockerRunning {
    try {
        $null = docker version 2>$null
        return ($LASTEXITCODE -eq 0)
    } catch {
        return $false
    }
}

# Function to get installed Docker version number
function Get-InstalledDockerVersion {
    try {
        $versionOutput = docker --version 2>$null
        if ($versionOutput -match 'version (\d+\.\d+\.\d+)') {
            return $matches[1]
        }
        # Try alternative format
        if ($versionOutput -match '(\d+\.\d+\.\d+)') {
            return $matches[1]
        }
    } catch {
        # Version parsing failed
    }
    
    return $null
}

# Function to get latest Docker version from download page
function Get-LatestDockerVersion {
    try {
        $ProgressPreference = 'SilentlyContinue'
        $downloadUrl = "https://download.docker.com/win/static/stable/x86_64/"
        $response = Invoke-WebRequest -Uri $downloadUrl -UseBasicParsing -ErrorAction Stop
        
        # Parse HTML to find latest version
        # Look for links like "docker-24.0.0.zip"
        $matches = [regex]::Matches($response.Content, 'docker-(\d+\.\d+\.\d+)\.zip')
        if ($matches.Count -gt 0) {
            $versions = $matches | ForEach-Object { [Version]$_.Groups[1].Value } | Sort-Object -Descending
            if ($versions.Count -gt 0) {
                return $versions[0].ToString()
            }
        }
    } catch {
        Write-Warning "Could not fetch latest version from download page: $_"
    }
    
    # Fallback: return null to indicate we should proceed with installation/update
    return $null
}

# Function to compare version numbers
function Compare-Version {
    param(
        [string]$Version1,
        [string]$Version2
    )
    
    if ([string]::IsNullOrEmpty($Version1) -or [string]::IsNullOrEmpty($Version2)) {
        return $null
    }
    
    try {
        $v1 = [Version]$Version1
        $v2 = [Version]$Version2
        
        if ($v1 -gt $v2) {
            return 1
        } elseif ($v1 -lt $v2) {
            return -1
        } else {
            return 0
        }
    } catch {
        Write-Warning "Version comparison failed: $_"
        return $null
    }
}

# Function to stop and unregister Docker service
function Stop-DockerService {
    Write-Host "Stopping Docker service..." -ForegroundColor Cyan
    
    try {
        $dockerService = Get-Service -Name "docker" -ErrorAction SilentlyContinue
        if ($dockerService -and $dockerService.Status -eq 'Running') {
            Stop-Service -Name "docker" -Force -ErrorAction Stop
            Write-Host "Docker service stopped." -ForegroundColor Green
            Start-Sleep -Seconds 2
        }
    } catch {
        Write-Warning "Could not stop Docker service: $_"
    }
    
    # Unregister service if it exists
    try {
        $service = Get-Service -Name "docker" -ErrorAction SilentlyContinue
        if ($service) {
            Write-Host "Unregistering Docker service..." -ForegroundColor Cyan
            & $dockerdExePath --unregister-service 2>$null
            Start-Sleep -Seconds 2
        }
    } catch {
        Write-Warning "Could not unregister Docker service: $_"
    }
}

# Function to update PATH environment variable
function Update-DockerPath {
    if (-not (Test-Path $dockerInstallPath)) {
        Write-Warning "Docker installation path not found: $dockerInstallPath"
        return
    }
    
    $currentPath = [Environment]::GetEnvironmentVariable("Path", "Machine")
    
    if ($currentPath -notlike "*$dockerInstallPath*") {
        Write-Host "Adding Docker to system PATH..." -ForegroundColor Cyan
        $newPath = $currentPath + ";$dockerInstallPath"
        [Environment]::SetEnvironmentVariable("Path", $newPath, "Machine")
        
        # Also update current session PATH
        $env:Path += ";$dockerInstallPath"
        
        Write-Host "Docker directory added to PATH: $dockerInstallPath" -ForegroundColor Green
    } else {
        Write-Host "Docker is already in system PATH." -ForegroundColor Green
    }
}

# Check if resuming after restart
if (Test-Path $resumeMarker) {
    Write-Host "Resuming installation after restart..." -ForegroundColor Cyan
    Remove-Item -Path $resumeMarker -Force -ErrorAction SilentlyContinue
    Write-Host ""
}

# Install Windows Containers feature
Write-Host "=== Installing Windows Containers Feature ===" -ForegroundColor Cyan
Write-Host ""
try {
    Install-ContainersFeature
    Test-AndHandleRestart -Silent
} catch {
    Write-Error "Failed to install Windows Containers feature: $_"
    exit 1
}
Write-Host ""

# Check if Docker is already installed
Write-Host "=== Checking Docker Installation ===" -ForegroundColor Cyan
Write-Host ""

$dockerStatus = Test-DockerInstalled
$needsUpdate = $false

if ($dockerStatus.Installed) {
    Write-Host "Docker is already installed: $($dockerStatus.Version)" -ForegroundColor Green
    
    # Check if update is needed
    Write-Host "Checking for updates..." -ForegroundColor Cyan
    $installedVersion = Get-InstalledDockerVersion
    $latestVersion = Get-LatestDockerVersion
    
    if ($installedVersion -and $latestVersion) {
        $comparison = Compare-Version -Version1 $latestVersion -Version2 $installedVersion
        if ($comparison -eq 1) {
            Write-Host "Newer version available: $latestVersion (current: $installedVersion)" -ForegroundColor Yellow
            $needsUpdate = $true
        } elseif ($comparison -eq 0) {
            Write-Host "Docker is up to date (version $installedVersion)." -ForegroundColor Green
            exit 0
        } else {
            Write-Host "Installed version ($installedVersion) is newer than latest available ($latestVersion)." -ForegroundColor Green
            exit 0
        }
    } elseif (-not $latestVersion) {
        Write-Host "Could not determine latest version. Skipping update check." -ForegroundColor Yellow
        exit 0
    } else {
        Write-Host "Could not determine installed version. Proceeding with update..." -ForegroundColor Yellow
        $needsUpdate = $true
    }
    
    if ($needsUpdate) {
        Write-Host "`nUpdating Docker..." -ForegroundColor Cyan
        Stop-DockerService
    }
} else {
    Write-Host "Docker is not installed. Starting installation..." -ForegroundColor Cyan
}

Write-Host ""

# Download and install Docker binaries
Write-Host "=== Installing Docker Binaries ===" -ForegroundColor Cyan
Write-Host ""

# Get latest version if not already determined
if (-not $latestVersion) {
    $latestVersion = Get-LatestDockerVersion
}

if (-not $latestVersion) {
    Write-Error "Could not determine latest Docker version. Please check your internet connection and try again."
    exit 1
}

# Create temporary directory for download
$tempDir = Join-Path $env:TEMP "docker-install"
if (-not (Test-Path $tempDir)) {
    New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
}

# Docker binary download URL
$dockerZipUrl = "https://download.docker.com/win/static/stable/x86_64/docker-$latestVersion.zip"
$dockerZipPath = Join-Path $tempDir "docker-$latestVersion.zip"

try {
    # Download Docker binaries
    $action = if ($needsUpdate) { "update" } else { "installation" }
    Write-Host "Downloading Docker binaries for $action..." -ForegroundColor Cyan
    Write-Host "Version: $latestVersion" -ForegroundColor Gray
    Write-Host "Source: $dockerZipUrl" -ForegroundColor Gray
    
    try {
        $ProgressPreference = 'SilentlyContinue'
        Invoke-WebRequest -Uri $dockerZipUrl -OutFile $dockerZipPath -UseBasicParsing -ErrorAction Stop
    } catch {
        throw "Failed to download Docker binaries from $dockerZipUrl : $_"
    }
    
    if (-not (Test-Path $dockerZipPath)) {
        throw "Downloaded file not found at expected location: $dockerZipPath"
    }
    
    $fileSize = (Get-Item $dockerZipPath).Length / 1MB
    Write-Host "Downloaded archive size: $([math]::Round($fileSize, 2)) MB" -ForegroundColor Gray
    
    Write-Host "Download completed. Extracting binaries..." -ForegroundColor Cyan
    
    # Extract archive to Program Files
    $extractPath = Join-Path $tempDir "docker-extract"
    if (Test-Path $extractPath) {
        Remove-Item -Path $extractPath -Recurse -Force -ErrorAction SilentlyContinue
    }
    New-Item -ItemType Directory -Path $extractPath -Force | Out-Null
    
    Expand-Archive -Path $dockerZipPath -DestinationPath $extractPath -Force -ErrorAction Stop
    
    # Find the docker directory in the extracted files
    $dockerExtractedPath = Get-ChildItem -Path $extractPath -Directory | Where-Object { $_.Name -like "docker*" } | Select-Object -First 1
    if (-not $dockerExtractedPath) {
        # Sometimes files are extracted directly without a subdirectory
        $dockerExtractedPath = $extractPath
    }
    
    Write-Host "Installing Docker binaries to $dockerInstallPath..." -ForegroundColor Cyan
    
    # Create installation directory if it doesn't exist
    if (-not (Test-Path $dockerInstallPath)) {
        New-Item -ItemType Directory -Path $dockerInstallPath -Force | Out-Null
    }
    
    # Copy binaries
    $binaries = @("docker.exe", "dockerd.exe")
    foreach ($binary in $binaries) {
        $sourcePath = Join-Path $dockerExtractedPath.FullName $binary
        if (Test-Path $sourcePath) {
            Copy-Item -Path $sourcePath -Destination (Join-Path $dockerInstallPath $binary) -Force -ErrorAction Stop
            Write-Host "Installed $binary" -ForegroundColor Green
        } else {
            Write-Warning "Binary $binary not found in archive"
        }
    }
    
    # Update PATH environment variable
    Update-DockerPath
    
    # Refresh PATH in current session
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
    
    # Register Docker service
    Write-Host "Registering Docker service..." -ForegroundColor Cyan
    $registerResult = & $dockerdExePath --register-service 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "Service registration output: $registerResult"
        # Continue anyway, service might already be registered
    } else {
        Write-Host "Docker service registered successfully." -ForegroundColor Green
    }
    
    # Start Docker service
    Write-Host "Starting Docker service..." -ForegroundColor Cyan
    try {
        Start-Service -Name "docker" -ErrorAction Stop
        Write-Host "Docker service started successfully." -ForegroundColor Green
    } catch {
        Write-Warning "Could not start Docker service: $_"
        Write-Host "You may need to start it manually: Start-Service docker" -ForegroundColor Yellow
    }
    
    # Wait a moment for service to start
    Start-Sleep -Seconds 5
    
    # Verify Docker is accessible
    if (Test-DockerRunning) {
        $finalVersion = docker --version 2>$null
        if ($finalVersion) {
            Write-Host "Docker is running: $finalVersion" -ForegroundColor Green
        }
        
        # Test with hello-world (Windows container)
        Write-Host "Testing Docker installation..." -ForegroundColor Cyan
        try {
            docker run --rm hello-world:nanoserver 2>&1 | Out-Null
            if ($LASTEXITCODE -eq 0) {
                Write-Host "Docker installation verified successfully!" -ForegroundColor Green
            }
        } catch {
            Write-Warning "Could not run test container, but Docker appears to be installed."
        }
    } else {
        Write-Host "Docker service may need a few more moments to start." -ForegroundColor Yellow
        Write-Host "You can verify with: docker version" -ForegroundColor Yellow
    }
    
    if ($needsUpdate) {
        Write-Host "Docker update completed successfully!" -ForegroundColor Green
    } else {
        Write-Host "Docker installation completed successfully!" -ForegroundColor Green
    }
    
    # Check if restart is still required after Docker installation
    Test-AndHandleRestart -Silent
    
    # Remove resume marker if installation completed successfully
    if (Test-Path $resumeMarker) {
        Remove-Item -Path $resumeMarker -Force -ErrorAction SilentlyContinue
    }
    
} catch {
    Write-Error "Error during Docker $action : $_"
    exit 1
} finally {
    # Clean up temporary files
    if (Test-Path $tempDir) {
        Remove-Item -Path $tempDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Write-Host "`nScript completed successfully!" -ForegroundColor Green
Write-Host ""
Write-Host "Docker binaries installed to: $dockerInstallPath" -ForegroundColor Cyan
Write-Host "Docker has been added to system PATH." -ForegroundColor Green
Write-Host ""
Write-Host "Note: If you're running this script in a new PowerShell session, you may need to:" -ForegroundColor Yellow
Write-Host "  - Close and reopen your PowerShell window, OR" -ForegroundColor Gray
Write-Host "  - Run: `$env:Path = [System.Environment]::GetEnvironmentVariable('Path','Machine') + ';' + [System.Environment]::GetEnvironmentVariable('Path','User')" -ForegroundColor Gray
Write-Host ""
Write-Host "Useful commands:" -ForegroundColor Yellow
Write-Host "  docker version              # Check Docker version" -ForegroundColor Gray
Write-Host "  docker run hello-world:nanoserver  # Test with Windows container" -ForegroundColor Gray
Write-Host "  Get-Service docker          # Check service status" -ForegroundColor Gray
Write-Host "  Start-Service docker        # Start Docker service" -ForegroundColor Gray
Write-Host "  Stop-Service docker        # Stop Docker service" -ForegroundColor Gray

