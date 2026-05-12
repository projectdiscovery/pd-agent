#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Automated silent installation and update of Docker Desktop for Windows

.DESCRIPTION
    This script downloads and installs Docker Desktop for Windows silently.
    It checks if Docker is already installed and updates it if a newer version is available.
#>

$ErrorActionPreference = "Stop"

# Check if running as Administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "This script must be run as Administrator. Please run PowerShell as Administrator and try again."
    exit 1
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
    
    # Check for Docker Desktop service
    $dockerService = Get-Service -Name "com.docker.service" -ErrorAction SilentlyContinue
    if ($dockerService) {
        return @{ Installed = $true; Version = "Unknown (service exists)" }
    }
    
    # Check for Docker Desktop executable
    $dockerDesktopPath = "${env:ProgramFiles}\Docker\Docker\Docker Desktop.exe"
    if (Test-Path $dockerDesktopPath) {
        return @{ Installed = $true; Version = "Unknown (executable exists)" }
    }
    
    # Check for Docker service (for Docker CE installations)
    $dockerServiceCE = Get-Service -Name "docker" -ErrorAction SilentlyContinue
    if ($dockerServiceCE) {
        return @{ Installed = $true; Version = "Docker CE (service exists)" }
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
    
    # Try to get version from Docker Desktop installation
    $dockerDesktopPath = "${env:ProgramFiles}\Docker\Docker\Docker Desktop.exe"
    if (Test-Path $dockerDesktopPath) {
        $fileVersion = (Get-Item $dockerDesktopPath).VersionInfo.FileVersion
        if ($fileVersion) {
            return $fileVersion
        }
    }
    
    return $null
}

# Function to get latest Docker Desktop version from GitHub releases
function Get-LatestDockerVersion {
    try {
        $ProgressPreference = 'SilentlyContinue'
        $releasesUrl = "https://api.github.com/repos/docker/docker-desktop/releases/latest"
        $response = Invoke-RestMethod -Uri $releasesUrl -UseBasicParsing -ErrorAction Stop
        
        if ($response.tag_name) {
            # Remove 'v' prefix if present
            $version = $response.tag_name -replace '^v', ''
            return $version
        }
    } catch {
        Write-Warning "Could not fetch latest version from GitHub API: $_"
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

# Function to uninstall Docker Desktop
function Uninstall-DockerDesktop {
    Write-Host "Uninstalling existing Docker Desktop..." -ForegroundColor Cyan
    
    # Stop Docker Desktop service if running
    try {
        $dockerService = Get-Service -Name "com.docker.service" -ErrorAction SilentlyContinue
        if ($dockerService -and $dockerService.Status -eq 'Running') {
            Write-Host "Stopping Docker Desktop service..." -ForegroundColor Cyan
            Stop-Service -Name "com.docker.service" -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 3
        }
    } catch {
        Write-Warning "Could not stop Docker Desktop service: $_"
    }
    
    # Try to find Docker Desktop uninstaller
    $uninstallPaths = @(
        "${env:ProgramFiles}\Docker\Docker\uninstall.exe",
        "${env:ProgramFiles(x86)}\Docker\Docker\uninstall.exe",
        "${env:LocalAppData}\Programs\Docker\Docker\uninstall.exe"
    )
    
    $uninstallerFound = $false
    foreach ($path in $uninstallPaths) {
        if (Test-Path $path) {
            Write-Host "Found uninstaller at: $path" -ForegroundColor Cyan
            try {
                $process = Start-Process -FilePath $path -ArgumentList @("--quiet", "--unattended") -Wait -PassThru -NoNewWindow -ErrorAction Stop
                
                if ($process.ExitCode -eq 0 -or $process.ExitCode -eq 3010) {
                    Write-Host "Docker Desktop uninstalled successfully." -ForegroundColor Green
                    $uninstallerFound = $true
                    
                    # Wait a bit for cleanup
                    Write-Host "Waiting for cleanup to complete..." -ForegroundColor Cyan
                    Start-Sleep -Seconds 5
                    break
                } else {
                    Write-Warning "Uninstaller exited with code: $($process.ExitCode)"
                }
            } catch {
                Write-Warning "Error running uninstaller at $path : $_"
            }
        }
    }
    
    if (-not $uninstallerFound) {
        Write-Warning "Could not find Docker Desktop uninstaller. Proceeding with installation anyway..."
        Write-Warning "The new installation may overwrite the existing installation."
    }
}

# Check if Docker is already installed
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
        Write-Host "`nUpdating Docker Desktop..." -ForegroundColor Cyan
        Uninstall-DockerDesktop
    }
} else {
    Write-Host "Docker is not installed. Starting installation..." -ForegroundColor Cyan
}

# Create temporary directory for download
$tempDir = Join-Path $env:TEMP "docker-install"
if (-not (Test-Path $tempDir)) {
    New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
}

# Docker Desktop download URL (latest stable version)
$dockerInstallerUrl = "https://desktop.docker.com/win/main/amd64/Docker%20Desktop%20Installer.exe"
$dockerInstallerPath = Join-Path $tempDir "DockerDesktopInstaller.exe"

try {
    # Download Docker Desktop installer
    $action = if ($needsUpdate) { "update" } else { "installation" }
    Write-Host "Downloading Docker Desktop installer for $action..." -ForegroundColor Cyan
    Write-Host "Source: $dockerInstallerUrl" -ForegroundColor Gray
    
    try {
        $ProgressPreference = 'SilentlyContinue'
        Invoke-WebRequest -Uri $dockerInstallerUrl -OutFile $dockerInstallerPath -UseBasicParsing -ErrorAction Stop
    } catch {
        throw "Failed to download Docker Desktop installer from $dockerInstallerUrl : $_"
    }
    
    if (-not (Test-Path $dockerInstallerPath)) {
        throw "Downloaded file not found at expected location: $dockerInstallerPath"
    }
    
    $fileSize = (Get-Item $dockerInstallerPath).Length / 1MB
    Write-Host "Downloaded installer size: $([math]::Round($fileSize, 2)) MB" -ForegroundColor Gray
    
    Write-Host "Download completed. Starting silent $action..." -ForegroundColor Cyan
    Write-Host "This may take several minutes. Please wait..." -ForegroundColor Yellow
    
    # Install Docker Desktop silently
    # install = Install/update mode
    # --quiet = Quiet mode (no UI)
    # --accept-license = Accept license agreement
    $installArgs = @(
        "install",
        "--quiet",
        "--accept-license"
    )
    
    $process = Start-Process -FilePath $dockerInstallerPath -ArgumentList $installArgs -Wait -PassThru -NoNewWindow
    
    if ($process.ExitCode -eq 0 -or $process.ExitCode -eq 3010) {
        # Exit code 0 = success, 3010 = success but requires reboot
        if ($needsUpdate) {
            Write-Host "Docker Desktop update completed successfully!" -ForegroundColor Green
        } else {
            Write-Host "Docker Desktop installation completed successfully!" -ForegroundColor Green
        }
        
        if ($process.ExitCode -eq 3010) {
            Write-Host "A system reboot is required to complete the $action." -ForegroundColor Yellow
            Write-Host "Please restart your computer and Docker Desktop will be ready to use." -ForegroundColor Yellow
        } else {
            $actionPast = if ($needsUpdate) { "updated" } else { "installed" }
            Write-Host "Docker Desktop has been $actionPast." -ForegroundColor Green
            
            # Wait a moment for services to start
            Write-Host "Waiting for Docker services to initialize..." -ForegroundColor Cyan
            Start-Sleep -Seconds 10
            
            # Verify Docker is accessible (if not requiring reboot)
            if (Test-DockerRunning) {
                $finalVersion = docker --version 2>$null
                if ($finalVersion) {
                    Write-Host "Docker is running: $finalVersion" -ForegroundColor Green
                }
            } else {
                Write-Host "Docker Desktop may need a few more moments to start, or you may need to restart your computer." -ForegroundColor Yellow
            }
            
            Write-Host "After restart (if needed), Docker Desktop should start automatically." -ForegroundColor Yellow
        }
    } else {
        throw "Docker Desktop $action failed with exit code: $($process.ExitCode)"
    }
    
} catch {
    Write-Error "Error during Docker Desktop $action : $_"
    exit 1
} finally {
    # Clean up installer file
    if (Test-Path $dockerInstallerPath) {
        Remove-Item -Path $dockerInstallerPath -Force -ErrorAction SilentlyContinue
    }
    if (Test-Path $tempDir) {
        Remove-Item -Path $tempDir -Force -ErrorAction SilentlyContinue
    }
}

Write-Host "`nScript completed successfully!" -ForegroundColor Green

