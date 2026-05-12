#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Automated silent installation and update of Go (Golang) for Windows

.DESCRIPTION
    This script downloads and installs Go (Golang) for Windows silently.
    It checks if Go is already installed and updates it if a newer version is available.
#>

$ErrorActionPreference = "Stop"

# Check if running as Administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "This script must be run as Administrator. Please run PowerShell as Administrator and try again."
    exit 1
}

# Function to check if Go is already installed
function Test-GoInstalled {
    try {
        $goVersion = go version 2>$null
        if ($goVersion) {
            return @{ Installed = $true; Version = $goVersion }
        }
    } catch {
        # Go not found
    }
    
    # Check for Go installation directory
    $goPaths = @(
        "${env:ProgramFiles}\Go",
        "${env:ProgramFiles(x86)}\Go",
        "$env:LOCALAPPDATA\Go"
    )
    
    foreach ($path in $goPaths) {
        if (Test-Path $path) {
            $goExe = Join-Path $path "bin\go.exe"
            if (Test-Path $goExe) {
                return @{ Installed = $true; Version = "Unknown (installation found)" }
            }
        }
    }
    
    return @{ Installed = $false; Version = $null }
}

# Function to get installed Go version number
function Get-InstalledGoVersion {
    try {
        $versionOutput = go version 2>$null
        if ($versionOutput -match 'go(\d+\.\d+(?:\.\d+)?)') {
            return $matches[1]
        }
        # Try alternative format
        if ($versionOutput -match '(\d+\.\d+(?:\.\d+)?)') {
            return $matches[1]
        }
    } catch {
        # Version parsing failed
    }
    
    # Try to get version from Go installation
    $goPaths = @(
        "${env:ProgramFiles}\Go",
        "${env:ProgramFiles(x86)}\Go",
        "$env:LOCALAPPDATA\Go"
    )
    
    foreach ($path in $goPaths) {
        $goExe = Join-Path $path "bin\go.exe"
        if (Test-Path $goExe) {
            try {
                $fileVersion = (Get-Item $goExe).VersionInfo.FileVersion
                if ($fileVersion) {
                    return $fileVersion
                }
            } catch {
                # Version info not available
            }
        }
    }
    
    return $null
}

# Function to get latest Go version from golang.org
function Get-LatestGoVersion {
    try {
        $ProgressPreference = 'SilentlyContinue'
        # Use golang.org/dl API to get latest stable version
        $releasesUrl = "https://go.dev/dl/?mode=json"
        $response = Invoke-RestMethod -Uri $releasesUrl -UseBasicParsing -ErrorAction Stop
        
        if ($response -and $response.Count -gt 0) {
            # Filter for stable releases (not beta/rc) and Windows amd64
            $stableReleases = $response | Where-Object { 
                $_.version -notmatch 'beta|rc' -and 
                ($_.files | Where-Object { $_.os -eq 'windows' -and $_.arch -eq 'amd64' })
            } | Sort-Object -Property @{Expression={[Version]($_.version -replace '^go','')}} -Descending
            
            if ($stableReleases -and $stableReleases.Count -gt 0) {
                $latest = $stableReleases[0]
                $version = $latest.version -replace '^go', ''
                return $version
            }
        }
    } catch {
        Write-Warning "Could not fetch latest version from golang.org API: $_"
    }
    
    # Fallback: try to get from GitHub releases
    try {
        $ProgressPreference = 'SilentlyContinue'
        $releasesUrl = "https://api.github.com/repos/golang/go/releases/latest"
        $response = Invoke-RestMethod -Uri $releasesUrl -UseBasicParsing -ErrorAction Stop
        
        if ($response.tag_name) {
            # Remove 'go' prefix if present
            $version = $response.tag_name -replace '^go', ''
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

# Function to find Go installation directory
function Get-GoInstallPath {
    $goPaths = @(
        "${env:ProgramFiles}\Go",
        "${env:ProgramFiles(x86)}\Go",
        "$env:LOCALAPPDATA\Go"
    )
    
    foreach ($path in $goPaths) {
        if (Test-Path $path) {
            $goExe = Join-Path $path "bin\go.exe"
            if (Test-Path $goExe) {
                return $path
            }
        }
    }
    
    return $null
}

# Function to uninstall Go
function Uninstall-Go {
    Write-Host "Uninstalling existing Go installation..." -ForegroundColor Cyan
    
    $goPath = Get-GoInstallPath
    if ($goPath) {
        Write-Host "Found Go installation at: $goPath" -ForegroundColor Cyan
        
        # Try to find uninstaller
        $uninstallPaths = @(
            (Join-Path $goPath "Uninstall.exe"),
            (Join-Path (Split-Path $goPath) "Go\Uninstall.exe")
        )
        
        $uninstallerFound = $false
        foreach ($uninstallPath in $uninstallPaths) {
            if (Test-Path $uninstallPath) {
                Write-Host "Found uninstaller at: $uninstallPath" -ForegroundColor Cyan
                try {
                    $process = Start-Process -FilePath $uninstallPath -ArgumentList @("/S") -Wait -PassThru -NoNewWindow -ErrorAction Stop
                    
                    if ($process.ExitCode -eq 0) {
                        Write-Host "Go uninstalled successfully." -ForegroundColor Green
                        $uninstallerFound = $true
                        Start-Sleep -Seconds 3
                        break
                    }
                } catch {
                    Write-Warning "Error running uninstaller: $_"
                }
            }
        }
        
        if (-not $uninstallerFound) {
            # Try to remove via MSI if it was installed via MSI
            try {
                $product = Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -like "*Go*" } | Select-Object -First 1
                if ($product) {
                    Write-Host "Uninstalling Go via MSI..." -ForegroundColor Cyan
                    $product.Uninstall() | Out-Null
                    Start-Sleep -Seconds 3
                    $uninstallerFound = $true
                }
            } catch {
                Write-Warning "Could not uninstall via MSI: $_"
            }
        }
        
        if (-not $uninstallerFound) {
            Write-Warning "Could not find Go uninstaller. The new installation will overwrite the existing one."
        }
    } else {
        Write-Warning "Could not find Go installation directory."
    }
}

# Function to update PATH environment variable
function Update-GoPath {
    $goPath = Get-GoInstallPath
    if (-not $goPath) {
        return
    }
    
    $goBinPath = Join-Path $goPath "bin"
    $currentPath = [Environment]::GetEnvironmentVariable("Path", "Machine")
    
    if ($currentPath -notlike "*$goBinPath*") {
        Write-Host "Adding Go to system PATH..." -ForegroundColor Cyan
        $newPath = $currentPath + ";$goBinPath"
        [Environment]::SetEnvironmentVariable("Path", $newPath, "Machine")
        $env:Path += ";$goBinPath"
        Write-Host "Go bin directory added to PATH." -ForegroundColor Green
    } else {
        Write-Host "Go is already in PATH." -ForegroundColor Green
    }
}

# Function to test if Go is accessible
function Test-GoRunning {
    try {
        $null = go version 2>$null
        return ($LASTEXITCODE -eq 0)
    } catch {
        return $false
    }
}

# Check if Go is already installed
$goStatus = Test-GoInstalled
$needsUpdate = $false

if ($goStatus.Installed) {
    Write-Host "Go is already installed: $($goStatus.Version)" -ForegroundColor Green
    
    # Check if update is needed
    Write-Host "Checking for updates..." -ForegroundColor Cyan
    $installedVersion = Get-InstalledGoVersion
    $latestVersion = Get-LatestGoVersion
    
    if ($installedVersion -and $latestVersion) {
        $comparison = Compare-Version -Version1 $latestVersion -Version2 $installedVersion
        if ($comparison -eq 1) {
            Write-Host "Newer version available: $latestVersion (current: $installedVersion)" -ForegroundColor Yellow
            $needsUpdate = $true
        } elseif ($comparison -eq 0) {
            Write-Host "Go is up to date (version $installedVersion)." -ForegroundColor Green
            # Ensure PATH is set correctly
            Update-GoPath
            exit 0
        } else {
            Write-Host "Installed version ($installedVersion) is newer than latest available ($latestVersion)." -ForegroundColor Green
            exit 0
        }
    } elseif (-not $latestVersion) {
        Write-Host "Could not determine latest version. Skipping update check." -ForegroundColor Yellow
        Update-GoPath
        exit 0
    } else {
        Write-Host "Could not determine installed version. Proceeding with update..." -ForegroundColor Yellow
        $needsUpdate = $true
    }
    
    if ($needsUpdate) {
        Write-Host "`nUpdating Go..." -ForegroundColor Cyan
        Uninstall-Go
    }
} else {
    Write-Host "Go is not installed. Starting installation..." -ForegroundColor Cyan
}

# Create temporary directory for download
$tempDir = Join-Path $env:TEMP "go-install"
if (-not (Test-Path $tempDir)) {
    New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
}

# Get latest version if not already determined
if (-not $latestVersion) {
    $latestVersion = Get-LatestGoVersion
}

if (-not $latestVersion) {
    Write-Error "Could not determine latest Go version. Please check your internet connection and try again."
    exit 1
}

# Go MSI installer download URL
$goInstallerUrl = "https://go.dev/dl/go$latestVersion.windows-amd64.msi"
$goInstallerPath = Join-Path $tempDir "go-installer.msi"

try {
    # Download Go installer
    $action = if ($needsUpdate) { "update" } else { "installation" }
    Write-Host "Downloading Go installer for $action..." -ForegroundColor Cyan
    Write-Host "Version: $latestVersion" -ForegroundColor Gray
    Write-Host "Source: $goInstallerUrl" -ForegroundColor Gray
    
    try {
        $ProgressPreference = 'SilentlyContinue'
        Invoke-WebRequest -Uri $goInstallerUrl -OutFile $goInstallerPath -UseBasicParsing -ErrorAction Stop
    } catch {
        throw "Failed to download Go installer from $goInstallerUrl : $_"
    }
    
    if (-not (Test-Path $goInstallerPath)) {
        throw "Downloaded file not found at expected location: $goInstallerPath"
    }
    
    $fileSize = (Get-Item $goInstallerPath).Length / 1MB
    Write-Host "Downloaded installer size: $([math]::Round($fileSize, 2)) MB" -ForegroundColor Gray
    
    Write-Host "Download completed. Starting silent $action..." -ForegroundColor Cyan
    Write-Host "This may take a few minutes. Please wait..." -ForegroundColor Yellow
    
    # Install Go silently using msiexec
    # /i = Install
    # /quiet = Silent installation
    # /norestart = Don't restart
    # /qn = No UI
    $installArgs = @(
        "/i",
        "`"$goInstallerPath`"",
        "/quiet",
        "/norestart",
        "/qn"
    )
    
    $process = Start-Process -FilePath "msiexec.exe" -ArgumentList $installArgs -Wait -PassThru -NoNewWindow
    
    if ($process.ExitCode -eq 0 -or $process.ExitCode -eq 3010) {
        # Exit code 0 = success, 3010 = success but requires reboot
        if ($needsUpdate) {
            Write-Host "Go update completed successfully!" -ForegroundColor Green
        } else {
            Write-Host "Go installation completed successfully!" -ForegroundColor Green
        }
        
        if ($process.ExitCode -eq 3010) {
            Write-Host "A system reboot is required to complete the $action." -ForegroundColor Yellow
            Write-Host "Please restart your computer and Go will be ready to use." -ForegroundColor Yellow
        } else {
            $actionPast = if ($needsUpdate) { "updated" } else { "installed" }
            Write-Host "Go has been $actionPast." -ForegroundColor Green
            
            # Update PATH
            Update-GoPath
            
            # Refresh environment variables in current session
            $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
            
            # Wait a moment for installation to complete
            Write-Host "Waiting for installation to finalize..." -ForegroundColor Cyan
            Start-Sleep -Seconds 5
            
            # Verify Go is accessible
            if (Test-GoRunning) {
                $finalVersion = go version 2>$null
                if ($finalVersion) {
                    Write-Host "Go is installed and accessible: $finalVersion" -ForegroundColor Green
                }
            } else {
                Write-Host "Go has been installed, but you may need to:" -ForegroundColor Yellow
                Write-Host "  1. Restart your PowerShell session" -ForegroundColor Yellow
                Write-Host "  2. Or restart your computer" -ForegroundColor Yellow
                Write-Host "  3. Verify PATH includes: $(Get-GoInstallPath)\bin" -ForegroundColor Yellow
            }
        }
    } else {
        throw "Go $action failed with exit code: $($process.ExitCode)"
    }
    
} catch {
    Write-Error "Error during Go $action : $_"
    exit 1
} finally {
    # Clean up installer file
    if (Test-Path $goInstallerPath) {
        Remove-Item -Path $goInstallerPath -Force -ErrorAction SilentlyContinue
    }
    if (Test-Path $tempDir) {
        Remove-Item -Path $tempDir -Force -ErrorAction SilentlyContinue
    }
}

Write-Host "`nScript completed successfully!" -ForegroundColor Green

