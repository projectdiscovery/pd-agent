# Prepares a Windows host to run pd-agent: adds Microsoft Defender exclusions
# for the agent and the bits it loads at runtime (Chrome's leakless watchdog,
# nuclei-templates payloads) so real-time protection doesn't quarantine them
# mid-scan. Run once before starting pd-agent. Idempotent.
#
# All PD scanners (nuclei/naabu/httpx/dnsx/tlsx) are now embedded in
# pd-agent.exe — earlier versions of this script excluded each as a separate
# process, but those binaries no longer exist on disk.
#
# Usage:
#   .\prereq-windows.ps1
#   .\prereq-windows.ps1 -InstallPath "C:\Program Files\pd-agent"
#   powershell -ExecutionPolicy Bypass -File .\prereq-windows.ps1

[CmdletBinding()]
param(
    [string]$InstallPath = $PSScriptRoot,
    [string[]]$AdditionalProcesses = @()
)

$ErrorActionPreference = "Stop"

# Verify Administrator. We don't auto-elevate via Start-Process -Verb RunAs
# because that path is unreliable on Windows Server (UWP/UAC quirks) - just
# bail with a clear message and let the user start an admin shell manually.
$current = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($current)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "ERROR: This script must be run as Administrator." -ForegroundColor Red
    Write-Host ""
    Write-Host "Open an admin PowerShell:" -ForegroundColor Yellow
    Write-Host "  Win+R -> type 'powershell' -> press Ctrl+Shift+Enter" -ForegroundColor Yellow
    Write-Host "Then re-run this script:" -ForegroundColor Yellow
    Write-Host "  cd $PSScriptRoot" -ForegroundColor Yellow
    Write-Host "  .\prereq-windows.ps1" -ForegroundColor Yellow
    exit 1
}

if (-not (Get-Command Add-MpPreference -ErrorAction SilentlyContinue)) {
    Write-Host "Microsoft Defender cmdlets not available on this host - skipping." -ForegroundColor Yellow
    Write-Host "If you run a third-party AV/EDR, configure exclusions there manually:" -ForegroundColor Yellow
    Write-Host "  paths:     $InstallPath, %TEMP%, %USERPROFILE%\nuclei-templates" -ForegroundColor Yellow
    Write-Host "  processes: pd-agent.exe, leakless.exe" -ForegroundColor Yellow
    exit 0
}

$tempPath = [System.IO.Path]::GetTempPath().TrimEnd('\')

$paths = @(
    $InstallPath
    $tempPath
    # leakless (used by httpx -screenshot via go-rod) extracts a watchdog
    # binary into a per-launch temp dir; Defender flags it as PUA otherwise.
    (Join-Path $tempPath "leakless-*")
    # nuclei-templates contains literal exploit payloads (CVE PoCs); Defender
    # quarantines them as Exploit:Script/* faster than they can be downloaded.
    (Join-Path $env:USERPROFILE "nuclei-templates")
    "C:\Users\*\nuclei-templates"
)

$processes = @(
    "pd-agent.exe"
    "pd-agent-windows-amd64.exe"
    "pd-agent-windows-arm64.exe"
    "leakless.exe"
) + $AdditionalProcesses

Write-Host "Adding Defender exclusions for pd-agent..." -ForegroundColor Cyan
Write-Host ""

foreach ($p in $paths) {
    if (-not $p) { continue }
    Add-MpPreference -ExclusionPath $p -ErrorAction SilentlyContinue
    Write-Host "  path:    $p" -ForegroundColor Green
}

foreach ($proc in $processes) {
    Add-MpPreference -ExclusionProcess $proc -ErrorAction SilentlyContinue
    Write-Host "  process: $proc" -ForegroundColor Green
}

# Restore anything Defender already quarantined from any of our excluded paths
$restorePatterns = @(
    [regex]::Escape($InstallPath),
    [regex]::Escape((Join-Path $env:USERPROFILE "nuclei-templates")),
    "leakless"
) -join "|"
$detections = Get-MpThreatDetection -ErrorAction SilentlyContinue |
    Where-Object { $_.Resources -match $restorePatterns }
if ($detections) {
    Write-Host ""
    Write-Host "Restoring previously quarantined files..." -ForegroundColor Cyan
    foreach ($d in $detections) {
        try {
            Restore-MpThreat -ThreatID $d.ThreatID -ErrorAction Stop
            Write-Host "  restored: $($d.Resources)" -ForegroundColor Green
        } catch {
            Write-Host "  failed:   $($d.Resources) - $_" -ForegroundColor Red
        }
    }
}

Write-Host ""
Write-Host "Done. Verify with:" -ForegroundColor Cyan
Write-Host "  Get-MpPreference | Select-Object ExclusionPath, ExclusionProcess" -ForegroundColor Gray
