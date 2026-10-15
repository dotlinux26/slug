# ==============================================================================
# Slug Universal Installer for Windows PowerShell
# Project: Slug (P2P Secure Workspace Sharing & Synchronization)
# License: Apache-2.0
# ==============================================================================

[CmdletBinding()]
param (
    [string]$InstallPath = "$env:LOCALAPPDATA\slug\bin",
    [string]$Version = "1.0.0-rc1"
)

$ErrorActionPreference = "Stop"

function Write-Info($msg) {
    Write-Host "[*] $msg" -ForegroundColor Cyan
}

function Write-Success($msg) {
    Write-Host "[+] $msg" -ForegroundColor Green
}

function Write-Warn($msg) {
    Write-Host "[!] $msg" -ForegroundColor Yellow
}

function Write-Err($msg) {
    Write-Host "[-] $msg" -ForegroundColor Red
}

Write-Info "Slug Universal Windows Installer v$Version"
Write-Info "Target Architecture: x86_64 / x64"

# 1. Determine Source Binary
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$sourceExe = ""

if (Test-Path "$scriptDir\slug.exe") {
    $sourceExe = "$scriptDir\slug.exe"
} elseif (Test-Path ".\slug.exe") {
    $sourceExe = ".\slug.exe"
} elseif (Test-Path ".\bin\slug.exe") {
    $sourceExe = ".\bin\slug.exe"
} elseif (Test-Path ".\build\Release\slug.exe") {
    $sourceExe = ".\build\Release\slug.exe"
}

if (-not $sourceExe) {
    Write-Info "No local slug.exe detected. Downloading latest release from GitHub..."
    $zipUrl = "https://github.com/slugproject/slug/releases/download/v$Version/slug-$Version-windows-x64.zip"
    $tempZip = Join-Path $env:TEMP "slug-$Version-windows.zip"
    $tempExtract = Join-Path $env:TEMP "slug-extract-$Version"

    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13
        Invoke-WebRequest -Uri $zipUrl -OutFile $tempZip -UseBasicParsing
        Expand-Archive -Path $tempZip -DestinationPath $tempExtract -Force
        $sourceExe = Get-ChildItem -Path $tempExtract -Filter "slug.exe" -Recurse | Select-Object -ExpandProperty FullName -First 1
    } catch {
        Write-Warn "Automated download failed or release not yet uploaded: $($_.Exception.Message)"
        Write-Info "You can build slug.exe on Windows using: scripts\build_windows.bat"
        exit 1
    }
}

if (-not (Test-Path $sourceExe)) {
    Write-Err "Source executable not found at: $sourceExe"
    exit 1
}

# 2. Create Target Directory & Copy Binary
if (-not (Test-Path $InstallPath)) {
    New-Item -ItemType Directory -Path $InstallPath -Force | Out-Null
}

$targetExe = Join-Path $InstallPath "slug.exe"
Write-Info "Installing Slug to: $targetExe"
Copy-Item -Path $sourceExe -Destination $targetExe -Force

# 3. Permanently Add to User PATH
$userPath = [Environment]::GetEnvironmentVariable("PATH", [EnvironmentVariableTarget]::User)
if ($userPath -notlike "*$InstallPath*") {
    Write-Info "Adding $InstallPath to User PATH..."
    $newPath = "$userPath;$InstallPath"
    [Environment]::SetEnvironmentVariable("PATH", $newPath, [EnvironmentVariableTarget]::User)
    $env:PATH = "$env:PATH;$InstallPath"
    Write-Success "User PATH updated successfully."
} else {
    Write-Info "$InstallPath is already in User PATH."
}

# 4. Verify Installation
Write-Info "Verifying Slug executable..."
try {
    & $targetExe version
    Write-Success "Slug installed successfully to $targetExe"
    Write-Host ""
    Write-Host "Quickstart Examples (PowerShell / Command Prompt):" -ForegroundColor White
    Write-Host "  slug add C:\path\to\folder -p 9443 -s 3 --ttl 2h"
    Write-Host "  slug connect -i 192.168.1.50 -p 9443 -o <TOTP>"
    Write-Host "  slug pull .\backup -i 192.168.1.50 -p 9443 -o <TOTP>"
    Write-Host "  slug bench --quick"
    Write-Host "  slug help"
} catch {
    Write-Err "Verification failed: $($_.Exception.Message)"
    exit 1
}
