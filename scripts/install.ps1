# ==============================================================================
# Slug Universal Installer for Windows PowerShell
# Project: Slug (P2P Secure Workspace Sharing & Synchronization)
# License: Apache-2.0
# ==============================================================================

[CmdletBinding()]
param (
    [string]$InstallPath = "$env:LOCALAPPDATA\slug\bin",
    [string]$Version = "1.0.0"
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
$scriptDir = $null
if ($MyInvocation.MyCommand -and $MyInvocation.MyCommand.Path) {
    $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
} elseif ($PSScriptRoot) {
    $scriptDir = $PSScriptRoot
}

$sourceExe = ""

if ($scriptDir -and (Test-Path "$scriptDir\slug.exe")) {
    $sourceExe = "$scriptDir\slug.exe"
} elseif (Test-Path ".\slug.exe") {
    $sourceExe = ".\slug.exe"
} elseif (Test-Path ".\bin\slug.exe") {
    $sourceExe = ".\bin\slug.exe"
} elseif (Test-Path ".\build\Release\slug.exe") {
    $sourceExe = ".\build\Release\slug.exe"
} elseif (Test-Path ".\build_win\Release\slug.exe") {
    $sourceExe = ".\build_win\Release\slug.exe"
}

if (-not $sourceExe) {
    Write-Info "No local slug.exe detected. Downloading latest release from GitHub..."
    $repo = if ($env:SLUG_REPO) { $env:SLUG_REPO } else { "dotlinux26/slug" }
    $urls = @(
        "https://github.com/$repo/releases/download/v$Version/slug-$Version-windows-x86_64.zip",
        "https://github.com/$repo/releases/download/v$Version/slug-$Version-windows-x64.zip",
        "https://github.com/$repo/releases/latest/download/slug-$Version-windows-x86_64.zip",
        "https://github.com/$repo/releases/latest/download/slug-$Version-windows-x64.zip"
    )
    $tempZip = Join-Path $env:TEMP "slug-$Version-windows.zip"
    $tempExtract = Join-Path $env:TEMP "slug-extract-$Version"

    $downloaded = $false
    $prevProgress = $ProgressPreference
    $ProgressPreference = 'SilentlyContinue'
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    } catch {}

    foreach ($url in $urls) {
        try {
            Write-Info "Attempting download from: $url"
            Invoke-WebRequest -Uri $url -OutFile $tempZip -UseBasicParsing -TimeoutSec 30
            if (Test-Path $tempExtract) { Remove-Item -Recurse -Force $tempExtract }
            Expand-Archive -Path $tempZip -DestinationPath $tempExtract -Force
            $found = Get-ChildItem -Path $tempExtract -Filter "slug.exe" -Recurse | Select-Object -ExpandProperty FullName -First 1
            if ($found -and (Test-Path $found)) {
                $sourceExe = $found
                $downloaded = $true
                break
            }
        } catch {
            continue
        }
    }
    $ProgressPreference = $prevProgress

    if (-not $downloaded) {
        Write-Warn "Automated download failed or release not yet uploaded."
        Write-Info "You can download slug.exe directly from: https://github.com/$repo/releases/tag/v$Version"
        return
    }
}

if (-not (Test-Path $sourceExe)) {
    Write-Err "Source executable not found at: $sourceExe"
    return
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
    Write-Host "  slug (or slug portal)  # Launch local loopback Web Viewing Engine"
    Write-Host "  slug add C:\path\to\folder -p 9443 -s 3 --ttl 2h"
    Write-Host "  slug connect -i 192.168.1.50 -p 9443 -o <TOTP>"
    Write-Host "  slug pull .\backup -i 192.168.1.50 -p 9443 -o <TOTP>"
    Write-Host "  slug shortcut          # Recreate Desktop shortcut"
    Write-Host "  slug help"
} catch {
    Write-Err "Verification failed: $($_.Exception.Message)"
    return
}

# 5. Create Desktop Shortcut for Web Viewing Portal
try {
    $desktopPath = [Environment]::GetFolderPath('Desktop')
    if (Test-Path $desktopPath) {
        $shortcutFile = Join-Path $desktopPath "Slug Workspace.lnk"
        $wscriptShell = New-Object -ComObject WScript.Shell
        $shortcut = $wscriptShell.CreateShortcut($shortcutFile)
        $shortcut.TargetPath = $targetExe
        $shortcut.Arguments = "portal"
        $shortcut.Description = "Slug Post-Quantum Workspace Viewing Engine"
        $shortcut.IconLocation = "$targetExe,0"
        $shortcut.Save()
        Write-Success "Created Desktop Shortcut: $shortcutFile"
    }
} catch {
    Write-Warn "Could not create Desktop shortcut automatically: $($_.Exception.Message)"
}

