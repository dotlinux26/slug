param (
    [string]$Version = "1.0.0",
    [string]$Arch = "x86_64"
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Resolve-Path "$PSScriptRoot\.."
Set-Location $ProjectRoot

$DistDir = Join-Path $ProjectRoot "dist"
$PkgName = "slug-$Version-windows-$Arch"
$TargetDir = Join-Path $DistDir $PkgName
$ZipPath = Join-Path $DistDir "$PkgName.zip"
$ZipCompatPath = Join-Path $DistDir "slug-$Version-windows-x64.zip"

Write-Host "[*] Packaging Slug Windows Distribution ($PkgName)..." -ForegroundColor Cyan

# 1. Locate slug.exe
$SourceExe = $null
$Candidates = @(
    "$ProjectRoot\bin\Release\slug.exe",
    "$ProjectRoot\bin\slug.exe",
    "$ProjectRoot\build\Release\slug.exe",
    "$ProjectRoot\build_win\Release\slug.exe",
    "$ProjectRoot\build\slug.exe",
    "$ProjectRoot\build_win\slug.exe"
)

foreach ($c in $Candidates) {
    if (Test-Path $c) {
        $SourceExe = $c
        break
    }
}

if (-not $SourceExe) {
    Write-Host "[-] Error: slug.exe was not found. Please build it first." -ForegroundColor Red
    exit 1
}

# 2. Prepare distribution directory
if (-not (Test-Path $DistDir)) {
    New-Item -ItemType Directory -Path $DistDir -Force | Out-Null
}
if (Test-Path $TargetDir) { Remove-Item -Recurse -Force $TargetDir }
if (Test-Path $ZipPath) { Remove-Item -Force $ZipPath }
if (Test-Path $ZipCompatPath) { Remove-Item -Force $ZipCompatPath }

New-Item -ItemType Directory -Path "$TargetDir\scripts" -Force | Out-Null

# 3. Copy files to package folder
Copy-Item -Path $SourceExe -Destination "$TargetDir\slug.exe" -Force
Copy-Item -Path "$ProjectRoot\scripts\install.ps1" -Destination "$TargetDir\install.ps1" -Force
Copy-Item -Path "$ProjectRoot\README.md" -Destination "$TargetDir\README.md" -Force
Copy-Item -Path "$ProjectRoot\LICENSE" -Destination "$TargetDir\LICENSE" -Force
if (Test-Path "$ProjectRoot\TUTORIAL.md") {
    Copy-Item -Path "$ProjectRoot\TUTORIAL.md" -Destination "$TargetDir\TUTORIAL.md" -Force
}
# Bundle icon file for use by install.ps1 (fallback when .exe doesn't embed icon)
$IconSrc = "$ProjectRoot\assets\slug-icon.ico"
if (Test-Path $IconSrc) {
    Copy-Item -Path $IconSrc -Destination "$TargetDir\slug-icon.ico" -Force
    Write-Host "[*] Bundled slug-icon.ico into package." -ForegroundColor Cyan
}

# 4. Create ZIP
Compress-Archive -Path "$TargetDir\*" -DestinationPath $ZipPath -Force
Copy-Item -Path $ZipPath -Destination $ZipCompatPath -Force

# 5. Copy standalone binaries and helper to dist root
Copy-Item -Path $SourceExe -Destination "$DistDir\slug-windows-x86_64.exe" -Force
Copy-Item -Path $SourceExe -Destination "$DistDir\slug.exe" -Force
Copy-Item -Path "$ProjectRoot\scripts\install.ps1" -Destination "$DistDir\install.ps1" -Force
if (Test-Path $IconSrc) {
    Copy-Item -Path $IconSrc -Destination "$DistDir\slug-icon.ico" -Force
}

# 6. Generate SHA256 checksums
Set-Location $DistDir
$releaseFiles = @(
    "$PkgName.zip",
    "slug-$Version-windows-x64.zip",
    "slug-windows-x86_64.exe",
    "slug.exe",
    "install.ps1",
    "slug-icon.ico"
)
$hashes = foreach ($f in $releaseFiles) {
    if (Test-Path $f) {
        $h = (Get-FileHash -Algorithm SHA256 $f).Hash.ToLower()
        "$h  $f"
    }
}
$hashes | Out-File -Encoding utf8 SHA256SUMS.windows

Set-Location $ProjectRoot

Write-Host ""
Write-Host "====================================================================" -ForegroundColor Green
Write-Host "[+] SUCCESS: Windows Release Package Created in $DistDir" -ForegroundColor Green
Write-Host "====================================================================" -ForegroundColor Green
Get-ChildItem $DistDir
Write-Host ""
Get-Content "$DistDir\SHA256SUMS.windows"
