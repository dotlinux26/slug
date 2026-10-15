# ==============================================================================
# Slug - Windows PowerShell Release Build Script (MSVC or MinGW)
# Builds: bin\Release\slug.exe
# ==============================================================================

Write-Host "====================================================================" -ForegroundColor Cyan
Write-Host "       Building Slug 1.0.0-rc1 Native Release for Windows (x64)     " -ForegroundColor Cyan
Write-Host "====================================================================" -ForegroundColor Cyan
Write-Host ""

$ProjectRoot = Resolve-Path "$PSScriptRoot\.."
Set-Location $ProjectRoot

# Check CMake
if (-not (Get-Command "cmake" -ErrorAction SilentlyContinue)) {
    Write-Host "[-] Error: CMake was not found in PATH." -ForegroundColor Red
    Write-Host "[*] Install CMake with: winget install Kitware.CMake" -ForegroundColor Yellow
    exit 1
}

$BuildDir = Join-Path $ProjectRoot "build_win"
if (-not (Test-Path $BuildDir)) {
    New-Item -ItemType Directory -Path $BuildDir | Out-Null
}
Set-Location $BuildDir

# Detect vcpkg toolchain if available
$VcpkgArgs = @()
$VcpkgPath = $env:VCPKG_ROOT
if (-not $VcpkgPath -and (Test-Path "C:\vcpkg")) {
    $VcpkgPath = "C:\vcpkg"
}

if ($VcpkgPath -and (Test-Path "$VcpkgPath\scripts\buildsystems\vcpkg.cmake")) {
    Write-Host "[+] Using vcpkg toolchain from $VcpkgPath" -ForegroundColor Green
    $VcpkgArgs += "-DCMAKE_TOOLCHAIN_FILE=$VcpkgPath\scripts\buildsystems\vcpkg.cmake"
    $VcpkgArgs += "-DVCPKG_TARGET_TRIPLET=x64-windows-static"
}

Write-Host "[*] Configuring CMake..." -ForegroundColor Blue
& cmake .. -DCMAKE_BUILD_TYPE=Release @VcpkgArgs
if ($LASTEXITCODE -ne 0) {
    Write-Host "[-] CMake configuration failed." -ForegroundColor Red
    Write-Host "[*] If using Visual Studio: Run 'vcpkg install openssl:x64-windows-static'" -ForegroundColor Yellow
    Write-Host "[*] If using MSYS2 / MinGW: Run 'pacman -S mingw-w64-x86_64-openssl'" -ForegroundColor Yellow
    Set-Location $ProjectRoot
    exit 1
}

Write-Host "[*] Compiling Slug Release executable..." -ForegroundColor Blue
& cmake --build . --config Release --parallel
if ($LASTEXITCODE -ne 0) {
    Write-Host "[-] Compilation failed." -ForegroundColor Red
    Set-Location $ProjectRoot
    exit 1
}

Set-Location $ProjectRoot

$BinaryPaths = @(
    Join-Path $ProjectRoot "bin\Release\slug.exe",
    Join-Path $ProjectRoot "bin\slug.exe"
)

$Found = $false
foreach ($p in $BinaryPaths) {
    if (Test-Path $p) {
        Write-Host ""
        Write-Host "====================================================================" -ForegroundColor Green
        Write-Host "[+] SUCCESS: Slug Windows binary created at: $p" -ForegroundColor Green
        Write-Host "====================================================================" -ForegroundColor Green
        & $p version
        $Found = $true
        break
    }
}

if (-not $Found) {
    Write-Host "[+] Build completed in $BuildDir" -ForegroundColor Yellow
}
