@echo off
rem ==============================================================================
rem Native Windows Build Script for Slug (Visual Studio 2022 / CMake / MSVC)
rem ==============================================================================

setlocal enabledelayedexpansion

echo [*] Slug Native Windows Build Setup
echo [*] Checking build dependencies...

rem 1. Check for cmake
where cmake >nul 2>&1
if %errorlevel% neq 0 (
    echo [-] Error: CMake is not installed or not in PATH.
    echo [*] Install CMake via: winget install Kitware.CMake
    exit /b 1
)

rem 2. Detect vcpkg or system OpenSSL
set CMAKE_ARGS=
if defined VCPKG_ROOT (
    if exist "%VCPKG_ROOT%\scripts\buildsystems\vcpkg.cmake" (
        echo [*] Using vcpkg toolchain from %VCPKG_ROOT%
        set "CMAKE_ARGS=-DCMAKE_TOOLCHAIN_FILE=%VCPKG_ROOT%\scripts\buildsystems\vcpkg.cmake"
    )
)

rem 3. Configure CMake with MSVC C++20 Release
echo [*] Configuring build with CMake...
cmake -B build -S . %CMAKE_ARGS% -DCMAKE_BUILD_TYPE=Release
if %errorlevel% neq 0 (
    echo [-] CMake configuration failed.
    echo [*] Ensure OpenSSL is installed via vcpkg or Chocolatey:
    echo     vcpkg install openssl:x64-windows-static
    exit /b 1
)

rem 4. Build Release binary
echo [*] Compiling Slug for Windows (Release)...
cmake --build build --config Release -j %NUMBER_OF_PROCESSORS%
if %errorlevel% neq 0 (
    echo [-] Build failed.
    exit /b 1
)

rem 5. Copy output
if not exist bin mkdir bin
if exist build\Release\slug.exe (
    copy /y build\Release\slug.exe bin\slug.exe >nul
    echo [+] Successfully compiled: bin\slug.exe
    bin\slug.exe version
) else if exist build\slug.exe (
    copy /y build\slug.exe bin\slug.exe >nul
    echo [+] Successfully compiled: bin\slug.exe
    bin\slug.exe version
)

echo.
echo [*] Run 'powershell -ExecutionPolicy Bypass -File scripts\install.ps1' to install slug.exe to your PATH.
endlocal
