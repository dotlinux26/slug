# Slug: Multi-Platform Build & Portability Guide

This guide provides step-by-step instructions for building **Slug** across Linux distributions, Microsoft Windows, and macOS, with a strong focus on **100% static linking** and **zero-runtime-dependency portability**.

---

## Table of Contents
1. [Core Requirements](#1-core-requirements)
2. [Universal Linux Build (100% Static Release)](#2-universal-linux-build-100-static-release)
3. [Windows Release Build](#3-windows-release-build)
   - [Option A: MSVC + vcpkg (Recommended for Visual Studio)](#option-a-msvc--vcpkg-recommended)
   - [Option B: MSYS2 / MinGW-w64](#option-b-msys2--mingw-w64)
   - [Option C: Cross-Compiling for Windows from Linux](#option-c-cross-compiling-for-windows-from-linux)
4. [macOS Build](#4-macos-build)
5. [Automated Integration Testing](#5-automated-integration-testing)
6. [Troubleshooting & FAQ](#6-troubleshooting--faq)

---

## 1. Core Requirements

- **C++ Compiler**: C++20 compliant compiler
  - Linux: GCC >= 11 or Clang >= 13
  - Windows: Visual Studio 2022 (MSVC >= 19.30) or MinGW-w64 (GCC >= 11)
  - macOS: Apple Clang >= 14 or GCC >= 11
- **Build System**: GNU Make >= 4.0 or CMake >= 3.20
- **Cryptography Library**: OpenSSL >= 3.0 (OpenSSL 3.2+ recommended for native FIPS 203 ML-KEM and FIPS 204 ML-DSA)
- **Vendored Dependencies** (included in tree, zero external download needed):
  - `third_party/blake3/`: Portable BLAKE3 implementation
  - `third_party/json/json.hpp`: nlohmann/json single-header

---

## 2. Universal Linux Build (100% Static Release)

Slug produces an 8.4 MB standalone static binary (`bin/slug-static`) that runs on **any Linux distribution** (Debian, Ubuntu, Alpine, RHEL, CentOS, Rocky Linux, Fedora, Arch Linux, Void, Gentoo, NixOS, Amazon Linux) without requiring any runtime shared libraries.

### Installing Dependencies

#### Ubuntu / Debian / Pop!_OS:
```bash
sudo apt-get update
sudo apt-get install -y build-essential cmake libssl-dev libzstd-dev zlib1g-dev
```

#### Alpine Linux (Musl libc - produces true ultra-minimal static binary):
```bash
apk add --no-cache build-base cmake openssl-dev openssl-libs-static zstd-dev zlib-dev linux-headers
```

#### RHEL / Fedora / CentOS / Rocky Linux:
```bash
sudo dnf install -y gcc-c++ make cmake openssl-devel libzstd-devel zlib-devel
```

#### Arch Linux / Manjaro:
```bash
sudo pacman -S --needed base-devel cmake openssl zstd zlib
```

### Compiling Static Release

Run the automated static build script:
```bash
./scripts/build_static.sh
```

Or invoke `make` directly:
```bash
# Compile with all CPU cores
make clean
make static -j$(nproc)

# Strip symbols to minimize size
strip -s bin/slug-static
```

### Verify Static Linking
```bash
file bin/slug-static
# Output: ELF 64-bit LSB executable, x86-64, statically linked, stripped

ldd bin/slug-static
# Output: not a dynamic executable
```

---

## 3. Windows Release Build

Slug fully supports Windows 10, Windows 11, and Windows Server (x64) with native Winsock2 asynchronous sockets, UTF-16 path conversions, and in-memory process environment isolation (`CreateProcessW`).

### Option A: MSVC + vcpkg (Recommended)

1. **Install Prerequisites**:
   - Visual Studio 2022 Community (Desktop development with C++ workload)
   - [CMake](https://cmake.org/download/) or run `winget install Kitware.CMake`
   - [vcpkg](https://vcpkg.io/):
     ```cmd
     git clone https://github.com/microsoft/vcpkg.git C:\vcpkg
     cd C:\vcpkg
     .\bootstrap-vcpkg.bat
     ```

2. **Install Static OpenSSL**:
   ```cmd
   C:\vcpkg\vcpkg install openssl:x64-windows-static
   ```

3. **Build Slug with the Automated Script**:
   From Developer Command Prompt:
   ```cmd
   .\scripts\build_windows.bat
   ```
   Or in PowerShell:
   ```powershell
   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
   .\scripts\build_windows.ps1
   ```

4. **Manual CMake Build**:
   ```cmd
   mkdir build_win && cd build_win
   cmake .. -DCMAKE_BUILD_TYPE=Release ^
            -DCMAKE_TOOLCHAIN_FILE=C:\vcpkg\scripts\buildsystems\vcpkg.cmake ^
            -DVCPKG_TARGET_TRIPLET=x64-windows-static
   cmake --build . --config Release --parallel
   ```
   The binary `slug.exe` is located at `bin\Release\slug.exe`.

---

### Option B: MSYS2 / MinGW-w64

If you prefer a GCC-based toolchain on Windows:

1. Download and install [MSYS2](https://www.msys2.org/).
2. Open **MSYS2 MINGW64** terminal and install packages:
   ```bash
   pacman -Syu
   pacman -S --needed \
       mingw-w64-x86_64-gcc \
       mingw-w64-x86_64-make \
       mingw-w64-x86_64-cmake \
       mingw-w64-x86_64-openssl \
       mingw-w64-x86_64-zstd \
       mingw-w64-x86_64-zlib
   ```
3. Build with CMake:
   ```bash
   mkdir build_mingw && cd build_mingw
   cmake .. -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release
   cmake --build . --parallel
   ```
   The binary `slug.exe` is generated in `bin/`.

---

### Option C: Cross-Compiling for Windows from Linux

You can build a Windows `slug.exe` directly on Ubuntu/Debian using the MinGW cross-compiler:

1. Install cross-toolchain:
   ```bash
   sudo apt-get install -y mingw-w64
   ```
2. Download or cross-compile OpenSSL for Windows, or use MXE (`mxe.cc`).
3. Run CMake with the MinGW toolchain:
   ```bash
   mkdir build_cross && cd build_cross
   cmake .. -DCMAKE_SYSTEM_NAME=Windows \
            -DCMAKE_C_COMPILER=x86_64-w64-mingw32-gcc \
            -DCMAKE_CXX_COMPILER=x86_64-w64-mingw32-g++
   cmake --build . --parallel
   ```

---

## 4. macOS Build

Slug supports Apple Silicon (M1/M2/M3/M4, ARM64) and Intel (x86_64).

1. Install Homebrew and OpenSSL:
   ```bash
   brew install cmake openssl@3
   ```
2. Build with CMake:
   ```bash
   mkdir build && cd build
   cmake .. -DCMAKE_BUILD_TYPE=Release \
            -DOPENSSL_ROOT_DIR=$(brew --prefix openssl@3)
   cmake --build . --parallel
   ```
   The binary `slug` will be located in `bin/`.

---

## 5. Automated Integration Testing

Slug includes a full end-to-end integration test suite (`scripts/test_local.sh`) validating:
- Version and help CLI commands
- PQC EnvShield envelope encryption and in-memory variable injection
- Ephemeral RBAC user accounts (`r`, `w`, `rw`) and password authentication
- 8-digit One-Time TOTP generation and single-use atomic burn
- Stateful AI Secret Guard heuristic scanning and content-hash caching
- Directory-scoped rules and hierarchical `.gitignore` enforcement
- Content-addressable Git-like Delta Sync (`slug pull` with dry-run and incremental updates)
- File upload (`slug push`) and write permission enforcement
- Strict path confinement preventing `../` traversal escape
- Dynamic rule addition and false-positive audit whitelist overrides
- Graceful server shutdown and workspace registry cleanup

Run the test suite on Linux:
```bash
# Test the dynamic binary
bash scripts/test_local.sh

# Or test the 100% static binary
SLUG_BIN="$PWD/bin/slug-static" bash scripts/test_local.sh
```

---

## 6. Troubleshooting & FAQ

### Q: Why does static linking require `-lzstd -lz` on Debian/Ubuntu?
**A**: When statically linking `libcrypto.a` from OpenSSL on Debian/Ubuntu, OpenSSL's internal BIO objects reference compression functions (`ZSTD_decompressStream`, `inflate`). Passing `-lzstd -lz` to the static linker resolves these internal symbols without pulling in any dynamic runtime dependencies.

### Q: Does the static binary run inside minimal Docker containers?
**A**: Yes! Because `bin/slug-static` has zero shared library dependencies, it can be copied directly into a `scratch` or `alpine` container:
```dockerfile
FROM scratch
COPY bin/slug-static /slug
ENTRYPOINT ["/slug"]
```

### Q: Which Post-Quantum algorithms are used?
**A**:
- **KEM**: `ML-KEM-768` (FIPS 203 / Kyber-768 draft standard)
- **Signature**: `ML-DSA-65` (FIPS 204 / Dilithium-3 draft standard)
- **Hash / KDF**: Portable `BLAKE3`
- **Symmetric Cipher**: `XChaCha20-Poly1305` (24-byte extended nonce)
