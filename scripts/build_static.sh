#!/usr/bin/env bash
# ==============================================================================
# Slug - Universal Linux 100% Static Release Build Script
# Creates a portable, zero-runtime-dependency binary: bin/slug-static
# Works on any Linux distribution (Debian, Ubuntu, Alpine, RHEL, Fedora, Arch)
# ==============================================================================

set -e

# ANSI Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

echo -e "\n${BOLD}${BLUE}====================================================================${NC}"
echo -e "${BOLD}${BLUE}       Building Slug 1.0.0-rc1 Static Release for Linux (x86_64)   ${NC}"
echo -e "${BOLD}${BLUE}====================================================================${NC}\n"

cd "$(dirname "$0")/.."
PROJECT_ROOT=$(pwd)

echo -e "${BLUE}[*] Checking build tools and dependencies...${NC}"

if ! command -v g++ >/dev/null 2>&1; then
    echo "Error: g++ (GCC C++20 compiler) is not installed."
    exit 1
fi

if ! command -v make >/dev/null 2>&1; then
    echo "Error: make is not installed."
    exit 1
fi

# Clean previous build artifacts
echo -e "${BLUE}[*] Cleaning old build artifacts...${NC}"
make clean

# Compile static binary
echo -e "${BLUE}[*] Compiling static release with $(nproc) parallel jobs...${NC}"
make static -j$(nproc)

if [ -f "bin/slug-static" ]; then
    # Strip debugging symbols to optimize binary footprint
    echo -e "${BLUE}[*] Stripping symbols to reduce binary size...${NC}"
    strip -s bin/slug-static || true

    echo -e "\n${BOLD}${GREEN}[+] SUCCESS: Universal Linux static binary created at bin/slug-static${NC}"
    ls -lh bin/slug-static
    file bin/slug-static

    echo -e "\n${YELLOW}[*] Testing static binary version output:${NC}"
    ./bin/slug-static version
    echo ""
else
    echo "Error: bin/slug-static was not generated."
    exit 1
fi
