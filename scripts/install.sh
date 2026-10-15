#!/usr/bin/env bash
# ==============================================================================
# Slug Universal Installer for Linux & POSIX Systems
# Project: Slug (P2P Secure Workspace Sharing & Synchronization)
# License: Apache-2.0
# ==============================================================================

set -euo pipefail

REPO="${SLUG_REPO:-dotlinux26/slug}"
VERSION="1.0.0-rc1"

print_info() {
    echo "[*] $1"
}

print_success() {
    echo "[+] $1"
}

print_warn() {
    echo "[!] $1"
}

print_error() {
    echo "[-] $1" >&2
}

# 1. Check OS and Architecture
OS="$(uname -s)"
ARCH="$(uname -m)"

if [ "$OS" != "Linux" ]; then
    print_error "This installer supports Linux. Detected OS: $OS"
    exit 1
fi

case "$ARCH" in
    x86_64|amd64)
        SLUG_ARCH="x86_64"
        ;;
    aarch64|arm64)
        SLUG_ARCH="aarch64"
        ;;
    *)
        print_warn "Architecture $ARCH might need to be built from source."
        SLUG_ARCH="$ARCH"
        ;;
esac

print_info "Slug Universal Installer v$VERSION"
print_info "Detected Platform: $OS ($SLUG_ARCH)"

# 2. Determine source binary
SOURCE_BIN=""
SCRIPT_DIR=""
ROOT_DIR=""

if [ -n "${BASH_SOURCE[0]:-}" ]; then
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd || echo "")"
fi

if [ -n "$SCRIPT_DIR" ]; then
    ROOT_DIR="$(cd "$SCRIPT_DIR/.." 2>/dev/null && pwd || echo "")"
    if [ -f "$SCRIPT_DIR/slug" ]; then
        SOURCE_BIN="$SCRIPT_DIR/slug"
    fi
fi

if [ -z "$SOURCE_BIN" ] && [ -f "./slug" ]; then
    SOURCE_BIN="./slug"
elif [ -z "$SOURCE_BIN" ] && [ -n "$ROOT_DIR" ] && [ -f "$ROOT_DIR/bin/slug-static" ]; then
    SOURCE_BIN="$ROOT_DIR/bin/slug-static"
elif [ -z "$SOURCE_BIN" ] && [ -n "$ROOT_DIR" ] && [ -f "$ROOT_DIR/bin/slug" ]; then
    SOURCE_BIN="$ROOT_DIR/bin/slug"
fi

TMP_DIR=""
cleanup() {
    if [ -n "$TMP_DIR" ] && [ -d "$TMP_DIR" ]; then
        rm -rf "$TMP_DIR"
    fi
}
trap cleanup EXIT

if [ -z "$SOURCE_BIN" ]; then
    print_info "No local binary detected. Downloading latest release from GitHub..."
    TMP_DIR="$(mktemp -d)"
    DOWNLOAD_URL="https://github.com/${REPO}/releases/download/v${VERSION}/slug-${VERSION}-linux-${SLUG_ARCH}.tar.gz"
    
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$DOWNLOAD_URL" -o "$TMP_DIR/slug.tar.gz" || true
    elif command -v wget >/dev/null 2>&1; then
        wget -q "$DOWNLOAD_URL" -O "$TMP_DIR/slug.tar.gz" || true
    else
        print_error "Neither curl nor wget found. Please install curl or build from source."
        exit 1
    fi

    if [ -f "$TMP_DIR/slug.tar.gz" ] && [ -s "$TMP_DIR/slug.tar.gz" ]; then
        tar -xzf "$TMP_DIR/slug.tar.gz" -C "$TMP_DIR" --strip-components=1 2>/dev/null || tar -xzf "$TMP_DIR/slug.tar.gz" -C "$TMP_DIR"
        if [ -f "$TMP_DIR/slug" ]; then
            SOURCE_BIN="$TMP_DIR/slug"
        elif [ -f "$TMP_DIR/slug-${VERSION}-linux-${SLUG_ARCH}/slug" ]; then
            SOURCE_BIN="$TMP_DIR/slug-${VERSION}-linux-${SLUG_ARCH}/slug"
        fi
    else
        print_warn "Release binary not yet published or download failed."
        print_info "Attempting local compilation..."
        if [ -n "$ROOT_DIR" ] && [ -f "$ROOT_DIR/Makefile" ]; then
            make -C "$ROOT_DIR" static -j"$(nproc 2>/dev/null || echo 2)"
            SOURCE_BIN="$ROOT_DIR/bin/slug-static"
        else
            print_error "Cannot compile: Makefile not found."
            exit 1
        fi
    fi
fi

if [ ! -f "$SOURCE_BIN" ]; then
    print_error "Source binary does not exist at: $SOURCE_BIN"
    exit 1
fi

# 3. Determine Installation Target
INSTALL_DIR="/usr/local/bin"
USE_SUDO=0

if [ "$(id -u)" -eq 0 ]; then
    INSTALL_DIR="/usr/local/bin"
elif command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
    INSTALL_DIR="/usr/local/bin"
    USE_SUDO=1
elif [ -w "/usr/local/bin" ]; then
    INSTALL_DIR="/usr/local/bin"
else
    INSTALL_DIR="$HOME/.local/bin"
    mkdir -p "$INSTALL_DIR"
fi

TARGET_BIN="$INSTALL_DIR/slug"
print_info "Installing Slug to: $TARGET_BIN"

if [ "$USE_SUDO" -eq 1 ]; then
    sudo install -m 0755 "$SOURCE_BIN" "$TARGET_BIN"
else
    install -m 0755 "$SOURCE_BIN" "$TARGET_BIN"
fi

# 4. Install Bash Completion if available
COMPLETION_SRC=""
if [ -n "$TMP_DIR" ] && [ -f "$TMP_DIR/scripts/slug.bash" ]; then
    COMPLETION_SRC="$TMP_DIR/scripts/slug.bash"
elif [ -n "$SCRIPT_DIR" ] && [ -f "$SCRIPT_DIR/slug.bash" ]; then
    COMPLETION_SRC="$SCRIPT_DIR/slug.bash"
elif [ -n "$ROOT_DIR" ] && [ -f "$ROOT_DIR/scripts/slug.bash" ]; then
    COMPLETION_SRC="$ROOT_DIR/scripts/slug.bash"
fi

if [ -n "$COMPLETION_SRC" ]; then
    if [ "$USE_SUDO" -eq 1 ] || [ "$(id -u)" -eq 0 ]; then
        if [ -d "/etc/bash_completion.d" ]; then
            if [ "$USE_SUDO" -eq 1 ]; then
                sudo cp "$COMPLETION_SRC" /etc/bash_completion.d/slug
            else
                cp "$COMPLETION_SRC" /etc/bash_completion.d/slug
            fi
            print_info "Installed shell completion to /etc/bash_completion.d/slug"
        elif [ -d "/usr/share/bash-completion/completions" ]; then
            if [ "$USE_SUDO" -eq 1 ]; then
                sudo cp "$COMPLETION_SRC" /usr/share/bash-completion/completions/slug
            else
                cp "$COMPLETION_SRC" /usr/share/bash-completion/completions/slug
            fi
            print_info "Installed shell completion to /usr/share/bash-completion/completions/slug"
        fi
    else
        USER_COMP_DIR="$HOME/.bash_completion.d"
        mkdir -p "$USER_COMP_DIR"
        cp "$COMPLETION_SRC" "$USER_COMP_DIR/slug"
        print_info "Installed user shell completion to $USER_COMP_DIR/slug"
    fi
fi

# 5. Check PATH environment
case ":$PATH:" in
    *":$INSTALL_DIR:"*) ;;
    *)
        print_warn "$INSTALL_DIR is not currently in your PATH."
        print_warn "Add the following line to your ~/.bashrc or ~/.zshrc:"
        echo "    export PATH=\"$INSTALL_DIR:\$PATH\""
        ;;
esac

# 6. Verify Installation
print_info "Verifying installed executable..."
if command -v slug >/dev/null 2>&1 || [ -x "$TARGET_BIN" ]; then
    "$TARGET_BIN" version
    print_success "Slug installed successfully to $TARGET_BIN"
    echo ""
    echo "Quickstart Examples:"
    echo "  Host folder:   slug add ./my_project -p 9443 -s 3 --ttl 2h"
    echo "  Connect client:slug connect -i <host_ip> -p 9443 -o <totp_code>"
    echo "  Pull files:    slug pull ./backup -i <host_ip> -p 9443 -o <totp_code>"
    echo "  Run benchmark: slug bench --quick"
    echo "  View docs:     slug help"
else
    print_error "Verification failed: cannot execute $TARGET_BIN"
    exit 1
fi
