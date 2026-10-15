#!/usr/bin/env bash
# ==============================================================================
# Script to create universal Linux distribution tarball
# ==============================================================================

set -euo pipefail

VERSION="1.0.0-rc2"
ARCH="x86_64"
DIST_DIR="dist"
PKG_NAME="slug-${VERSION}-linux-${ARCH}"
TARGET_DIR="${DIST_DIR}/${PKG_NAME}"

echo "[*] Packaging Slug Linux Distribution..."

# 1. Compile static binary
make static -j"$(nproc 2>/dev/null || echo 2)"

if [ ! -f "bin/slug-static" ]; then
    echo "[-] Error: bin/slug-static was not built."
    exit 1
fi

# 2. Prepare distribution directory
rm -rf "$TARGET_DIR" "${DIST_DIR}/${PKG_NAME}.tar.gz"
mkdir -p "$TARGET_DIR/scripts"

# 3. Copy static binary and strip debug symbols
cp bin/slug-static "$TARGET_DIR/slug"
strip --strip-all "$TARGET_DIR/slug" || true
chmod 0755 "$TARGET_DIR/slug"

# 4. Copy auxiliary files
cp scripts/install.sh "$TARGET_DIR/install.sh"
chmod 0755 "$TARGET_DIR/install.sh"
cp scripts/slug.bash "$TARGET_DIR/scripts/slug.bash"
cp README.md "$TARGET_DIR/README.md"
cp LICENSE "$TARGET_DIR/LICENSE"
[ -f "TUTORIAL.md" ] && cp TUTORIAL.md "$TARGET_DIR/TUTORIAL.md"

# 5. Create tar.gz archive
mkdir -p "$DIST_DIR"
tar -czf "${DIST_DIR}/${PKG_NAME}.tar.gz" -C "$DIST_DIR" "$PKG_NAME"

echo "[+] Universal Linux tarball created: ${DIST_DIR}/${PKG_NAME}.tar.gz"
ls -lh "${DIST_DIR}/${PKG_NAME}.tar.gz"
echo "[*] Contents:"
tar -ztvf "${DIST_DIR}/${PKG_NAME}.tar.gz"
