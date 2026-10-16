#!/usr/bin/env bash
# ==============================================================================
# Script to build Debian/Ubuntu .deb package for Slug
# ==============================================================================

set -euo pipefail

VERSION="1.0.0"
ARCH="amd64"
DIST_DIR="dist"
DEB_ROOT="${DIST_DIR}/slug_${VERSION}_${ARCH}"

echo "[*] Building Debian package for Slug v${VERSION} (${ARCH})..."

# 1. Compile static binary
make static -j"$(nproc 2>/dev/null || echo 2)"

if [ ! -f "bin/slug-static" ]; then
    echo "[-] Error: bin/slug-static was not built."
    exit 1
fi

# 2. Setup directory tree
rm -rf "$DEB_ROOT"
mkdir -p "$DEB_ROOT/DEBIAN"
mkdir -p "$DEB_ROOT/usr/local/bin"
mkdir -p "$DEB_ROOT/usr/share/bash-completion/completions"
mkdir -p "$DEB_ROOT/usr/share/doc/slug"

# 3. Copy binary and strip
cp bin/slug-static "$DEB_ROOT/usr/local/bin/slug"
strip --strip-all "$DEB_ROOT/usr/local/bin/slug" || true
chmod 0755 "$DEB_ROOT/usr/local/bin/slug"

# 4. Copy completion and doc files
cp scripts/slug.bash "$DEB_ROOT/usr/share/bash-completion/completions/slug"
cp LICENSE "$DEB_ROOT/usr/share/doc/slug/copyright"
cp README.md "$DEB_ROOT/usr/share/doc/slug/README.md"
[ -f "TUTORIAL.md" ] && cp TUTORIAL.md "$DEB_ROOT/usr/share/doc/slug/TUTORIAL.md"

# 5. Create DEBIAN/control file
INSTALLED_SIZE=$(du -s "$DEB_ROOT" | cut -f1)

cat <<EOF > "$DEB_ROOT/DEBIAN/control"
Package: slug
Version: ${VERSION}
Section: utils
Priority: optional
Architecture: ${ARCH}
Installed-Size: ${INSTALLED_SIZE}
Maintainer: Slug Core Team <security@slugproject.dev>
Description: Secure, Ephemeral, Git-like Workspace Sharing and Synchronization
 Slug provides post-quantum cryptographic transport (ML-KEM-768/ML-DSA-65),
 ephemeral TOTP-gated access control, Git-like differential sync with 64 KiB
 content-addressable chunking, and stateful AI Secret Guard.
 Fully static executable with zero external runtime dependencies.
Homepage: https://github.com/dotlinux26/slug
EOF

# 6. Build .deb package
dpkg-deb --build --root-owner-group "$DEB_ROOT" "${DIST_DIR}/slug_${VERSION}_${ARCH}.deb"
rm -rf "$DEB_ROOT"

echo "[+] Debian package built: ${DIST_DIR}/slug_${VERSION}_${ARCH}.deb"
ls -lh "${DIST_DIR}/slug_${VERSION}_${ARCH}.deb"
dpkg-deb --info "${DIST_DIR}/slug_${VERSION}_${ARCH}.deb"
