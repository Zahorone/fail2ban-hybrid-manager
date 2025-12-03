#!/bin/bash
set -e

VERSION="0.19"
DIST_NAME="f2b-wrapper-v${VERSION}-production-ready"

echo "Creating clean distribution: $DIST_NAME"

# Create structure
mkdir -p "$DIST_NAME"/{config/filters,docs}

# Copy WORKING scripts
echo "Copying installation scripts..."
cp INSTALL-ALL-v019.sh "$DIST_NAME/"
cp 00-pre-cleanup-v019.sh "$DIST_NAME/"
cp 01-install-nftables.sh "$DIST_NAME/"
cp 02-install-jails.sh "$DIST_NAME/"
cp 03-install-docker-block-v03.sh "$DIST_NAME/"
cp 04-install-wrapper-v019.sh "$DIST_NAME/"
cp 05-install-auto-sync.sh "$DIST_NAME/"
cp 06-install-aliases.sh "$DIST_NAME/"
cp f2b-wrapper-v019.sh "$DIST_NAME/"

# Copy config
echo "Copying configuration files..."
cp config/jail.local "$DIST_NAME/config/"
cp config/filters/*.conf "$DIST_NAME/config/filters/"

# Copy documentation
echo "Copying documentation..."
cp README-v019.md "$DIST_NAME/docs/" 2>/dev/null || true
cp F2B-QUICK-REFERENCE-v019.txt "$DIST_NAME/docs/" 2>/dev/null || true
cp PRODUCTION-SETUP-v019.md "$DIST_NAME/docs/" 2>/dev/null || true
cp FINAL-FIX-SUMMARY.md "$DIST_NAME/docs/" 2>/dev/null || true
cp DEPLOYMENT-GUIDE.md "$DIST_NAME/docs/" 2>/dev/null || true

# Create tarball
echo "Creating tarball..."
tar czf "${DIST_NAME}.tar.gz" "$DIST_NAME/"

# Checksums
sha256sum "${DIST_NAME}.tar.gz" > "${DIST_NAME}.tar.gz.sha256"

# Summary
echo ""
echo "✅ DISTRIBUTION PACKAGE CREATED"
echo ""
echo "Package: ${DIST_NAME}.tar.gz"
echo "Size: $(du -h ${DIST_NAME}.tar.gz | cut -f1)"
echo ""
echo "SHA256:"
cat "${DIST_NAME}.tar.gz.sha256"
echo ""
echo "To deploy: scp ${DIST_NAME}.tar.gz user@server:/tmp/"
echo ""

# Keep temp dir for inspection
echo "Temp directory: $DIST_NAME/ (not deleted)"
