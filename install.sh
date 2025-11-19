#!/bin/bash
set -e

REPO="https://raw.githubusercontent.com/Zahorone/fail2ban-hybrid-manager/main"
INSTALL_PATH="/usr/local/bin/f2b"
VERSION_URL="$REPO/VERSION"

echo "📥 Downloading fail2ban-hybrid-manager..."

# Stiahni verziu
LATEST=$(curl -s "$VERSION_URL")
echo "✅ Version: $LATEST"

# Stiahni main script
curl -s "$REPO/fail2ban_hybrid-v0.7.3-COMPLETE.sh" > "$INSTALL_PATH"
chmod +x "$INSTALL_PATH"

# Aliases do bashrc (pridá len ak ešte nie je!)
grep -qxF "source /usr/local/bin/f2b" ~/.bashrc || echo "source /usr/local/bin/f2b" >> ~/.bashrc

source ~/.bashrc
echo "✅ Installation complete!"

