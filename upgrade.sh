#!/bin/bash
set -e

REPO="https://raw.githubusercontent.com/Zahorone/fail2ban-hybrid-manager/main"
INSTALL_PATH="/usr/local/bin/f2b"
VERSION_FILE="/usr/local/bin/f2b.version"
SCRIPT="fail2ban_hybrid-v0.7.3-COMPLETE.sh"

# Aktuálna verzia
CURRENT=$([[ -f "$VERSION_FILE" ]] && cat "$VERSION_FILE" || echo "0.0")

# Najnovšia verzia
LATEST=$(curl -s "$REPO/VERSION")

echo "🔍 Current version: $CURRENT"
echo "🔍 Latest version: $LATEST"

if [ "$CURRENT" = "$LATEST" ]; then
    echo "✅ Already up-to-date!"
else
    echo "📥 Upgrading to $LATEST..."

    # Backup starý
    cp "$INSTALL_PATH" "$INSTALL_PATH.backup"

    # Stiahni nový
    curl -s "$REPO/$SCRIPT" > "$INSTALL_PATH"
    chmod +x "$INSTALL_PATH"

    # Ulož verziu
    echo "$LATEST" > "$VERSION_FILE"

    echo "✅ Upgraded from $CURRENT to $LATEST"
fi

echo ""
# Voliteľná synchronizácia filtrov
read -p "🛡️  Chceš aktualizovať aj všetky custom Fail2Ban filtre z GitHubu? (y/n): " ANS
if [[ "$ANS" =~ ^[Yy]$ ]]; then
    FILTERS=(
        manualblock.conf
        nginx-444.conf
        nginx-exploit-pattern.conf
        nginx-limit-req.conf
        nginx-npm-4xx.conf
        nginx-recon.conf
        npm-fasthttp.conf
        npm-iot-exploit.conf
        recidive.conf
    )
    TARGET="/etc/fail2ban/filter.d"
    echo "📦 Synchronizujem custom filtre do $TARGET..."
    for filter in "${FILTERS[@]}"; do
        curl -sSLO "$REPO/filters/$filter"
        sudo mv "$filter" "$TARGET/$filter"
        echo "✅ $filter → $TARGET"
    done
fi

echo "💡 Run: source ~/.bashrc && f2b_audit"
echo "🎉 Upgrade complete!"

