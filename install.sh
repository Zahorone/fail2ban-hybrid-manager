#!/bin/bash
set -e

REPO="https://raw.githubusercontent.com/Zahorone/fail2ban-hybrid-manager/main"
INSTALL_PATH="/usr/local/bin/f2b"
VERSION_URL="$REPO/VERSION"
SCRIPT="fail2ban_hybrid-v0.7.3-COMPLETE.sh"

echo "📥 Downloading fail2ban-hybrid-manager..."

# Stiahni verziu
LATEST=$(curl -s "$VERSION_URL")
echo "✅ Version: $LATEST"

# Stiahni main script
curl -s "$REPO/$SCRIPT" > "$INSTALL_PATH"
chmod +x "$INSTALL_PATH"

# Pridaj alias do .bashrc, ak nie je
grep -qxF "source /usr/local/bin/f2b" ~/.bashrc || echo "source /usr/local/bin/f2b" >> ~/.bashrc

echo "✅ Hybridný tool nainštalovaný!"

# Voliteľná auto-inštalácia filtrov
read -p "🛡️  Chceš nainštalovať aj všetky custom Fail2Ban filtre na tento server? (y/n): " ANS
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
    echo "📦 Inštalujem custom filtre do $TARGET..."
    for filter in "${FILTERS[@]}"; do
        curl -sSLO "$REPO/filters/$filter"
        sudo mv "$filter" "$TARGET/$filter"
        echo "✅ $filter → $TARGET"
    done
fi

source ~/.bashrc
echo "🎉 Installation complete!"

