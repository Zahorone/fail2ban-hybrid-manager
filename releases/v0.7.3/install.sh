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

# Voliteľná inštalácia jail.local
read -p "🔒  Chceš nainštalovať jail.local z repozitára? (y/n): " JAIL
if [[ "$JAIL" =~ ^[Yy]$ ]]; then
    curl -s "$REPO/jail.local" > /tmp/jail.local
    sudo mv /tmp/jail.local /etc/fail2ban/jail.local
    echo "✅ jail.local nainštalovaný"
fi

# Voliteľný NFTables setup
read -p "💡  Chceš spustiť ULTIMATE NFT setup tool? (y/n): " NFT
if [[ "$NFT" =~ ^[Yy]$ ]]; then
    curl -s "$REPO/fail2ban_hybrid-ULTIMATE-setup-v0.7.3.sh" > /tmp/f2b-setup.sh
    chmod +x /tmp/f2b-setup.sh
    sudo bash /tmp/f2b-setup.sh
    echo "✅ NFT setup dokončený"
fi

source ~/.bashrc
echo "🎉 Installation complete!"

