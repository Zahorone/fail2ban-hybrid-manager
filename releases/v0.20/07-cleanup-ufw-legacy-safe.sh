#!/bin/bash
set -e

echo "=== PREVIEW: IP ktoré BUDÚ vymazané ==="
sudo ufw status | grep "Fail2Ban" | awk '{print $4}' | sort -u

echo ""
COUNT=$(sudo ufw status | grep -c "Fail2Ban" || echo 0)
echo "Total rules to remove: $COUNT"

echo ""
echo "=== TVOJE pravidlá (OSTANÚ nedotknuté) ==="
sudo ufw status numbered | grep -vE "Fail2Ban|^\s*$" | head -25

echo ""
read -p "Continue with removal? [yes/no]: " -r
[[ ! $REPLY =~ ^[Yy]es$ ]] && exit 0

echo "Removing..."
BANNED_IPS=$(sudo ufw status | grep "Fail2Ban" | awk '{print $4}' | sort -u)
for ip in $BANNED_IPS; do
    sudo ufw delete deny from "$ip" 2>/dev/null || true
    echo "  ✓ Removed $ip"
done

sudo ufw reload
echo "✅ Done!"
