#!/bin/bash
################################################################################
# Pre-Installation Cleanup for Fail2Ban + nftables v0.20
# Safely removes old configurations before fresh install
################################################################################

set -e

echo ""
echo "╔═══════════════════════════════════════════════════════╗"
echo "║   Pre-Installation Cleanup v0.20                     ║"
echo "╚═══════════════════════════════════════════════════════╝"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "[ERROR] Please run with sudo"
    exit 1
fi

# === STEP 1: BACKUP ===
echo "🔄 Step 1: Creating backup..."
BACKUP_DIR=~/nft-backup-pre-v020-$(date +%Y%m%d-%H%M)
mkdir -p "$BACKUP_DIR"

# Backup nftables ruleset
nft list ruleset > "$BACKUP_DIR/nft-ruleset.bak" 2>/dev/null || true

# Backup fail2ban configs
if [ -d /etc/fail2ban ]; then
    cp -r /etc/fail2ban "$BACKUP_DIR/fail2ban-backup" 2>/dev/null || true
fi

# Backup nftables configs
if [ -d /etc/nftables ]; then
    cp -r /etc/nftables "$BACKUP_DIR/nftables-backup" 2>/dev/null || true
fi

# Backup nftables.d
if [ -d /etc/nftables.d ]; then
    cp -r /etc/nftables.d "$BACKUP_DIR/nftables.d-backup" 2>/dev/null || true
fi

echo "[OK] Backup saved: $BACKUP_DIR"
echo ""

# === STEP 2: STOP SERVICES ===
echo "🛑 Step 2: Stopping services..."

# Stop old docker-firewall service (if exists)
systemctl stop docker-firewall.service 2>/dev/null || true
systemctl disable docker-firewall.service 2>/dev/null || true
echo "[OK] Old docker-firewall service stopped"

# Stop auto-sync timer (if exists)
systemctl stop f2b-nft-sync.timer 2>/dev/null || true
systemctl disable f2b-nft-sync.timer 2>/dev/null || true
systemctl stop f2b-nft-sync.service 2>/dev/null || true
echo "[OK] Old sync timers stopped"

echo ""

# === STEP 3: CLEAN OLD NFT TABLES ===
echo "🧹 Step 3: Removing old nftables tables..."

# Remove old fail2ban tables
nft delete table inet fail2ban-filter 2>/dev/null && echo "[OK] Removed: inet fail2ban-filter" || echo "[SKIP] No inet fail2ban-filter table"

# Remove old docker-block tables
nft delete table inet docker-block 2>/dev/null && echo "[OK] Removed: inet docker-block" || echo "[SKIP] No inet docker-block table"

# Remove old ip filter tables (from fixdockerfw)
nft flush chain ip filter DOCKER-USER 2>/dev/null && echo "[OK] Flushed: ip filter DOCKER-USER" || true

echo ""

# === STEP 4: CLEAN OLD CONFIG FILES ===
echo "🗑️  Step 4: Removing old config files..."

# Remove old nftables configs
rm -f /etc/nftables/fail2ban-*.nft 2>/dev/null && echo "[OK] Removed old fail2ban nft files" || true
rm -f /etc/nftables/docker-block.nft 2>/dev/null && echo "[OK] Removed old docker-block.nft" || true

# Clean old includes from nftables.conf
sed -i '/fail2ban-/d' /etc/nftables.conf 2>/dev/null || true
sed -i '/docker-block/d' /etc/nftables.conf 2>/dev/null || true
echo "[OK] Cleaned nftables.conf includes"

# Remove old systemd services
rm -f /etc/systemd/system/docker-firewall.service 2>/dev/null && echo "[OK] Removed docker-firewall.service" || true
rm -f /etc/systemd/system/f2b-nft-sync.* 2>/dev/null && echo "[OK] Removed old sync services" || true

systemctl daemon-reload
echo "[OK] Systemd reloaded"

echo ""

# === STEP 5: CLEAN OLD WRAPPER & ALIASES ===
echo "🔧 Step 5: Removing old wrapper and aliases..."

# Remove old f2b wrapper
rm -f /usr/local/bin/f2b 2>/dev/null && echo "[OK] Removed old f2b wrapper" || echo "[SKIP] No old wrapper"

# Remove global aliases file
rm -f /etc/profile.d/f2b-aliases.sh 2>/dev/null && echo "[OK] Removed global f2b aliases" || true

# Clean old aliases from .bashrc
if [ -f ~/.bashrc ]; then
    sed -i '/f2b-status/d' ~/.bashrc 2>/dev/null || true
    sed -i '/f2b-audit/d' ~/.bashrc 2>/dev/null || true
    sed -i '/f2b-sync/d' ~/.bashrc 2>/dev/null || true
    sed -i '/f2b-watch/d' ~/.bashrc 2>/dev/null || true
    sed -i '/f2b-check/d' ~/.bashrc 2>/dev/null || true
    sed -i '/f2b-ban/d' ~/.bashrc 2>/dev/null || true
    sed -i '/f2b-unban/d' ~/.bashrc 2>/dev/null || true
    sed -i '/f2b-bans/d' ~/.bashrc 2>/dev/null || true
    sed -i '/f2b-top/d' ~/.bashrc 2>/dev/null || true
    sed -i '/f2b-find/d' ~/.bashrc 2>/dev/null || true
    sed -i '/f2b-trends/d' ~/.bashrc 2>/dev/null || true
    sed -i '/f2b-log/d' ~/.bashrc 2>/dev/null || true
    sed -i '/f2b-json/d' ~/.bashrc 2>/dev/null || true
    sed -i '/f2b-csv/d' ~/.bashrc 2>/dev/null || true
    sed -i '/fixdockerfw/d' ~/.bashrc 2>/dev/null || true
    echo "[OK] Cleaned old aliases from .bashrc"
fi

# Clean .bash_aliases if exists
if [ -f ~/.bash_aliases ]; then
    sed -i '/f2b-/d' ~/.bash_aliases 2>/dev/null || true
    echo "[OK] Cleaned .bash_aliases"
fi

echo ""

# === STEP 6: VERIFICATION ===
echo "📊 Step 6: Verification..."
echo ""

echo "Current NFT tables:"
nft list tables 2>/dev/null || echo "  (none)"
echo ""

echo "Systemd services:"
systemctl list-units --all | grep -E "docker-firewall|f2b-nft-sync" || echo "  (none found - good!)"
echo ""

echo "F2B wrapper:"
which f2b 2>/dev/null || echo "  (not found - good!)"
echo ""

echo "Global aliases:"
ls -lh /etc/profile.d/f2b-aliases.sh 2>/dev/null || echo "  (not found - good!)"
echo ""

# === SUMMARY ===
echo ""
echo "╔═══════════════════════════════════════════════════════╗"
echo "║   ✅ PRE-CLEANUP COMPLETE                            ║"
echo "╚═══════════════════════════════════════════════════════╝"
echo ""
echo "📁 Backup location: $BACKUP_DIR"
echo ""
echo "🚀 Ready for v0.20 installation!"
echo ""
echo "Next steps:"
echo "  1. Review backup if needed: ls -lh $BACKUP_DIR"
echo "  2. Run installer: sudo bash INSTALL-ALL-v020.sh"
echo ""
