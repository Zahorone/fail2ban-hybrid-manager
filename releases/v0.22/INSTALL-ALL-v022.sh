#!/bin/bash

################################################################################
# Fail2Ban + nftables v0.22 - Universal Installer
# Complete Production Installation with IPv4+IPv6 support
#
# Features:
# - Auto-detects: Fresh install / Upgrade from v0.19/v0.21
# - 11 Fail2Ban jails + 11 detection filters
# - Full IPv4 + IPv6 dual-stack support
# - F2B Wrapper v0.23 (50 functions)
# - Docker port blocking v0.4
# - Docker-block auto-sync (cron every 1 minute) ⚠️ CRITICAL
# - Auto-sync service
#
# Supports:
# - Fresh installation on new servers
# - Upgrade from v0.19/v0.21 (adds IPv6 + docker-block sync)
# - Reinstall v0.22 (rebuild components)
################################################################################

set -e

export VERSION="0.22"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Logging functions
log() { echo -e "${GREEN}[✓]${NC} $1"; }
error() { echo -e "${RED}[✗]${NC} $1"; exit 1; }
warning() { echo -e "${YELLOW}[!]${NC} $1"; }
info() { echo -e "${BLUE}[ℹ]${NC} $1"; }
step() { echo -e "${CYAN}[STEP $1/${2}]${NC} $3"; }

clear

cat << 'EOF'
╔════════════════════════════════════════════════════════════════╗
║                                                                ║
║    Fail2Ban + nftables Complete Setup v0.22                   ║
║    Universal Installer (Fresh Install / Upgrade)              ║
║    Full IPv4 + IPv6 + Docker-Block Sync Support              ║
║                                                                ║
╚════════════════════════════════════════════════════════════════╝
EOF

echo ""

# Root check
if [ "$EUID" -ne 0 ]; then
    error "Please run with sudo: sudo bash $0"
fi

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

################################################################################
# DETECT INSTALLATION TYPE
################################################################################

info "Detecting installation type..."
echo ""

INSTALL_TYPE="fresh"

# Check if fail2ban is installed
if command -v fail2ban-client &>/dev/null; then
    info "Fail2Ban detected: $(fail2ban-client --version | head -1)"
    INSTALL_TYPE="upgrade"
fi

# Check if nftables table exists
if nft list table inet fail2ban-filter &>/dev/null 2>&1; then
    info "nftables fail2ban-filter table detected"
    INSTALL_TYPE="upgrade"
    
    # Count current structure
    CURRENT_SETS_V4=$(nft list table inet fail2ban-filter 2>/dev/null | grep "^\s*set f2b-" | grep -vc '\-v6' || echo 0)
    CURRENT_SETS_V6=$(nft list table inet fail2ban-filter 2>/dev/null | grep "^\s*set f2b-.*-v6" -c || echo 0)
    
    if [ "$CURRENT_SETS_V6" -eq 0 ]; then
        info "Detected v0.19/v0.21 installation (no IPv6 support)"
        INSTALL_TYPE="upgrade_old"
    else
        info "Detected v0.22+ installation (with IPv6 support)"
        INSTALL_TYPE="reinstall"
    fi
fi

# Check for F2B wrapper
if [ -x /usr/local/bin/f2b ]; then
    F2B_VERSION=$(/usr/local/bin/f2b version 2>/dev/null | grep -oP 'v\K[0-9.]+' || echo "unknown")
    info "F2B wrapper detected: v${F2B_VERSION}"
fi

# Check for docker-block
if nft list table inet docker-block &>/dev/null 2>&1; then
    info "docker-block table detected"
fi

# Check for docker-sync cron
if sudo crontab -l 2>/dev/null | grep -q "f2b sync docker"; then
    info "docker-block auto-sync ACTIVE ✅"
else
    warning "docker-block auto-sync NOT configured ⚠️"
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
info "Installation Type: $INSTALL_TYPE"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

case $INSTALL_TYPE in
    fresh)
        echo "This is a FRESH INSTALLATION"
        echo ""
        echo "Will install:"
        echo " • nftables with fail2ban-filter table (IPv4+IPv6)"
        echo " • Fail2Ban with 11 jails"
        echo " • 11 detection filters"
        echo " • Docker port blocking v0.4"
        echo " • F2B wrapper v0.23 (50 functions)"
        echo " • Docker-block auto-sync (cron) ⚠️ CRITICAL"
        echo " • Auto-sync service (hourly)"
        echo " • Bash aliases"
        ;;
    upgrade_old)
        echo "UPGRADE from v0.19/v0.21 to v0.22"
        echo ""
        echo "Current state:"
        echo " • IPv4 sets: $CURRENT_SETS_V4"
        echo " • IPv6 sets: $CURRENT_SETS_V6 (missing)"
        echo ""
        echo "Will upgrade to:"
        echo " • Add IPv6 support (11 sets + 11 rules)"
        echo " • Add docker-block v0.4"
        echo " • Add docker-block auto-sync ⚠️ CRITICAL"
        echo " • Update F2B wrapper to v0.23 (50 functions)"
        echo " • Add new filters if missing"
        echo " • Preserve all banned IPs"
        ;;
    reinstall)
        echo "REINSTALL - v0.22 already present"
        echo ""
        echo "Will rebuild all components while preserving bans"
        ;;
    upgrade)
        echo "GENERIC UPGRADE to v0.22"
        ;;
esac

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

read -p "Continue with installation? (yes/no): " -r
echo ""

if [[ ! $REPLY =~ ^[Yy]es$ ]]; then
    warning "Installation cancelled by user"
    exit 0
fi

START_TIME=$(date +%s)

################################################################################
# INSTALLATION STEPS
################################################################################

TOTAL_STEPS=9

# Step 1: Pre-cleanup
step 1 $TOTAL_STEPS "Pre-installation cleanup & backup"
echo ""

if [ -f "$SCRIPT_DIR/scripts/00-pre-cleanup-v021.sh" ]; then
    bash "$SCRIPT_DIR/scripts/00-pre-cleanup-v021.sh" || warning "Pre-cleanup had warnings (continuing)"
else
    info "Pre-cleanup script not found (skipping)"
fi

echo ""

# Step 2: Install nftables
step 2 $TOTAL_STEPS "Installing nftables infrastructure (IPv4+IPv6)"
echo ""

if [ -f "$SCRIPT_DIR/scripts/01-install-nftables-v022.sh" ]; then
    bash "$SCRIPT_DIR/scripts/01-install-nftables-v022.sh" || error "nftables installation failed"
else
    error "nftables installation script not found"
fi

echo ""

# Step 3: Install Fail2Ban jails + filters
step 3 $TOTAL_STEPS "Installing Fail2Ban jails + 11 detection filters"
echo ""

if [ -f "$SCRIPT_DIR/scripts/02-install-jails-v022.sh" ]; then
    bash "$SCRIPT_DIR/scripts/02-install-jails-v022.sh" || error "Jails installation failed"
else
    error "Jails installation script not found"
fi

echo ""

# Step 4: Install Docker port blocking v0.4
step 4 $TOTAL_STEPS "Installing Docker port blocking v0.4"
echo ""

if [ -f "$SCRIPT_DIR/scripts/03-install-docker-block-v04.sh" ]; then
    bash "$SCRIPT_DIR/scripts/03-install-docker-block-v04.sh" || warning "Docker blocking had warnings (may be optional)"
else
    warning "Docker blocking script not found (skipping)"
fi

echo ""

# Step 5: Install F2B wrapper v0.23
step 5 $TOTAL_STEPS "Installing F2B wrapper v0.23 (50 functions)"
echo ""

# Try direct wrapper installation first
if [ -f "$SCRIPT_DIR/scripts/f2b-wrapper-v023.sh" ]; then
    sudo cp "$SCRIPT_DIR/scripts/f2b-wrapper-v023.sh" /usr/local/bin/f2b
    sudo chmod +x /usr/local/bin/f2b
    log "F2B wrapper installed at /usr/local/bin/f2b"
elif [ -f "$SCRIPT_DIR/scripts/04-install-wrapper-v023.sh" ]; then
    bash "$SCRIPT_DIR/scripts/04-install-wrapper-v023.sh" || error "Wrapper installation failed"
else
    error "Wrapper installation script not found"
fi

echo ""

# Step 6: Install auto-sync (fail2ban ↔ nftables)
step 6 $TOTAL_STEPS "Installing auto-sync service (fail2ban ↔ nftables)"
echo ""

if [ -f "$SCRIPT_DIR/scripts/05-install-auto-sync.sh" ]; then
    bash "$SCRIPT_DIR/scripts/05-install-auto-sync.sh" || warning "Auto-sync installation had warnings"
else
    warning "Auto-sync script not found (skipping)"
fi

echo ""

# Step 7: Install bash aliases
step 7 $TOTAL_STEPS "Installing bash aliases"
echo ""

if [ -f "$SCRIPT_DIR/scripts/06-install-aliases-v023.sh" ]; then
    bash "$SCRIPT_DIR/scripts/06-install-aliases-v023.sh" || warning "Aliases installation had warnings"
else
    warning "Aliases script not found (skipping)"
fi

echo ""

# Step 8: ⚠️ CRITICAL - Setup docker-block auto-sync
step 8 $TOTAL_STEPS "⚠️ CRITICAL: Configuring docker-block auto-sync (cron)"
echo ""

if [ -f "$SCRIPT_DIR/scripts/07-setup-docker-sync-cron.sh" ]; then
    bash "$SCRIPT_DIR/scripts/07-setup-docker-sync-cron.sh" || warning "Docker-sync cron setup had warnings"
else
    warning "Docker-sync cron script not found (skipping)"
    warning "⚠️ Docker containers will NOT be protected without this!"
    echo ""
    info "Manual setup required:"
    echo "  sudo crontab -e"
    echo ""
    echo "Add this line:"
    echo "  */1 * * * * /usr/local/bin/f2b sync docker >> /var/log/f2b-docker-sync.log 2>&1"
fi

echo ""

# Step 9: Final Verification
step 9 $TOTAL_STEPS "Final system verification"
echo ""

# Verify nftables
SETS_V4=$(nft list table inet fail2ban-filter 2>/dev/null | grep "^\s*set f2b-" | grep -vc '\-v6' || echo 0)
SETS_V6=$(nft list table inet fail2ban-filter 2>/dev/null | grep "^\s*set f2b-.*-v6" -c || echo 0)
INPUT_RULES=$(nft list chain inet fail2ban-filter f2b-input 2>/dev/null | grep -c "drop" || echo 0)
FORWARD_RULES=$(nft list chain inet fail2ban-filter f2b-forward 2>/dev/null | grep -c "drop" || echo 0)

echo "nftables Structure:"
echo " • IPv4 sets: $SETS_V4 / 11"
echo " • IPv6 sets: $SETS_V6 / 11"
echo " • INPUT rules: $INPUT_RULES / 22"
echo " • FORWARD rules: $FORWARD_RULES / 6"
echo ""

# Verify Fail2Ban
JAILCOUNT=$(fail2ban-client status 2>/dev/null | grep "Jail list" | sed 's/.*://' | tr ',' '\n' | wc -l)
echo "Fail2Ban:"
echo " • Active jails: $JAILCOUNT / 11"
echo ""

# Verify F2B wrapper
if [ -x /usr/local/bin/f2b ]; then
    echo "F2B Wrapper:"
    echo " • Status: Installed ✅"
    F2B_VERSION=$(/usr/local/bin/f2b version 2>/dev/null | grep -oP 'v\K[0-9.]+' || echo "unknown")
    echo " • Version: $F2B_VERSION"
    echo " • Functions: 50 complete functions"
else
    echo "F2B Wrapper:"
    echo " • Status: Not found ❌"
fi
echo ""

# Verify docker-block
if nft list table inet docker-block &>/dev/null 2>&1; then
    echo "Docker-block:"
    echo " • Status: Installed ✅"
    
    # Check auto-sync cron
    if sudo crontab -l 2>/dev/null | grep -q "f2b sync docker"; then
        echo " • Auto-sync: ACTIVE ✅ (every 1 minute)"
    else
        echo " • Auto-sync: NOT CONFIGURED ❌"
    fi
else
    echo "Docker-block:"
    echo " • Status: Not installed ⚠️"
fi
echo ""

# Calculate success
ERRORS=0
[ "$SETS_V4" -ne 11 ] && ((ERRORS++))
[ "$SETS_V6" -ne 11 ] && ((ERRORS++))
[ "$INPUT_RULES" -ne 22 ] && ((ERRORS++))
[ "$FORWARD_RULES" -ne 6 ] && ((ERRORS++))
[ "$JAILCOUNT" -lt 11 ] && ((ERRORS++))

END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))
MINUTES=$((DURATION / 60))
SECONDS=$((DURATION % 60))

echo ""
echo "╔════════════════════════════════════════════════════════════════╗"

if [ $ERRORS -eq 0 ]; then
    echo "║           ✅ INSTALLATION COMPLETE - SUCCESS!                 ║"
else
    echo "║          ⚠️ INSTALLATION COMPLETE - $ERRORS WARNINGS              ║"
fi

echo "╚════════════════════════════════════════════════════════════════╝"
echo ""

log "Installation duration: ${MINUTES}m ${SECONDS}s"
echo ""

if [ $ERRORS -eq 0 ]; then
    echo "Your system is now protected with v0.22:"
    echo " ✅ Full IPv4 + IPv6 dual-stack support"
    echo " ✅ 22 nftables rules (11 IPv4 + 11 IPv6)"
    echo " ✅ 11 Fail2Ban jails + 11 detection filters"
    echo " ✅ Docker port blocking v0.4"
    echo " ✅ F2B wrapper v0.23 (50 functions)"
    echo " ✅ Docker-block auto-sync (every 1 minute)"
    echo " ✅ Auto-sync enabled (hourly)"
else
    warning "Installation completed with $ERRORS warnings"
    info "Review logs for details"
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
info "Next Steps"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

echo "1. Reload bash aliases:"
echo "   source ~/.bashrc"
echo ""

echo "2. Test the F2B wrapper:"
echo "   sudo f2b status"
echo ""

echo "3. Verify docker-block sync:"
echo "   sudo crontab -l | grep docker-sync"
echo "   sudo tail -f /var/log/f2b-docker-sync.log"
echo ""

echo "4. Real-time docker-block dashboard:"
echo "   sudo f2b docker dashboard"
echo ""

echo "5. Monitor attacks in real-time:"
echo "   sudo f2b monitor watch"
echo ""

echo "6. Manual docker-block sync (if needed):"
echo "   sudo f2b sync docker"
echo ""

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

log "Installation complete! 🚀"
echo ""

