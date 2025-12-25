#!/bin/bash
set -e
################################################################################
# Docker Sync Cron Setup
# Component: DOCKER-SYNC-CRON
# Part of: Fail2Ban Hybrid Nftables Manager
################################################################################

# shellcheck disable=SC2034
RELEASE="v0.31"
# shellcheck disable=SC2034
VERSION="0.31"
# shellcheck disable=SC2034
BUILD_DATE="2025-12-26"
# shellcheck disable=SC2034
COMPONENT_NAME="DOCKER-SYNC-CRON"

# Colors (some may be unused, so SC2034 is disabled per line)
# shellcheck disable=SC2034
RED='\033[0;31m'
# shellcheck disable=SC2034
GREEN='\033[0;32m'
# shellcheck disable=SC2034
YELLOW='\033[1;33m'
# shellcheck disable=SC2034
BLUE='\033[0;34m'
# shellcheck disable=SC2034
CYAN='\033[0;36m'
# shellcheck disable=SC2034
NC='\033[0m'

# Logging functions
log() { echo -e "${GREEN}[✓]${NC} $1"; }
error() { echo -e "${RED}[✗]${NC} $1"; exit 1; }
warning() { echo -e "${YELLOW}[!]${NC} $1"; }
info() { echo -e "${BLUE}[ℹ]${NC} $1"; }

echo ""
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║                                                                ║"
echo "║        Docker-Block Auto-Sync Configuration ${RELEASE}           ║"
echo "║        Critical for docker-block protection                    ║"
echo "║                                                                ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""

# Root check
if [ "$EUID" -ne 0 ]; then
    error "Please run with sudo: sudo bash $0"
fi

################################################################################
# PRE-CHECKS
################################################################################

info "Verifying prerequisites..."
echo ""

# Check if f2b wrapper exists
if [ ! -f /usr/local/bin/f2b ]; then
    error "F2B wrapper not found at /usr/local/bin/f2b"
fi

F2B_VERSION=$(/usr/local/bin/f2b version 2>/dev/null | grep -oP 'v\K[0-9.]+' || echo "unknown")
log "F2B wrapper detected: v${F2B_VERSION}"

# Check if docker-block table exists
if ! nft list table inet docker-block &>/dev/null; then
    error "docker-block table not found - install first: bash 03-install-docker-block-v031.sh"

fi

log "docker-block table found"

# Check if fail2ban is running
if ! systemctl is-active --quiet fail2ban; then
    warning "fail2ban is not running - start it first"
fi

echo ""

################################################################################
# INSTALL CRON JOB
################################################################################

info "Installing cron job for docker-block sync..."
echo ""

CRON_LINE_VALIDATE="*/1 * * * * flock -n /run/f2b-docker-validate.lock /usr/local/bin/f2b docker sync validate 2>&1 | sed -r 's/\x1B\[[0-9;]*[A-Za-z]//g' | logger -t f2b-docker-validate"
CRON_LINE_FULL="*/15 * * * * flock -n /run/f2b-docker-full.lock /usr/local/bin/f2b docker sync full 2>&1 | sed -r 's/\x1B\[[0-9;]*[A-Za-z]//g' | logger -t f2b-docker-full"

# Check if cron jobs already exist
if sudo crontab -l 2>/dev/null | grep -q "f2b docker sync"; then
    warning "Cron jobs already exist - checking if correct..."

    EXISTING_VALIDATE=$(sudo crontab -l 2>/dev/null | grep "f2b docker sync validate" || true)
    EXISTING_FULL=$(sudo crontab -l 2>/dev/null | grep "f2b docker sync full" || true)

    echo " Current validate: $EXISTING_VALIDATE"
    echo " Expected validate: $CRON_LINE_VALIDATE"
    echo ""
    echo " Current full:     $EXISTING_FULL"
    echo " Expected full:    $CRON_LINE_FULL"
    echo ""

    read -p "Update cron jobs? (yes/no): " -r
    if [[ $REPLY =~ ^[Yy]es$ ]]; then
        # Remove old and add new
        sudo crontab -l 2>/dev/null | grep -v "f2b docker sync" | sudo crontab -
        (sudo crontab -l 2>/dev/null; echo "$CRON_LINE_VALIDATE"; echo "$CRON_LINE_FULL") | sudo crontab -
        log "Cron jobs updated ✅"
    else
        info "Keeping existing cron jobs"
    fi
else
    # Add new cron jobs
    (sudo crontab -l 2>/dev/null; echo "$CRON_LINE_VALIDATE"; echo "$CRON_LINE_FULL") | sudo crontab -
    log "Cron jobs added: validate every 1 minute, full every 15 minutes ✅"
fi

echo ""

################################################################################
# CREATE LOG FILE
################################################################################

info "Setting up log file..."
echo ""

LOG_FILE="/var/log/f2b-docker-sync.log"

# Create log file if not exists
if [ ! -f "$LOG_FILE" ]; then
    sudo touch "$LOG_FILE"
    sudo chmod 644 "$LOG_FILE"
    log "Log file created: $LOG_FILE"
else
    log "Log file already exists: $LOG_FILE"
fi

# Add log rotation config
LOGROTATE_CONF="/etc/logrotate.d/f2b-docker-sync"

if [ ! -f "$LOGROTATE_CONF" ]; then
    cat <<EOF | sudo tee "$LOGROTATE_CONF" > /dev/null
/var/log/f2b-docker-sync.log {
    weekly
    rotate 4
    compress
    delaycompress
    missingok
    notifempty
    create 0644 root root
}
EOF
    log "Logrotate config created"
else
    log "Logrotate config already exists"
fi

echo ""

################################################################################
# INITIAL SYNC
################################################################################

info "Running initial sync..."
echo ""

if /usr/local/bin/f2b sync docker; then
    log "Initial sync completed successfully ✅"
else
    warning "Initial sync had issues - check manually"
fi

echo ""

################################################################################
# VERIFICATION
################################################################################

info "Verification:"
echo ""

# Show cron jobs
echo "Installed cron jobs:"
sudo crontab -l 2>/dev/null | grep "f2b docker sync" | sed 's/^/  /'
echo ""

# Check log file
if [ -s "$LOG_FILE" ]; then
    echo "Recent sync log (last 5 lines):"
    tail -5 "$LOG_FILE" | sed 's/^/  /'
else
    warning "Log file is empty (sync will run in ~1 minute)"
fi

echo ""

################################################################################
# SUMMARY
################################################################################

echo "╔════════════════════════════════════════════════════════════════╗"
echo "║          ✅ Docker-Block Auto-Sync Configured!                 ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""

log "Configuration complete!"
echo ""

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
info "What happens now?"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Every minute, the system will:"
echo "  1. Run validate sync (REMOVE-only) for docker-block"
echo "Every 15 minutes, the system will:"
echo "  2. Run full sync (ADD+REMOVE) for docker-block"
echo "  3. Log all changes to $LOG_FILE"
echo ""

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
info "Monitoring Commands"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "1. Watch sync log in real-time:"
echo "   sudo tail -f /var/log/f2b-docker-sync.log"
echo ""
echo "2. Real-time dashboard (live monitoring):"
echo "   sudo f2b docker dashboard"
echo ""
echo "3. Manual sync (if needed):"
echo "   sudo f2b docker sync full"
echo ""
echo "4. Check docker-block status:"
echo "   sudo f2b docker info"
echo ""
echo "5. Verify cron jobs:"
echo "   sudo crontab -l | grep 'f2b docker sync'"
echo ""

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

log "Setup complete - docker-block auto-sync is now active! 🚀"
echo ""
