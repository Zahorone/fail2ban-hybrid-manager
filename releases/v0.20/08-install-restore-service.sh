#!/bin/bash
################################################################################
# Install systemd service for restore banned IPs after boot
################################################################################

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

log() { echo -e "${GREEN}[OK]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }
info() { echo -e "${BLUE}[INFO]${NC} $1"; }

echo ""
echo "═══════════════════════════════════════════════════════"
echo "  Install F2B Auto-Restore Service"
echo "═══════════════════════════════════════════════════════"
echo ""

[[ $EUID -ne 0 ]] && error "Please run with sudo"

# Check wrapper exists
[[ ! -f /usr/local/bin/f2b ]] && error "F2B wrapper not installed (run 04-install-wrapper-v019.sh first)"

info "Creating systemd service..."

# Create service
cat << 'EOFSVC' | tee /etc/systemd/system/f2b-restore-bans.service > /dev/null
[Unit]
Description=Restore F2B banned IPs to nftables after boot
After=fail2ban.service nftables.service
Requires=fail2ban.service nftables.service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/f2b sync force
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOFSVC

log "Service file created"

# Enable service
systemctl daemon-reload
systemctl enable f2b-restore-bans.service
log "Service enabled"

# Test
info "Testing service..."
systemctl start f2b-restore-bans.service
sleep 2

if systemctl is-active --quiet f2b-restore-bans.service; then
    log "Service test: SUCCESS"
else
    error "Service test: FAILED"
fi

echo ""
log "Installation complete!"
echo ""
info "Service will restore banned IPs after each reboot"
info "Check status: sudo systemctl status f2b-restore-bans.service"
echo ""
