#!/bin/bash

################################################################################
# F2B Wrapper v0.23 Installation Script
# Installs the unified F2B management wrapper
################################################################################

set -e

VERSION="0.23"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Logging
log() { echo -e "${GREEN}[OK]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }
warning() { echo -e "${YELLOW}[WARN]${NC} $1"; }
info() { echo -e "${BLUE}[INFO]${NC} $1"; }

# Header
clear
echo ""
echo "╔════════════════════════════════════════════════════════════╗"
echo "║                                                            ║"
echo "║ F2B Wrapper v${VERSION} Installation                       ║"
echo "║ Complete Fail2Ban + nftables Management                    ║"
echo "║                                                            ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

# Root check
if [ "$EUID" -ne 0 ]; then
error "Please run with sudo: sudo bash $0"
fi

# Dependencies check
info "Checking dependencies..."
MISSING_DEPS=()

for cmd in nft fail2ban-client systemctl; do
if ! command -v "$cmd" &>/dev/null; then
MISSING_DEPS+=("$cmd")
error "Missing: $cmd"
else
log "Found: $cmd"
fi
done

if [ ${#MISSING_DEPS[@]} -gt 0 ]; then
echo ""
error "Missing ${#MISSING_DEPS[@]} required command(s)"
fi

echo ""
info "All dependencies satisfied"
echo ""

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Look for wrapper script
WRAPPER_SOURCE=""

if [ -f "$SCRIPT_DIR/f2b-wrapper-v023.sh" ]; then
WRAPPER_SOURCE="$SCRIPT_DIR/f2b-wrapper-v023.sh"
elif [ -f "$SCRIPT_DIR/f2b-wrapper.sh" ]; then
WRAPPER_SOURCE="$SCRIPT_DIR/f2b-wrapper.sh"
elif [ -f "$HOME/f2b-wrapper-v023.sh" ]; then
WRAPPER_SOURCE="$HOME/f2b-wrapper-v023.sh"
else
error "F2B wrapper script not found. Please ensure f2b-wrapper-v023.sh is in: $SCRIPT_DIR"
fi

info "Found wrapper script: $WRAPPER_SOURCE"
echo ""

# Verify wrapper version
WRAPPER_VERSION=$(grep "^VERSION=" "$WRAPPER_SOURCE" | head -1 | cut -d'"' -f2)

if [ "$WRAPPER_VERSION" != "$VERSION" ]; then
warning "Version mismatch: installer=$VERSION, wrapper=$WRAPPER_VERSION"
read -p "Continue anyway? (yes/no): " -r
if [[ ! $REPLY =~ ^[Yy]es$ ]]; then
error "Installation cancelled"
fi
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
info "Installation Steps:"
echo " 1. Create log directories"
echo " 2. Install wrapper to /usr/local/bin/f2b"
echo " 3. Set permissions"
echo " 4. Verify installation"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

read -p "Continue with installation? (yes/no): " -r
echo ""

if [[ ! $REPLY =~ ^[Yy]es$ ]]; then
warning "Installation cancelled by user"
exit 0
fi

# Step 1: Create directories and log files
log "Step 1/4: Creating directories and log files..."

mkdir -p /var/log
mkdir -p /var/backups/firewall
mkdir -p /var/firewall-reports
touch /var/log/f2b-wrapper.log
touch /var/log/f2b-sync.log
touch /var/log/f2b-audit.log
touch /var/log/f2b-docker-sync.log

chmod 640 /var/log/f2b-wrapper.log
chmod 640 /var/log/f2b-sync.log
chmod 640 /var/log/f2b-audit.log
chmod 640 /var/log/f2b-docker-sync.log

log "Log files created"
echo ""

# Step 2: Install wrapper
log "Step 2/4: Installing F2B wrapper..."

# Backup existing
if [ -f /usr/local/bin/f2b ]; then
BACKUP_FILE="/usr/local/bin/f2b.backup-$(date +%Y%m%d-%H%M%S)"
cp /usr/local/bin/f2b "$BACKUP_FILE"
warning "Existing wrapper backed up to: $BACKUP_FILE"
fi

# Copy wrapper
cp "$WRAPPER_SOURCE" /usr/local/bin/f2b
log "Wrapper installed to: /usr/local/bin/f2b"
echo ""

# Step 3: Set permissions
log "Step 3/4: Setting permissions..."

chmod +x /usr/local/bin/f2b
chown root:root /usr/local/bin/f2b

log "Permissions set: 755 (root:root)"
echo ""

# Step 4: Verify installation
log "Step 4/4: Verifying installation..."
echo ""

if [ ! -f /usr/local/bin/f2b ]; then
error "Installation failed: /usr/local/bin/f2b not found"
fi

if [ ! -x /usr/local/bin/f2b ]; then
error "Installation failed: /usr/local/bin/f2b not executable"
fi

# Test execution
if /usr/local/bin/f2b version &>/dev/null; then
log "Wrapper execution: OK"
else
error "Wrapper execution failed"
fi

# Show version
echo ""
info "Installed version:"
/usr/local/bin/f2b version 2>/dev/null || true
echo ""

# Summary
echo ""
echo "╔════════════════════════════════════════════════════════════╗"
echo "║                                                            ║"
echo "║ ✅ F2B WRAPPER v${VERSION} INSTALLED!                      ║"
echo "║                                                            ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

log "Installation location: /usr/local/bin/f2b"
log "Log file: /var/log/f2b-wrapper.log"
log "Backup directory: /var/backups/firewall"
log "Reports directory: /var/firewall-reports"
log "Docker sync log: /var/log/f2b-docker-sync.log"
echo ""

# Post-installation info
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
info "Quick Start Guide"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

echo "Basic Commands:"
echo " f2b status - Show system status"
echo " f2b audit - Audit all jails"
echo " f2b sync check - Check sync status"
echo " f2b monitor watch - Real-time monitoring"
echo ""

echo "New in v${VERSION}:"
echo " f2b docker dashboard - Real-time Docker-block dashboard"
echo " f2b docker info      - Docker-block configuration"
echo " f2b sync docker      - Full docker sync + verification"
echo ""

echo "Management:"
echo " f2b manage block-port - Block Docker port"
echo " f2b manage manual-ban - Ban IP manually"
echo " f2b find - Find IP in jails"
echo ""

echo "Full Help:"
echo " f2b help"
echo ""

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Test basic functionality
info "Running basic functionality test..."
echo ""

echo "Test 1: Status check"
if f2b status &>/dev/null; then
log "✅ Status command works"
else
warning "⚠️ Status command failed (might be normal if services not running)"
fi

echo ""
echo "Test 2: Help display"
if f2b help &>/dev/null; then
log "✅ Help command works"
else
warning "⚠️ Help command failed"
fi

echo ""
echo "Test 3: Log file"
if [ -f /var/log/f2b-wrapper.log ]; then
log "✅ Log file created"
else
warning "⚠️ Log file not found"
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
info "Next Steps"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

echo "1. Install bash aliases (optional):"
echo " sudo bash 06-install-aliases.sh"
echo ""
echo "2. Test the wrapper:"
echo " sudo f2b status"
echo ""
echo "3. Check system sync:"
echo " sudo f2b sync check"
echo ""
echo "4. View Docker dashboard (NEW v0.23):"
echo " sudo f2b docker dashboard"
echo ""
echo "5. Export report:"
echo " sudo f2b report json > /tmp/f2b-report.json"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

log "Installation completed successfully!"
echo ""

echo "For detailed help: sudo f2b help"
echo ""

