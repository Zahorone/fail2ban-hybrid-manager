#!/bin/bash

################################################################################
# v0.32 KEY CHANGES (2025-12-20):
# + Immediate docker-block ban cez docker-sync-hook (žiadne čakanie na cron)
# + Lock mechanizmus /tmp/f2b-wrapper.lock proti paralelným behom
# + Vylepšené validate_ip()/validate_port() + IPv6 validácia cez ip(8)
# + Nové reporty (report json/csv/daily, audit-silent, stats-quick)
# + v0.30: version --json/--human/--short + presné počítanie IPv4/IPv6 setov
#
# F2B Wrapper v0.31 Installation Script
# Installs the unified F2B management wrapper
################################################################################

set -e

# shellcheck disable=SC2034
RELEASE="v0.31"
# shellcheck disable=SC2034
VERSION="0.31"
# shellcheck disable=SC2034
BUILD_DATE="2025-12-26"
# shellcheck disable=SC2034
COMPONENT_NAME="WRAPPER-INSTALLER"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
# shellcheck disable=SC2034
CYAN='\033[0;36m'
NC='\033[0m'

# Logging
log()    { echo -e "${GREEN}[✓]${NC} $1"; }
error()  { echo -e "${RED}[✗]${NC} $1"; exit 1; }
warning(){ echo -e "${YELLOW}[!]${NC} $1"; }
info()   { echo -e "${BLUE}[i]${NC} $1"; }

###############################################################################
# CLI FLAGS (non-interactive mode)
###############################################################################

ASSUME_YES=0

case "${1:-}" in
  --yes|--non-interactive)
    ASSUME_YES=1
    shift || true
    ;;
esac

# Header
clear
echo ""
echo "═══════════════════════════════════════════════════════"
echo " F2B Wrapper ${RELEASE} Installation"
echo " Complete Fail2Ban + nftables Management"
echo "═══════════════════════════════════════════════════════"
echo ""

# Root check
if [ "$EUID" -ne 0 ]; then
  error "Please run with sudo: sudo bash $0"
fi

# Dependencies check
info "Checking dependencies..."
MISSING=0
for cmd in nft fail2ban-client systemctl; do
  if ! command -v "$cmd" &>/dev/null; then
    error "Missing: $cmd"
    # shellcheck disable=SC2317
    ((MISSING++))
  else
    log "Found: $cmd"
  fi
done

if [ "$MISSING" -gt 0 ]; then
  echo ""
  error "Missing $MISSING required commands"
fi

echo ""
info "All dependencies satisfied"
echo ""

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Look for wrapper script
WRAPPER_SOURCE=""
if   [ -f "$SCRIPT_DIR/f2b-wrapper-v031.sh" ]; then
  WRAPPER_SOURCE="$SCRIPT_DIR/f2b-wrapper-v031.sh"
elif [ -f "$SCRIPT_DIR/f2b-wrapper.sh" ]; then
  WRAPPER_SOURCE="$SCRIPT_DIR/f2b-wrapper.sh"
elif [ -f "$HOME/f2b-wrapper-v031.sh" ]; then
  WRAPPER_SOURCE="$HOME/f2b-wrapper-v031.sh"
else
  error "F2B wrapper script not found. Please ensure f2b-wrapper-v031.sh is in $SCRIPT_DIR"
fi

info "Found wrapper script: $WRAPPER_SOURCE"
echo ""

# Verify wrapper release/version
WRAPPER_RELEASE=$(grep -m1 '^RELEASE=' "$WRAPPER_SOURCE" | cut -d'"' -f2)
WRAPPER_VERSION=$(grep -m1 '^VERSION=' "$WRAPPER_SOURCE" | cut -d'"' -f2)

# toleruj prefix "v"
WRAPPER_RELEASE="${WRAPPER_RELEASE#v}"
RELEASE="${RELEASE#v}"
WRAPPER_VERSION="${WRAPPER_VERSION#v}"
VERSION="${VERSION#v}"

# 1) Release musí sedieť (ak to berieš ako "kompatibilitnú vetvu")
if [ "$WRAPPER_RELEASE" != "$RELEASE" ]; then
  warning "Release mismatch: installer=$RELEASE, wrapper=$WRAPPER_RELEASE"

  if [ "$ASSUME_YES" -eq 1 ]; then
    info "--yes specified -> continuing despite release mismatch"
  else
    read -r -p "Continue anyway? (yes/no): "
    if [[ ! $REPLY =~ ^[Yy](es)?$ ]]; then
      error "Installation cancelled"
      exit 1
    fi
  fi
fi

# 2) Wrapper musí byť aspoň minimálna verzia (wrapper >= required)
if [ "$(printf '%s\n%s\n' "$VERSION" "$WRAPPER_VERSION" | sort -V | head -n1)" != "$VERSION" ]; then
  warning "Wrapper is older than required: wrapper=$WRAPPER_VERSION < required=$VERSION"

  if [ "$ASSUME_YES" -eq 1 ]; then
    info "--yes specified -> continuing despite older wrapper version"
  else
    read -r -p "Continue anyway? (yes/no): "
    if [[ ! $REPLY =~ ^[Yy](es)?$ ]]; then
      error "Installation cancelled"
      exit 1
    fi
  fi
fi

echo ""
echo ""
info "Installation Steps:"
echo " 1. Create log directories"
echo " 2. Remove old wrapper versions (v024, v025, etc.)"
echo " 3. Install wrapper to /usr/local/bin/f2b"
echo " 4. Set permissions"
echo " 5. Verify installation"
echo ""

if [ "$ASSUME_YES" -eq 1 ]; then
  info "--yes specified -> skipping interactive confirmation"
else
  read -p "Continue with installation? (yes/no): " -r
  echo ""
  if [[ ! $REPLY =~ ^[Yy](es)?$ ]]; then
    warning "Installation cancelled by user"
    exit 0
  fi
fi

# Step 1: Create directories and log files
log "Step 1/5: Creating directories and log files..."

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

# Step 2: Remove old versions (CLEANUP)
log "Step 2/5: Removing old wrapper versions..."

# Backup existing if present
if [ -f /usr/local/bin/f2b ]; then
  BACKUP_FILE="/usr/local/bin/f2b.backup-$(date +%Y%m%d-%H%M%S)"
  cp /usr/local/bin/f2b "$BACKUP_FILE"
  warning "Existing wrapper backed up to: $BACKUP_FILE"
fi

# Remove old versioned copies (if they exist)
for old_file in /usr/local/bin/f2b-wrapper-v*.sh; do
  if [ -f "$old_file" ]; then
    rm -f "$old_file"
    info "Removed old version: $old_file"
  fi
done

log "Cleanup complete"
echo ""

# Step 3: Install wrapper
log "Step 3/5: Installing F2B wrapper..."

cp "$WRAPPER_SOURCE" /usr/local/bin/f2b
log "Wrapper installed to: /usr/local/bin/f2b"
echo ""

# Step 4: Set permissions
log "Step 4/5: Setting permissions..."

chmod +x /usr/local/bin/f2b
chown root:root /usr/local/bin/f2b
log "Permissions set: 755 root:root"
echo ""

# Step 5: Verify installation
log "Step 5/5: Verifying installation..."
echo ""

if [ ! -f /usr/local/bin/f2b ]; then
  error "Installation failed: /usr/local/bin/f2b not found"
fi

if [ ! -x /usr/local/bin/f2b ]; then
  error "Installation failed: /usr/local/bin/f2b not executable"
fi

# Test execution
if /usr/local/bin/f2b version --short &>/dev/null; then
  log "Wrapper execution: OK"
else
  error "Wrapper execution failed"
fi

# Show version
echo ""
info "Installed version: $(/usr/local/bin/f2b version --short 2>/dev/null || true)"
echo ""

# Summary
echo ""
echo "═══════════════════════════════════════════════════════"
echo " F2B WRAPPER ${RELEASE} INSTALLED!"
echo "═══════════════════════════════════════════════════════"
echo ""
log "Installation location: /usr/local/bin/f2b"
log "Log file: /var/log/f2b-wrapper.log"
log "Backup directory: /var/backups/firewall"
log "Reports directory: /var/firewall-reports"
log "Docker sync log: /var/log/f2b-docker-sync.log"
echo ""

# Quick start guide (ponechané ako v pôvodnom skripte) ...
# [zvyšok sú len echo-info; netreba meniť kvôli --yes režimu]

