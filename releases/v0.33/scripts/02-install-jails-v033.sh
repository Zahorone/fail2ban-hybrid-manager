#!/bin/bash

set -e

################################################################################
# Component: INSTALL-JAILS
# Part of: Fail2Ban Hybrid Nftables Manager
################################################################################

# shellcheck disable=SC2034 # Metadata used for release tracking
RELEASE="v0.33"

# shellcheck disable=SC2034
VERSION="0.33"

# shellcheck disable=SC2034
BUILD_DATE="2026-01-01"

# shellcheck disable=SC2034
COMPONENT_NAME="INSTALL-JAILS"

# Colors
# shellcheck disable=SC2034
RED='\033[0;31m'

# shellcheck disable=SC2034
GREEN='\033[0;32m'

# shellcheck disable=SC2034
YELLOW='\033[1;33m'

# shellcheck disable=SC2034
BLUE='\033[0;34m'

# shellcheck disable=SC2034
NC='\033[0m'

log_header() { echo -e "${BLUE}$1${NC}"; }
log_success() { echo -e "${GREEN}✓${NC} $1"; }
log_error() { echo -e "${RED}✗${NC} $1"; }
log_info() { echo -e "${BLUE}ℹ${NC} $1"; }
log_warn() { echo -e "${YELLOW}⚠${NC} $1"; }

echo ""
echo "╔════════════════════════════════════════════════════════════╗"
echo "║                                                            ║"
echo "║  Fail2Ban Jails + Filters Installer ${RELEASE}               ║"
echo "║  12 Jails + 12 Filters + Actions (recidive 30d)            ║"
echo "║                                                            ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

# Root check
if [ "$EUID" -ne 0 ]; then
  log_error "Please run with sudo"
  exit 1
fi

################################################################################
# KROK 1: PATH RESOLUTION
################################################################################

log_header "═══ KROK 1: PATH RESOLUTION ═══"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

log_info "Script directory: $SCRIPT_DIR"

if [ -d "$SCRIPT_DIR/filters" ] && [ -d "$SCRIPT_DIR/config" ] && [ -d "$SCRIPT_DIR/actions" ]; then
  FILTERS_DIR="$SCRIPT_DIR/filters"
  CONFIG_DIR="$SCRIPT_DIR/config"
  ACTIONS_DIR="$SCRIPT_DIR/actions"
  log_success "Found filters/ and config/ in script directory"
elif [ -d "$SCRIPT_DIR/../filters" ] && [ -d "$SCRIPT_DIR/../config" ] && [ -d "$SCRIPT_DIR/../actions" ]; then
  FILTERS_DIR="$SCRIPT_DIR/../filters"
  CONFIG_DIR="$SCRIPT_DIR/../config"
  ACTIONS_DIR="$SCRIPT_DIR/../actions"
  log_success "Found filters/ and config/ in parent directory"
else
  log_error "Cannot find filters/, config/ or actions/ directories!"
  exit 1
fi

echo ""
log_info "Directories resolved:"
echo "  Filters: $FILTERS_DIR"
echo "  Config: $CONFIG_DIR"
echo "  Actions: $ACTIONS_DIR"
echo ""

################################################################################
# KROK 2: BACKUP EXISTING CONFIGURATION
################################################################################

log_header "═══ KROK 2: BACKUP EXISTING CONFIGURATION ═══"

BACKUP_DIR="/tmp/fail2ban-backup-$(date +%s)"

mkdir -p "$BACKUP_DIR"

if [ -f /etc/fail2ban/jail.local ]; then
  cp /etc/fail2ban/jail.local "$BACKUP_DIR/jail.local"
  log_success "Backed up jail.local"
fi

if [ -d /etc/fail2ban/filter.d ]; then
  mkdir -p "$BACKUP_DIR/filter.d"
  cp /etc/fail2ban/filter.d/*.conf "$BACKUP_DIR/filter.d/" 2>/dev/null || true
fi

if [ -d /etc/fail2ban/action.d ]; then
  mkdir -p "$BACKUP_DIR/action.d"
  cp /etc/fail2ban/action.d/nftables-*.conf "$BACKUP_DIR/action.d/" 2>/dev/null || true
  cp /etc/fail2ban/action.d/nftables-common.local "$BACKUP_DIR/action.d/" 2>/dev/null || true
  cp /etc/fail2ban/action.d/nftables.conf.local "$BACKUP_DIR/action.d/" 2>/dev/null || true
  cp /etc/fail2ban/action.d/docker-sync-hook.conf.local "$BACKUP_DIR/action.d/" 2>/dev/null || true
fi

log_info "Backup location: $BACKUP_DIR"

echo ""

################################################################################
# KROK 3: INSTALL FILTERS (12)
################################################################################

log_header "═══ KROK 3: INSTALL FILTERS (12) ═══"

EXPECTED_FILTERS=(
"sshd.conf"
"f2b-exploit-critical.conf"
"f2b-dos-high.conf"
"f2b-web-medium.conf"
"nginx-recon-optimized.conf"
"f2b-fuzzing-payloads.conf"
"f2b-botnet-signatures.conf"
"f2b-anomaly-detection.conf"
"manualblock.conf"
"recidive.conf"
"nginx-php-errors.conf"
)

for filter in "${EXPECTED_FILTERS[@]}"; do
  if [ -f "$FILTERS_DIR/$filter" ]; then
    echo -n "  $filter ... "
    sudo cp "$FILTERS_DIR/$filter" /etc/fail2ban/filter.d/
    echo "✓"
  fi
done

echo ""

################################################################################
# KROK 4: INSTALL CONFIGURATION FILES
################################################################################

log_header "═══ KROK 4: INSTALL CONFIGURATION FILES ═══"

if [ -f "$CONFIG_DIR/jail.local" ]; then
  sudo cp "$CONFIG_DIR/jail.local" /etc/fail2ban/jail.local
  log_success "jail.local installed"
fi

LOCAL_CONFIGS=("nginx-recon-optimized.local" "f2b-anomaly-detection.local")

for local_conf in "${LOCAL_CONFIGS[@]}"; do
  if [ -f "$CONFIG_DIR/$local_conf" ]; then
    sudo cp "$CONFIG_DIR/$local_conf" /etc/fail2ban/filter.d/
  fi
done

echo ""

################################################################################
# KROK 5: INSTALL ACTIONS
################################################################################

log_header "═══ KROK 5: INSTALL ACTIONS ═══"

# nftables-common.local - KRITICKÝ súbor (table override)
if [ -f "$ACTIONS_DIR/nftables-common.local" ]; then
echo -n " nftables-common.local ... "
sudo cp "$ACTIONS_DIR/nftables-common.local" /etc/fail2ban/action.d/
echo "✓ (table override: fail2ban-filter)"
else
log_warn "nftables-common.local NOT FOUND - using defaults"
fi

# nftables.conf.local - KRITICKÝ súbor (unified f2b-* set naming + defaults)
if [ -f "$ACTIONS_DIR/nftables.conf.local" ]; then
echo -n " nftables.conf.local ... "
sudo cp "$ACTIONS_DIR/nftables.conf.local" /etc/fail2ban/action.d/
echo "✓ (addr_set=f2b-, table=fail2ban-filter)"
else
log_warn "nftables.conf.local NOT FOUND - using defaults"
fi

# nftables-multiport.conf - fallback (ak originál chýba)
if [ -f /etc/fail2ban/action.d/nftables-multiport.conf ]; then
log_info "nftables-multiport.conf already exists (using existing)"
else
if [ -f "$ACTIONS_DIR/nftables-multiport.conf" ]; then
log_warn "nftables-multiport.conf missing - installing fallback"
echo -n " nftables-multiport.conf ... "
sudo cp "$ACTIONS_DIR/nftables-multiport.conf" /etc/fail2ban/action.d/
echo "✓ (7d timeout - fallback)"
fi
fi

# nftables-recidive.conf - custom action (30d)
if [ -f "$ACTIONS_DIR/nftables-recidive.conf" ]; then
echo -n " nftables-recidive.conf ... "
sudo cp "$ACTIONS_DIR/nftables-recidive.conf" /etc/fail2ban/action.d/
echo "✓ (30d timeout - custom)"
else
log_error "nftables-recidive.conf NOT FOUND!"
fi

# docker-sync-hook.conf - OPRAVENÉ (chýbalo)
if [ -f "$ACTIONS_DIR/docker-sync-hook.conf" ]; then
echo -n " docker-sync-hook.conf ... "
sudo cp "$ACTIONS_DIR/docker-sync-hook.conf" /etc/fail2ban/action.d/
echo "✓ (docker-sync action)"
else
log_error "docker-sync-hook.conf NOT FOUND inside $ACTIONS_DIR!"
fi

# f2b-docker-hook.sh - helper pre docker-sync-hook (do /usr/local/sbin)
# OPRAVENÉ: Súbor je v scripts/, takže používame SCRIPT_DIR
if [ -f "$SCRIPT_DIR/f2b-docker-hook.sh" ]; then
echo -n " f2b-docker-hook.sh ... "
sudo cp "$SCRIPT_DIR/f2b-docker-hook.sh" /usr/local/sbin/f2b-docker-hook
sudo chmod 0755 /usr/local/sbin/f2b-docker-hook
sudo chown root:root /usr/local/sbin/f2b-docker-hook
echo "✓ (/usr/local/sbin/f2b-docker-hook)"
else
log_error "f2b-docker-hook.sh NOT FOUND in $SCRIPT_DIR!"
fi

echo ""
log_header "═══ KROK 6: CREATE LOG FILES ═══"

LOG_FILES=(
  "/var/log/fail2ban-blocked-ips.txt"
  "/var/log/f2b-wrapper.log"
  "/var/log/f2b-docker-sync.log"
)

for log_file in "${LOG_FILES[@]}"; do
  if [ ! -f "$log_file" ]; then
    sudo touch "$log_file"
    sudo chmod 644 "$log_file"
  fi
done

echo ""

################################################################################
# KROK 7-8: RESTART FAIL2BAN
################################################################################

log_header "═══ KROK 7-8: RESTART FAIL2BAN ═══"

if systemctl list-unit-files 2>/dev/null | grep -q "fail2ban.service"; then
  log_info "Restarting Fail2Ban..."
  sudo systemctl restart fail2ban
  sleep 3
  log_success "Fail2Ban restarted"
fi

echo ""

################################################################################
# KROK 9: VERIFICATION
################################################################################

log_header "═══ KROK 9: VERIFICATION ═══"

echo -n "  nftables-common.local configuration ... "
if grep -q "table = fail2ban-filter" /etc/fail2ban/action.d/nftables-common.local 2>/dev/null; then
  echo "✓ (table = fail2ban-filter)"
else
  echo "⚠ (using defaults)"
fi

echo -n "  Recidive jail status ... "
if sudo fail2ban-client status recidive >/dev/null 2>&1; then
  echo "✓"
else
  echo "✗"
fi

echo ""

################################################################################
# COMPLETE
################################################################################

log_header "╔════════════════════════════════════════════════════════════╗"
log_header "║           INSTALLATION COMPLETE v${VERSION}                    ║"
log_header "╚════════════════════════════════════════════════════════════╝"

echo ""

echo "Next steps:"
echo " 1. sudo bash 01-install-nftables-v033.sh"
echo " 2. sudo bash 02-verify-jails-v033.sh"
echo ""

echo "Backup: $BACKUP_DIR"
echo ""
