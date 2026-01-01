#!/bin/bash
set -e

################################################################################
# Component: PRE-CLEANUP
# Part of: Fail2Ban Hybrid Nftables Manager
################################################################################
# shellcheck disable=SC2034 
RELEASE="v0.33"
# shellcheck disable=SC2034
VERSION="0.33"
# shellcheck disable=SC2034
BUILD_DATE="2026-01-01"
# shellcheck disable=SC2034
COMPONENT_NAME="PRE-CLEANUP"

# Optional flags / env:
#   F2B_FORCE_CLEANUP=yes     -> allows deleting nft tables (DANGEROUS)
#   --force-cleanup           -> same as F2B_FORCE_CLEANUP=yes
#   --cleanup-only            -> run and exit 0 (for manual troubleshooting)

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log()     { echo -e "${GREEN}[✓]${NC} $1"; }
warning() { echo -e "${YELLOW}[!]${NC} $1"; }
info()    { echo -e "${BLUE}[i]${NC} $1"; }
error()   { echo -e "${RED}[✗]${NC} $1"; exit 1; }

FORCE_CLEANUP="${F2B_FORCE_CLEANUP:-no}"
CLEANUP_ONLY="no"

case "${1:-}" in
  --force-cleanup) FORCE_CLEANUP="yes" ;;
  --cleanup-only) CLEANUP_ONLY="yes" ;;
esac

clear
echo ""
echo "═══════════════════════════════════════════════════════"
echo " Pre-Installation Cleanup ${RELEASE}"
echo " Fail2Ban Hybrid Nftables Manager"
echo "═══════════════════════════════════════════════════════"
echo ""

# Root check
if [ "$EUID" -ne 0 ]; then
  error "Please run with sudo: sudo bash $0"
fi

echo ""
info "Mode:"
echo "  RELEASE: ${RELEASE}  VERSION: ${VERSION}  BUILD_DATE: ${BUILD_DATE}"
echo "  FORCE_CLEANUP: ${FORCE_CLEANUP}"
echo "  CLEANUP_ONLY:  ${CLEANUP_ONLY}"
echo ""

################################################################################
# STEP 1: BACKUP
################################################################################
info "Step 1/6: Creating backup..."
TS="$(date +%Y%m%d-%H%M%S)"
BACKUP_DIR="/var/backups/firewall/precleanup-${RELEASE}-${TS}"
mkdir -p "$BACKUP_DIR"

# Backup nftables ruleset
nft list ruleset > "$BACKUP_DIR/nft-ruleset.txt" 2>/dev/null || true

# Backup fail2ban configs
if [ -d /etc/fail2ban ]; then
  cp -a /etc/fail2ban "$BACKUP_DIR/fail2ban-backup" 2>/dev/null || true
fi

# Backup nftables configs
if [ -d /etc/nftables ]; then
  cp -a /etc/nftables "$BACKUP_DIR/nftables-backup" 2>/dev/null || true
fi

# Backup nftables.d
if [ -d /etc/nftables.d ]; then
  cp -a /etc/nftables.d "$BACKUP_DIR/nftables.d-backup" 2>/dev/null || true
fi

log "Backup saved: $BACKUP_DIR"
echo ""

################################################################################
# STEP 2: STOP LEGACY SERVICES
################################################################################
info "Step 2/6: Stopping legacy services/timers..."
systemctl stop docker-firewall.service 2>/dev/null || true
systemctl disable docker-firewall.service 2>/dev/null || true

systemctl stop f2b-nft-sync.timer 2>/dev/null || true
systemctl disable f2b-nft-sync.timer 2>/dev/null || true
systemctl stop f2b-nft-sync.service 2>/dev/null || true

systemctl daemon-reload 2>/dev/null || true
log "Legacy services cleanup done"
echo ""

################################################################################
# STEP 3: CLEAN LEGACY CRON ENTRIES (avoid duplicates)
################################################################################
info "Step 3/6: Removing legacy cron entries (avoid duplicates)..."
# Important: installer Step 8 configures docker-sync; so we remove old ones here.
if crontab -l >/dev/null 2>&1; then
  TMP_CRON="$(mktemp)"
  ( crontab -l 2>/dev/null | grep -v "f2b sync docker" ) > "$TMP_CRON" || true
  crontab "$TMP_CRON" 2>/dev/null || true
  rm -f "$TMP_CRON"
  log "Cron cleaned (removed: 'f2b sync docker' if present)"
else
  info "No root crontab found (nothing to clean)"
fi
echo ""

################################################################################
# STEP 4: CLEAN NFT TABLES (ONLY WHEN FORCED)
################################################################################
info "Step 4/6: nftables cleanup..."
if [ "$FORCE_CLEANUP" = "yes" ]; then
  warning "FORCE cleanup enabled -> deleting nft tables (this may remove active bans!)"
    if nft delete table inet fail2ban-filter 2>/dev/null; then
      log "Removed: inet fail2ban-filter"
    else
      info "No inet fail2ban-filter table"
    fi
    
    if nft delete table inet docker-block 2>/dev/null; then
      log "Removed: inet docker-block"
    else
      info "No inet docker-block table"
    fi
else
  info "Safe mode -> NOT deleting nft tables (upgrade-friendly)."
fi

# legacy chain cleanup (best-effort)
nft flush chain ip filter DOCKER-USER 2>/dev/null || true
echo ""

################################################################################
# STEP 5: CLEAN LEGACY FILES (safe)
################################################################################
info "Step 5/6: Removing legacy generated files..."
rm -f /etc/nftables/fail2ban-*.nft 2>/dev/null || true
rm -f /etc/nftables/docker-block.nft 2>/dev/null || true
log "Removed old /etc/nftables snippets (if any)"

# Clean old includes from /etc/nftables.conf (portable-ish: keep backup)
if [ -f /etc/nftables.conf ]; then
  sed -i.bak '/fail2ban-/d' /etc/nftables.conf 2>/dev/null || true
  sed -i.bak '/docker-block/d' /etc/nftables.conf 2>/dev/null || true
  log "Cleaned /etc/nftables.conf includes (backup: /etc/nftables.conf.bak)"
fi

rm -f /etc/systemd/system/docker-firewall.service 2>/dev/null || true
rm -f /etc/systemd/system/f2b-nft-sync.* 2>/dev/null || true
systemctl daemon-reload 2>/dev/null || true
log "Removed legacy systemd unit files (if any)"
echo ""

################################################################################
# STEP 6: WRAPPER & ALIASES (safe defaults)
################################################################################
info "Step 6/6: Wrapper & aliases cleanup..."
# In upgrade mode we typically do NOT remove /usr/local/bin/f2b; installer will replace it.
# But in forced cleanup it is fine to remove.
if [ "$FORCE_CLEANUP" = "yes" ]; then
      if rm -f /usr/local/bin/f2b 2>/dev/null; then
      log "Removed old f2b wrapper"
    else
      info "No old wrapper"
    fi
fi

rm -f /etc/profile.d/f2b-aliases.sh 2>/dev/null || true
log "Removed global aliases file (if any)"
echo ""

################################################################################
# VERIFICATION OUTPUT
################################################################################
info "Verification snapshot:"
echo ""
echo "Current nft tables:"
nft list tables 2>/dev/null || echo " (none)"
echo ""
echo "Legacy units (docker-firewall|f2b-nft-sync):"
systemctl list-units --all 2>/dev/null | grep -E "docker-firewall|f2b-nft-sync" || echo " (none)"
echo ""
echo "Docker-sync cron line (should be absent now):"
crontab -l 2>/dev/null | grep "f2b sync docker" || echo " (none)"
echo ""

echo "═══════════════════════════════════════════════════════"
log "PRE-CLEANUP COMPLETE (${RELEASE})"
echo "═══════════════════════════════════════════════════════"
echo ""
log "Backup location: $BACKUP_DIR"
echo ""

if [ "$CLEANUP_ONLY" = "yes" ]; then
  info "Cleanup-only mode -> exiting now."
  exit 0
fi

info "Next steps:"
echo " 1) Run installer: sudo bash INSTALL-ALL-v033.sh"
echo ""

