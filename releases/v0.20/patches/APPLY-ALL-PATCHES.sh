#!/bin/bash
set -e

GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

log() { echo -e "${GREEN}[✓]${NC} $1"; }
info() { echo -e "${BLUE}[i]${NC} $1"; }

echo ""
echo "╔════════════════════════════════════════════════════════╗"
echo "║   F2B v0.19 - Applying All Patches                   ║"
echo "╚════════════════════════════════════════════════════════╝"
echo ""

cd "$(dirname "$0")"

info "1/4: Creating missing filters..."
bash 01-create-missing-filters.sh
echo ""

info "2/4: Fixing 02-install-jails.sh..."
bash 02-fix-jail-installer.sh
echo ""

info "3/4: Disabling KROK 6..."
bash 03-disable-krok6.sh
echo ""

info "4/4: Fixing wrapper (if installed)..."
bash 04-fix-wrapper-docker-set.sh
echo ""

echo "╔════════════════════════════════════════════════════════╗"
echo "║   ✅ ALL PATCHES APPLIED                              ║"
echo "╚════════════════════════════════════════════════════════╝"
echo ""

log "You can now run: sudo bash ../INSTALL-ALL-v019.sh"
echo ""
