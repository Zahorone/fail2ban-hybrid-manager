#!/bin/bash
set -e
################################################################################
# F2B Wrapper Aliases Installer
# Component: INSTALL-ALIASES
# Part of: Fail2Ban Hybrid Nftables Manager
################################################################################

# shellcheck disable=SC2034
RELEASE="v0.30"
# shellcheck disable=SC2034
VERSION="0.30"
# shellcheck disable=SC2034
BUILD_DATE="2025-12-19"
# shellcheck disable=SC2034
COMPONENT_NAME="INSTALL-ALIASES"
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

log()      { echo -e "${GREEN}✓${NC} $1"; }
error()    { echo -e "${RED}✗${NC} $1"; exit 1; }
warning()  { echo -e "${YELLOW}⚠${NC} $1"; }
info()     { echo -e "${BLUE}ℹ${NC} $1"; }

echo ""
echo "╔════════════════════════════════════════════════════════════╗"
echo "║  F2B Wrapper Aliases Installer ${RELEASE}                  ║"
echo "║  Adds handy f2b-* shell aliases                            ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""


# Detect user
if [ -n "$SUDO_USER" ]; then
    TARGET_USER="$SUDO_USER"
    TARGET_HOME=$(getent passwd "$SUDO_USER" | cut -d: -f6)
else
    TARGET_USER="$(whoami)"
    TARGET_HOME="$HOME"
fi

BASHRC="$TARGET_HOME/.bashrc"

info "Installing aliases for user: $TARGET_USER"
info "Bash RC file: $BASHRC"
echo ""

# Backup
if [ -f "$BASHRC" ]; then
    cp "$BASHRC" "${BASHRC}.backup-$(date +%Y%m%d-%H%M%S)"
    log "Backed up existing .bashrc"
fi

# Remove old aliases
if grep -q "# F2B Wrapper Aliases" "$BASHRC" 2>/dev/null; then
    info "Removing old F2B aliases..."
    sed -i '/# F2B Wrapper Aliases v/,/# End F2B Wrapper Aliases/d' "$BASHRC"
fi

cat >> "$BASHRC" << 'EOF'

# F2B Wrapper Aliases v0.30 (minimal+)
# Quick access to the most used commands

# Core
alias f2b-status='sudo f2b status'
alias f2b-audit='sudo f2b audit'

# Monitoring
alias f2b-watch='sudo f2b monitor watch'
alias f2b-trends='sudo f2b monitor trends'

# Sync
alias f2b-sync='sudo f2b sync check'
alias f2b-sync-enhanced='sudo f2b sync enhanced'
alias f2b-sync-docker='sudo f2b sync docker'

# Docker dashboard
alias f2b-docker-dashboard='sudo f2b docker dashboard'

# Attack analysis
alias f2b-attack-analysis='sudo f2b report attack-analysis'

# Silent/cron-friendly audit
alias f2b-audit-silent='sudo f2b audit-silent'

# End F2B Wrapper Aliases v0.30 (minimal+)
EOF

log "Aliases installed successfully!"
echo ""

# Summary
echo "══════════════════════════════════════════════════════════"
echo " INSTALLED ALIASES (v0.30 - minimal+)"
echo "══════════════════════════════════════════════════════════"
echo ""

echo "Core:"
echo " f2b-status         - System status"
echo " f2b-audit          - Audit all jails"
echo ""

echo "Monitor:"
echo " f2b-watch          - Real-time monitoring"
echo " f2b-trends         - Attack trends"
echo ""

echo "Sync:"
echo " f2b-sync           - Check sync (Fail2Ban ↔ nftables)"
echo " f2b-sync-enhanced  - Enhanced sync checks"
echo " f2b-sync-docker    - Docker-block sync"
echo ""

echo "Docker-Block:"
echo " f2b-docker-dashboard - Real-time docker-block dashboard"
echo ""

echo "Attack Analysis:"
echo " f2b-attack-analysis  - Complete NPM+SSH security analysis"
echo ""

echo "Silent / cron:"
echo " f2b-audit-silent     - Silent audit for cron"
echo ""

echo "══════════════════════════════════════════════════════════"
echo ""

info "To activate aliases, run:"
echo " source ~/.bashrc"
echo ""
info "Or logout and login again"
echo ""

log "Installation complete!"
echo ""
