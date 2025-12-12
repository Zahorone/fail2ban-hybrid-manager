#!/bin/bash

################################################################################
# Install F2B Wrapper Aliases v0.23 (UPDATED - Docker Support)
# Adds convenient bash aliases for F2B management
################################################################################

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log() { echo -e "${GREEN}[OK]${NC} $1"; }
info() { echo -e "${BLUE}[INFO]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; }

echo ""
echo "══════════════════════════════════════════════════════════"
echo " F2B Wrapper v0.23 - Bash Aliases Installation (Docker)"
echo "══════════════════════════════════════════════════════════"
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

# Add new aliases
cat >> "$BASHRC" << 'EOF'

# F2B Wrapper Aliases v0.23
# Quick access to F2B management commands

# Core commands
alias f2b-status='sudo f2b status'
alias f2b-audit='sudo f2b audit'
alias f2b-find='sudo f2b find'
alias f2b-version='sudo f2b version'

# Sync commands
alias f2b-sync='sudo f2b sync check'
alias f2b-sync-force='sudo f2b sync force'
alias f2b-sync-docker='sudo f2b sync docker'

# Monitor commands
alias f2b-watch='sudo f2b monitor watch'
alias f2b-bans='sudo f2b monitor show-bans'
alias f2b-top='sudo f2b monitor top-attackers'
alias f2b-trends='sudo f2b monitor trends'
alias f2b-log='sudo f2b monitor jail-log'

# Port management
alias f2b-block-port='sudo f2b manage block-port'
alias f2b-unblock-port='sudo f2b manage unblock-port'
alias f2b-list-ports='sudo f2b manage list-blocked-ports'
alias f2b-docker='sudo f2b manage docker-info'

# IP management
alias f2b-ban='sudo f2b manage manual-ban'
alias f2b-unban='sudo f2b manage manual-unban'
alias f2b-unban-all='sudo f2b manage unban-all'

# System management
alias f2b-reload='sudo f2b manage reload'
alias f2b-backup='sudo f2b manage backup'

# Reports (NEW v0.20)
alias f2b-json='sudo f2b report json'
alias f2b-csv='sudo f2b report csv'
alias f2b-report='sudo f2b report daily'

# Quick stats
alias f2b-quick='sudo f2b stats-quick'

# Docker-Block Dashboard (NEW v0.23)
alias f2b-docker-dashboard='sudo f2b docker dashboard'
alias f2b-docker-sync='sudo f2b docker sync'
alias f2b-docker-info='sudo f2b docker info'

# End F2B Wrapper Aliases v0.23
EOF

log "Aliases installed successfully!"
echo ""

# Summary
echo "══════════════════════════════════════════════════════════"
echo " INSTALLED ALIASES (v0.23)"
echo "══════════════════════════════════════════════════════════"
echo ""

echo "Core:"
echo " f2b-status - System status"
echo " f2b-audit - Audit all jails"
echo " f2b-find - Find IP in jails"
echo " f2b-version - Show version"
echo ""

echo "Sync:"
echo " f2b-sync - Check sync"
echo " f2b-sync-force - Force sync"
echo " f2b-sync-docker - Docker sync (NEW v0.23)"
echo ""

echo "Monitor:"
echo " f2b-watch - Real-time monitoring"
echo " f2b-bans [jail] - Show banned IPs"
echo " f2b-top - Top attackers"
echo " f2b-trends - Attack trends"
echo " f2b-log - Jail log"
echo ""

echo "Port Management:"
echo " f2b-block-port - Block port"
echo " f2b-unblock-port - Unblock port"
echo " f2b-list-ports - List blocked"
echo " f2b-docker - Docker-block info"
echo ""

echo "IP Management:"
echo " f2b-ban [time] - Ban IP"
echo " f2b-unban - Unban IP"
echo " f2b-unban-all - Unban from all"
echo ""

echo "System:"
echo " f2b-reload - Reload firewall"
echo " f2b-backup - Backup config"
echo ""

echo "Reports:"
echo " f2b-json - Export JSON"
echo " f2b-csv - Export CSV"
echo " f2b-report - Daily report"
echo " f2b-quick - Quick stats"
echo ""

echo "🐋 Docker-Block (NEW v0.23):"
echo " f2b-docker-dashboard - Real-time monitoring dashboard"
echo " f2b-docker-sync - Manual sync fail2ban ↔ docker-block"
echo " f2b-docker-info - Show docker-block configuration"
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
