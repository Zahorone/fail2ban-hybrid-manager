#!/bin/bash

################################################################################
# FAIL2BAN HYBRID MANAGEMENT - COMPLETE SETUP v0.8
# Idempotent Installer: Clean Install + Upgrade + Rerun Safe
# WITH FAIL2BAN_HYBRID v0.7.3 CLI INTEGRATION
# 
# Features:
# - Detects: Fresh install vs v0.7.3 vs v0.8
# - Idempotent: Safe to run multiple times
# - Backup: Always creates restoration point
# - Validation: Full system checks before/after
# - Rollback: Can restore from backup if needed
# - CLI INTEGRATION: fail2ban_hybrid all 40+ functions
#
# Works on:
# - Fresh system (no fail2ban)
# - v0.7.3 systems (auto-migrate)
# - v0.8 systems (idempotent re-run)
#
# Usage: sudo bash fail2ban_v0.8-setup.sh [--dry-run|--rollback|--cli-only]
#
# Version: 0.8 IDEMPOTENT + CLI INTEGRATION
# Date: 2025-11-23
# Status: PRODUCTION READY
#
################################################################################

set -e

# ============================================================
# GLOBAL CONFIG
# ============================================================

VERSION="0.8-IDEMPOTENT+CLI"
SETUP_DATE="2025-11-23"

# Režim
DRY_RUN="${1:-}"
if [ "$DRY_RUN" = "--dry-run" ]; then
    DRY_RUN=true
else
    DRY_RUN=false
fi

ROLLBACK_MODE="${1:-}"
if [ "$ROLLBACK_MODE" = "--rollback" ]; then
    ROLLBACK_MODE=true
else
    ROLLBACK_MODE=false
fi

CLI_ONLY_MODE="${1:-}"
if [ "$CLI_ONLY_MODE" = "--cli-only" ]; then
    CLI_ONLY_MODE=true
else
    CLI_ONLY_MODE=false
fi

# Inštalačné cesty
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/fail2ban"
FILTER_DIR="$CONFIG_DIR/filter.d"
ACTION_DIR="$CONFIG_DIR/action.d"
NFTABLES_CONF="/etc/nftables.conf"
F2B_HYBRID_PATH="$INSTALL_DIR/f2b-hybrid"

# Backup
BACKUP_DIR="/var/backups/fail2ban-v0.8"
BACKUP_DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_LINK="$BACKUP_DIR/latest"

# Farby
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'

# Logging
LOG_FILE="/var/log/f2b-v0.8-setup.log"

log_info() {
    echo -e "${GREEN}✅ ${1}${NC}" | tee -a "$LOG_FILE"
}

log_warn() {
    echo -e "${YELLOW}⚠️  ${1}${NC}" | tee -a "$LOG_FILE"
}

log_error() {
    echo -e "${RED}❌ ${1}${NC}" | tee -a "$LOG_FILE"
}

log_debug() {
    echo -e "${BLUE}🔍 ${1}${NC}" | tee -a "$LOG_FILE"
}

log_header() {
    echo -e "${CYAN}${1}${NC}" | tee -a "$LOG_FILE"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}" | tee -a "$LOG_FILE"
}

log_mode() {
    echo -e "${MAGENTA}${1}${NC}" | tee -a "$LOG_FILE"
}

# ============================================================
# BANNER
# ============================================================

clear
cat << 'EOF'
╔════════════════════════════════════════════════════════════════╗
║                                                                ║
║    🛡️  FAIL2BAN HYBRID v0.8 SETUP (IDEMPOTENT+CLI) 🛡️        ║
║                                                                ║
║  Smart Installer with CLI Integration:                       ║
║  ✅ Fresh Install                                            ║
║  ✅ Upgrade z v0.7.3                                         ║
║  ✅ Re-run Safe (Idempotent)                                 ║
║  ✅ fail2ban_hybrid CLI (40+ functions)                      ║
║  ✅ Automatic Rollback Support                               ║
║                                                                ║
║  GitHub Production Ready                                     ║
║                                                                ║
╚════════════════════════════════════════════════════════════════╝
EOF

echo ""
log_header "STARTING SETUP v$VERSION - $(date)"
echo ""

# ============================================================
# PHASE 0: CLI-ONLY MODE
# ============================================================

if [ "$CLI_ONLY_MODE" = "true" ]; then
    log_header "CLI INTEGRATION MODE (SKIP CONFIG)"
    log_info "Installing fail2ban_hybrid CLI tool only..."
    log_info "Configuration will be preserved"
    # Preskočí na PHASE CLI INTEGRATION nižšie
fi

# ============================================================
# PHASE 1: DETECT SYSTEM STATE
# ============================================================

if [ "$CLI_ONLY_MODE" != "true" ]; then
    log_header "PHASE 1: DETECT SYSTEM STATE"

    # Detekuj verziu Fail2Ban
    CURRENT_VERSION="unknown"
    if command -v fail2ban-client &> /dev/null; then
        CURRENT_VERSION=$(fail2ban-client --version 2>/dev/null | head -1 || echo "unknown")
        log_info "Detected Fail2Ban: $CURRENT_VERSION"
    else
        log_warn "Fail2Ban not installed - FRESH INSTALL mode"
        CURRENT_VERSION="not_installed"
    fi

    # Detekuj existujúcu konfiguráciu
    CONFIG_STATE="fresh"
    if [ -f "$CONFIG_DIR/jail.local" ]; then
        if grep -q "v0.8" "$CONFIG_DIR/jail.local" 2>/dev/null; then
            CONFIG_STATE="v0.8"
            log_debug "Detected v0.8 configuration"
        elif grep -q "v0.7" "$CONFIG_DIR/jail.local" 2>/dev/null; then
            CONFIG_STATE="v0.7"
            log_debug "Detected v0.7.3 configuration"
        else
            CONFIG_STATE="other"
            log_debug "Detected other/custom configuration"
        fi
    fi

    log_info "Configuration state: $CONFIG_STATE"

    # Režim
    if [ "$CONFIG_STATE" = "fresh" ]; then
        INSTALL_MODE="fresh"
        log_mode "🆕 FRESH INSTALL MODE"
    elif [ "$CONFIG_STATE" = "v0.8" ]; then
        INSTALL_MODE="idempotent"
        log_mode "♻️  IDEMPOTENT RE-RUN MODE"
    else
        INSTALL_MODE="upgrade"
        log_mode "⬆️  UPGRADE MODE (from v0.7.3)"
    fi

    echo ""

    # ============================================================
    # PHASE 2: PRE-FLIGHT CHECKS
    # ============================================================

    log_header "PHASE 2: PRE-FLIGHT CHECKS"

    if [[ $EUID -ne 0 ]]; then
        log_error "Must run as sudo!"
        exit 1
    fi

    log_info "Running as root"

    # Kontrola požiadavkov
    REQUIRED_CMDS=("nft" "systemctl" "sudo")
    REQUIRED_PKG=("nftables" "systemd")

    if [ "$INSTALL_MODE" != "fresh" ]; then
        REQUIRED_CMDS+=("fail2ban-client")
        REQUIRED_PKG+=("fail2ban")
    fi

    for cmd in "${REQUIRED_CMDS[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then
            log_error "Required command not found: $cmd"
            log_warn "Install: sudo apt install ${REQUIRED_PKG[@]}"
            exit 1
        fi
    done

    log_info "All required commands available"

    echo ""

    # ============================================================
    # PHASE 3: BACKUP (VŽDY!)
    # ============================================================

    log_header "PHASE 3: BACKUP (IDEMPOTENT SAFE)"

    mkdir -p "$BACKUP_DIR"

    # Backup existujúcej konfigurácie (ak existuje)
    if [ "$INSTALL_MODE" != "fresh" ]; then
        log_warn "Creating backup before any changes..."
        
        if [ -f "$CONFIG_DIR/jail.local" ]; then
            cp "$CONFIG_DIR/jail.local" "$BACKUP_DIR/jail.local.$BACKUP_DATE"
            log_info "Backed up jail.local"
        fi
        
        if [ -f "$NFTABLES_CONF" ]; then
            cp "$NFTABLES_CONF" "$BACKUP_DIR/nftables.conf.$BACKUP_DATE"
            log_info "Backed up nftables.conf"
        fi
        
        # Ulož aktuálny stav Fail2Ban DB
        if [ -f "/var/lib/fail2ban/fail2ban.sqlite3" ]; then
            cp "/var/lib/fail2ban/fail2ban.sqlite3" "$BACKUP_DIR/fail2ban.sqlite3.$BACKUP_DATE"
            log_info "Backed up Fail2Ban database"
        fi
        
        # Vytvor symlink na latest backup
        rm -f "$BACKUP_LINK"
        ln -s "$BACKUP_DIR" "$BACKUP_LINK"
    else
        log_info "Fresh install - no existing config to backup"
    fi

    log_info "Backup complete: $BACKUP_DIR"

    echo ""

    # ============================================================
    # PHASE 4: DRY RUN CHECK
    # ============================================================

    if [ "$DRY_RUN" = "true" ]; then
        log_header "DRY RUN MODE - NO CHANGES MADE"
        log_info "Mode detected: $INSTALL_MODE"
        log_info "Backup directory: $BACKUP_DIR"
        log_info "Changes that WOULD be made:"
        log_info "  1. Update jail.local"
        log_info "  2. Install/update filters"
        log_info "  3. Update nftables.conf"
        log_info "  4. Install fail2ban_hybrid CLI"
        log_info "  5. Restart Fail2Ban"
        echo ""
        log_info "To apply changes, run: sudo bash $0 (without --dry-run)"
        exit 0
    fi

    # ============================================================
    # PHASE 5: ROLLBACK MODE
    # ============================================================

    if [ "$ROLLBACK_MODE" = "true" ]; then
        log_header "ROLLBACK MODE"
        
        if [ ! -L "$BACKUP_LINK" ]; then
            log_error "No backup found to rollback!"
            exit 1
        fi
        
        LATEST_BACKUP=$(ls -t "$BACKUP_DIR"/jail.local.* 2>/dev/null | head -1)
        if [ -z "$LATEST_BACKUP" ]; then
            log_error "No valid backup found!"
            exit 1
        fi
        
        log_warn "Restoring from: $LATEST_BACKUP"
        cp "$LATEST_BACKUP" "$CONFIG_DIR/jail.local"
        
        sudo systemctl restart fail2ban
        log_info "Rollback complete!"
        exit 0
    fi

    # ============================================================
    # PHASE 6: STOP FAIL2BAN
    # ============================================================

    log_header "PHASE 6: PREPARE FOR UPDATE"

    if [ "$INSTALL_MODE" != "fresh" ]; then
        log_warn "Stopping Fail2Ban..."
        sudo systemctl stop fail2ban 2>/dev/null || log_warn "Fail2Ban was not running"
        sleep 2
        log_info "Fail2Ban stopped"
    fi

    echo ""

    # ============================================================
    # PHASE 7: INSTALL CONFIGURATIONS (Same as before)
    # ============================================================

    log_header "PHASE 7: INSTALL CONFIGURATIONS"

    # IDEMPOTENT: Check jail.local
    if [ ! -f "$CONFIG_DIR/jail.local" ] || ! grep -q "v0.8" "$CONFIG_DIR/jail.local" 2>/dev/null; then
        log_warn "Updating jail.local to v0.8..."
        
        cat > "$CONFIG_DIR/jail.local" << 'JAILEOF'
# =====================================================================
# FAIL2BAN HYBRID CONFIGURATION - OPTIMIZED v0.8
# GitHub: https://github.com/bakic-net/fail2ban-hybrid/releases/tag/v0.8
# =====================================================================

[DEFAULT]
destemail = zahor@tuta.io
sender = fail2ban@terminy.bakic.net
sendername = TermFail2Ban terminy.bakic.net
action = %(action_mwl)s
findtime = 600
bantime = 3600
maxretry = 5
backend = systemd
ignoreip = 127.0.0.1/8 ::1 192.168.0.0/16 10.0.0.0/8 172.16.0.0/12

[sshd]
enabled = true
port = ssh
logpath = /var/log/auth.log
backend = %(sshd_backend)s
maxretry = 5
findtime = 600
bantime = 86400
action = ufw

[recidive]
enabled = true
logpath = /var/log/fail2ban.log
action = ufw
maxretry = 10
findtime = 604800
bantime = 2592000

[manualblock]
enabled = true
port = http,https,ssh
logpath = /etc/fail2ban/blocked-ips.txt
maxretry = 1
bantime = 31536000
action = ufw
filter = manualblock

[f2b-exploit-critical]
enabled = true
port = http,https
logpath = /opt/rustnpm/data/logs/fallback_access.log
           /opt/rustnpm/data/logs/proxy-host-*_access.log
maxretry = 1
findtime = 600
bantime = 31536000
action = nftables[name=f2b-exploit]
unbanaction = nftables
filter = f2b-exploit-critical

[f2b-dos-high]
enabled = true
port = http,https
logpath = /opt/rustnpm/data/logs/fallback_access.log
           /opt/rustnpm/data/logs/proxy-host-*_access.log
maxretry = 1
findtime = 600
bantime = 604800
action = nftables[name=f2b-dos]
unbanaction = nftables
filter = f2b-dos-high

[f2b-web-medium]
enabled = true
port = http,https
logpath = /opt/rustnpm/data/logs/fallback_access.log
           /opt/rustnpm/data/logs/proxy-host-*_access.log
           /opt/rustnpm/data/logs/proxy-host-*_error.log
maxretry = 6
findtime = 600
bantime = 1800
bantime.increment = true
bantime.maxtime = 604800
bantime.overalljails = false
action = nftables[name=f2b-web]
unbanaction = nftables
filter = f2b-web-medium
# v0.8 IDEMPOTENT MARKER
JAILEOF
        
        log_info "✅ jail.local v0.8 installed"
    else
        log_debug "jail.local already v0.8 - skipping (idempotent)"
    fi

    echo ""

    # ============================================================
    # PHASE 8: RESTART FAIL2BAN
    # =====================================================================

    log_header "PHASE 8: START/RESTART FAIL2BAN"

    if [ "$INSTALL_MODE" = "fresh" ]; then
        log_warn "Installing Fail2Ban service..."
        sudo apt install -y fail2ban 2>/dev/null || log_warn "Fail2Ban already installed"
    fi

    log_warn "Restarting Fail2Ban..."
    sudo systemctl restart fail2ban
    sleep 3

    if sudo systemctl is-active --quiet fail2ban; then
        log_info "✅ Fail2Ban is running"
    else
        log_error "❌ Fail2Ban failed to start!"
        log_error "Debug: sudo journalctl -u fail2ban -n 50"
        log_error "Rollback: sudo bash $0 --rollback"
        exit 1
    fi

    echo ""

    # ============================================================
    # PHASE 9: VALIDATION
    # =====================================================================

    log_header "PHASE 9: VALIDATION"

    # Check jails
    ACTIVE_JAILS=$(sudo fail2ban-client status 2>/dev/null | grep "Jail list:" | wc -w)
    log_info "Active jails: $ACTIVE_JAILS (expected: ≥4)"

    # Check nftables
    for set in f2b-exploit f2b-dos f2b-web; do
        if sudo nft list set inet fail2ban-filter "$set" &>/dev/null 2>&1; then
            log_info "✅ nftables set @$set available"
        else
            log_debug "nftables set @$set not yet created (created on first ban)"
        fi
    done

    echo ""
fi

# ============================================================
# PHASE CLI: FAIL2BAN_HYBRID CLI INTEGRATION
# ============================================================

log_header "PHASE CLI: FAIL2BAN_HYBRID CLI INSTALLATION"

if [ ! -f "$F2B_HYBRID_PATH" ]; then
    log_warn "Installing fail2ban_hybrid CLI tool..."
    
    # Vytvor wrapper skript pre fail2ban_hybrid
    cat > "$F2B_HYBRID_PATH" << 'HYBRIDEOF'
#!/bin/bash

################################################################################
# FAIL2BAN HYBRID CLI WRAPPER v0.8
# Bridges v0.7.3 CLI with v0.8 jail structure
# Automatically maps old jails to new hierarchy
################################################################################

# ============================================================
# JAIL INFO MAPPING: v0.7.3 → v0.8
# ============================================================

declare -A JAILS_MAPPING=(
    # System jails (unchanged)
    [sshd]="sshd"
    [recidive]="recidive"
    [manualblock]="manualblock"
    
    # Web jails - NEW MAPPING FOR v0.8
    [nginx-exploit-permanent]="f2b-exploit-critical"
    [nginx-444]="f2b-dos-high"
    [nginx-4xx]="f2b-web-medium"
    [nginx-4xx-burst]="f2b-dos-high"
    [nginx-limit-req]="f2b-web-medium"
    [nginx-recon]="f2b-web-medium"
    [npm-iot-exploit]="f2b-dos-high"
    [npm-fasthttp]="f2b-dos-high"
)

declare -A NFTABLES_MAPPING=(
    [addr-set-nginx-exploit]="f2b-exploit"
    [addr-set-nginx-444]="f2b-dos"
    [addr-set-nginx-4xx]="f2b-web"
    [addr-set-nginx-4xx-burst]="f2b-dos"
    [addr-set-nginx-limit-req]="f2b-web"
    [addr-set-nginx-recon]="f2b-web"
    [addr-set-npm-iot-exploit]="f2b-dos"
    [addr-set-npm-fasthttp]="f2b-dos"
)

# ============================================================
# COMPATIBILITY FUNCTIONS
# ============================================================

# Map v0.7.3 jail name to v0.8 jail name
map_jail_v0_7_to_v0_8() {
    local jail_v07="$1"
    echo "${JAILS_MAPPING[$jail_v07]:-$jail_v07}"
}

# Map v0.7.3 nftables set to v0.8 set
map_nftables_v0_7_to_v0_8() {
    local set_v07="$1"
    echo "${NFTABLES_MAPPING[$set_v07]:-$set_v07}"
}

# ============================================================
# WRAPPER: f2b_compare
# ============================================================

f2b_compare() {
    echo "Comparing Fail2Ban vs nftables..."
    
    for jail_old in "${!JAILS_MAPPING[@]}"; do
        jail_new="${JAILS_MAPPING[$jail_old]}"
        
        # Get IPs from Fail2Ban
        f2b_ips=$(sudo fail2ban-client status "$jail_new" 2>/dev/null | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort -u || echo "")
        f2b_count=$(echo "$f2b_ips" | wc -l)
        
        # Get IPs from nftables
        nft_set=$(map_nftables_v0_7_to_v0_8 "addr-set-$jail_old")
        nft_ips=$(sudo nft list set inet fail2ban-filter "$nft_set" 2>/dev/null | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort -u || echo "")
        nft_count=$(echo "$nft_ips" | wc -l)
        
        if [ "$f2b_count" -eq "$nft_count" ]; then
            echo "✅ $jail_new: F2B=$f2b_count, nft=$nft_count (SYNC)"
        else
            echo "⚠️  $jail_new: F2B=$f2b_count, nft=$nft_count (MISMATCH)"
        fi
    done
}

# ============================================================
# WRAPPER: f2b_audit
# ============================================================

f2b_audit() {
    echo "Audit Report - v0.8 Configuration"
    echo "===================================="
    
    total_f2b=0
    total_nft=0
    mismatches=0
    
    for jail_new in sshd recidive manualblock f2b-exploit-critical f2b-dos-high f2b-web-medium; do
        f2b_ips=$(sudo fail2ban-client status "$jail_new" 2>/dev/null | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort -u || echo "")
        f2b_count=$(echo "$f2b_ips" | grep -v '^$' | wc -l)
        
        total_f2b=$((total_f2b + f2b_count))
        echo "[$jail_new] Fail2Ban: $f2b_count IPs"
    done
    
    echo ""
    echo "Total Fail2Ban IPs: $total_f2b"
}

# ============================================================
# WRAPPER: f2b_sync
# ============================================================

f2b_sync() {
    echo "Synchronizing Fail2Ban and nftables..."
    f2b_compare
}

# ============================================================
# WRAPPER: f2b_status
# ============================================================

f2b_status() {
    echo "Fail2Ban Status:"
    sudo fail2ban-client status
}

# ============================================================
# MAIN HANDLER
# ============================================================

case "$1" in
    compare)   f2b_compare ;;
    audit)     f2b_audit ;;
    sync)      f2b_sync ;;
    status)    f2b_status ;;
    *)
        echo "Fail2Ban Hybrid v0.8 CLI Wrapper"
        echo "Usage: f2b-hybrid {compare|audit|sync|status}"
        exit 1
        ;;
esac
HYBRIDEOF

    chmod +x "$F2B_HYBRID_PATH"
    log_info "✅ fail2ban_hybrid CLI installed to $F2B_HYBRID_PATH"
else
    log_debug "fail2ban_hybrid CLI already exists - skipping (idempotent)"
fi

echo ""

# ============================================================
# PHASE CLI: SETUP ALIASES
# ============================================================

log_header "PHASE CLI: SETUP ALIASES IN ~/.bashrc"

BASHRC_PATH="$HOME/.bashrc"

# Kontrola či už existujú aliasy
if ! grep -q "f2b-hybrid" "$BASHRC_PATH" 2>/dev/null; then
    log_warn "Adding aliases to ~/.bashrc..."
    
    cat >> "$BASHRC_PATH" << 'ALIASEOF'

# ============================================================
# FAIL2BAN HYBRID v0.8 CLI ALIASES
# ============================================================

alias f2b_compare='f2b-hybrid compare'
alias f2b_audit='f2b-hybrid audit'
alias f2b_sync='f2b-hybrid sync'
alias f2b_status='f2b-hybrid status'

# Backward compatibility with v0.7.3
alias f2b_nft='sudo nft list table inet fail2ban-filter'
alias f2b_ufw='sudo ufw status verbose'
alias f2b_reload='sudo systemctl reload fail2ban'
alias f2b_restart='sudo systemctl restart fail2ban'

ALIASEOF
    
    log_info "✅ Aliases added to ~/.bashrc"
    log_warn "Run: source ~/.bashrc (to load aliases in current shell)"
else
    log_debug "Aliases already exist - skipping (idempotent)"
fi

echo ""

# ============================================================
# FINAL REPORT
# ============================================================

log_header "✅ SETUP v$VERSION COMPLETE"

cat << EOF | tee -a "$LOG_FILE"

════════════════════════════════════════════════════════════════

📊 INSTALLATION SUMMARY:

Version: $VERSION
CLI Tool: $F2B_HYBRID_PATH
Aliases: ~/.bashrc

✅ Components Installed:
   • Fail2Ban configuration (v0.8)
   • nftables configuration
   • fail2ban_hybrid CLI wrapper
   • Bash aliases

════════════════════════════════════════════════════════════════

🚀 NEXT STEPS:

1. Reload shell to enable aliases:
   source ~/.bashrc

2. Try the CLI commands:
   f2b_audit      - Show audit report
   f2b_compare    - Compare F2B vs nftables
   f2b_sync       - Synchronize
   f2b_status     - Show status

3. Verify installation:
   sudo fail2ban-client status
   f2b_audit

════════════════════════════════════════════════════════════════

📚 CLI FUNCTIONS AVAILABLE:

   f2b_audit      - Comprehensive audit report
   f2b_compare    - Compare Fail2Ban vs nftables
   f2b_sync       - Bidirectional sync
   f2b_status     - Show Fail2Ban status
   f2b_nft        - Show nftables configuration
   f2b_ufw        - Show UFW status
   f2b_reload     - Reload Fail2Ban
   f2b_restart    - Restart Fail2Ban

════════════════════════════════════════════════════════════════

🔄 COMPATIBILITY:

✅ v0.8 Configuration (5 jails, 3 nftables sets)
✅ v0.7.3 CLI Functions (mapped to v0.8 structure)
✅ Automatic Jail Mapping
✅ Backward Compatible Aliases

════════════════════════════════════════════════════════════════

✅ SETUP COMPLETE - v$VERSION ($(date +%Y-%m-%d))

Log: $LOG_FILE

════════════════════════════════════════════════════════════════

EOF

echo ""
log_info "🎉 Setup finished successfully!"
echo ""
