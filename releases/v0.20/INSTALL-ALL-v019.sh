#!/bin/bash
################################################################################
# Fail2Ban + nftables Production Setup v0.19
# Master Installer with docker-block v0.3 support
#
# Changes in v0.19:
#   - F2B wrapper v0.19 with enhanced monitoring
#   - Lock mechanism for safe concurrent operations
#   - Port and IP validation
#   - Attack trend analysis
#   - Jail log filtering
#   - JSON/CSV export reports
#   - Persistent logging to /var/log/f2b-wrapper.log
#   - Historical top attackers tracking
#
# Prerequisites:
#   - Ubuntu/Debian system
#   - sudo privileges
#   - Internet connection
################################################################################

set -e

VERSION="0.19"
DOCKER_BLOCK_VERSION="0.3"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'

# Logging
log() { echo -e "${GREEN}[$(date +'%H:%M:%S')]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; }
warning() { echo -e "${YELLOW}[WARN]${NC} $1"; }
info() { echo -e "${BLUE}[INFO]${NC} $1"; }
highlight() { echo -e "${CYAN}[NEW]${NC} $1"; }

# Banner
clear
echo ""
echo "╔════════════════════════════════════════════════════════════╗"
echo "║                                                            ║"
echo "║   Fail2Ban + nftables Production Setup v${VERSION}         ║"
echo "║   (Hybrid Firewall + docker-block v${DOCKER_BLOCK_VERSION} + F2B Wrapper)   ║"
echo "║                                                            ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

# Root check
if [ "$EUID" -ne 0 ]; then
    error "Please run with sudo: sudo bash $0"
    exit 1
fi

# Check for required scripts
REQUIRED_SCRIPTS=(
    "01-install-nftables.sh"
    "02-install-jails.sh"
    "03-install-docker-block-v03.sh"
    "04-install-wrapper-v019.sh"
    "05-install-auto-sync.sh"
    "06-install-aliases.sh"
)

info "Checking for required installation scripts..."
MISSING_SCRIPTS=()

for script in "${REQUIRED_SCRIPTS[@]}"; do
    if [ ! -f "$SCRIPT_DIR/$script" ]; then
        MISSING_SCRIPTS+=("$script")
        error "Missing: $script"
    else
        log "Found: $script"
    fi
done

if [ ${#MISSING_SCRIPTS[@]} -gt 0 ]; then
    echo ""
    error "Missing ${#MISSING_SCRIPTS[@]} required script(s)"
    error "Please ensure all scripts are in: $SCRIPT_DIR"
    exit 1
fi

echo ""
info "All required scripts found!"
echo ""

# Confirmation
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
warning "This installer will:"
echo "  • Install and configure nftables for Fail2Ban"
echo "  • Setup 10 production jails"
echo "  • Configure docker-block v${DOCKER_BLOCK_VERSION} (localhost exception)"
echo "  • Install F2B wrapper v${VERSION}"
echo "  • Enable auto-sync systemd timer"
echo "  • Create bash aliases for management"
echo ""
highlight "NEW in v${VERSION}:"
echo "  ✅ Lock mechanism - prevents concurrent operation conflicts"
echo "  ✅ Input validation - port and IP address validation"
echo "  ✅ Attack trends - analyze attack patterns over time"
echo "  ✅ Jail log filter - view specific jail activity logs"
echo "  ✅ JSON/CSV export - export reports for external tools"
echo "  ✅ Enhanced top attackers - historical tracking from logs"
echo "  ✅ Persistent logging - all operations logged to /var/log/f2b-wrapper.log"
echo ""
info "Previous features (v0.18):"
echo "  ✅ docker-block v${DOCKER_BLOCK_VERSION} - External blocking with localhost access"
echo "  ✅ F2B wrapper - kompletné core/manage/monitor/sync funkcie"
echo "  ✅ SSH port forwarding support pre admin porty"
echo ""
warning "Recommendation: Run pre-cleanup first!"
echo "  sudo bash ~/00-pre-cleanup-v015.sh"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

read -p "Continue with installation? (yes/no): " -r
echo ""

if [[ ! $REPLY =~ ^[Yy]es$ ]]; then
    warning "Installation cancelled by user"
    exit 0
fi

# Start installation
START_TIME=$(date +%s)
log "Installation started at $(date +%Y-%m-%d-%H:%M:%S)"
echo ""

# Create log
LOG_FILE="/tmp/f2b-install-v${VERSION}-$(date +%Y%m%d-%H%M%S).log"
exec > >(tee -a "$LOG_FILE") 2>&1

# Installation steps
STEPS=(
    "02-install-jails.sh|Fail2Ban Jails Setup"
    "01-install-nftables.sh|nftables Configuration"
    "03-install-docker-block-v03.sh|Docker Port Blocking v${DOCKER_BLOCK_VERSION}"
    "04-install-wrapper-v019.sh|F2B Wrapper v${VERSION} Installation"
    "05-install-auto-sync.sh|Auto-Sync Configuration"
    "06-install-aliases.sh|Bash Aliases Setup"
)

TOTAL_STEPS=${#STEPS[@]}
CURRENT_STEP=0
FAILED_STEPS=()

for step_info in "${STEPS[@]}"; do
    CURRENT_STEP=$((CURRENT_STEP + 1))
    SCRIPT_NAME="${step_info%%|*}"
    STEP_DESC="${step_info##*|}"

    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    log "STEP ${CURRENT_STEP}/${TOTAL_STEPS}: ${STEP_DESC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""

    if bash "$SCRIPT_DIR/$SCRIPT_NAME"; then
        log "✅ ${STEP_DESC} - SUCCESS"
    else
        error "❌ ${STEP_DESC} - FAILED"
        FAILED_STEPS+=("$STEP_DESC")

        echo ""
        read -p "Continue despite error? (yes/no): " -r
        if [[ ! $REPLY =~ ^[Yy]es$ ]]; then
            error "Installation aborted at step ${CURRENT_STEP}/${TOTAL_STEPS}"
            exit 1
        fi
    fi

    sleep 1
done

# Time
END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))
MINUTES=$((DURATION / 60))
SECONDS=$((DURATION % 60))

# Summary
echo ""
echo ""
echo "╔════════════════════════════════════════════════════════════╗"
echo "║                                                            ║"
echo "║              🎉 INSTALLATION COMPLETE! 🎉                  ║"
echo "║                                                            ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

if [ ${#FAILED_STEPS[@]} -eq 0 ]; then
    log "✅ All ${TOTAL_STEPS} steps completed successfully!"
else
    warning "⚠️  Completed with ${#FAILED_STEPS[@]} warning(s):"
    for failed in "${FAILED_STEPS[@]}"; do
        echo "   - $failed"
    done
fi

echo ""
info "Installation time: ${MINUTES}m ${SECONDS}s"
info "Installation log: $LOG_FILE"
echo ""

# Post-installation checks
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
log "Running post-installation checks..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

echo "📊 Service Status:"
systemctl is-active --quiet nftables && echo "  ✅ nftables: active" || echo "  ❌ nftables: inactive"
systemctl is-active --quiet fail2ban && echo "  ✅ fail2ban: active" || echo "  ❌ fail2ban: inactive"
systemctl is-active --quiet ufw && echo "  ✅ ufw: active" || echo "  ⚠️  ufw: inactive"
systemctl is-active --quiet f2b-nft-sync.timer && echo "  ✅ f2b-sync: active" || echo "  ⚠️  f2b-sync: inactive"

echo ""
echo "📋 NFT Tables:"
nft list tables 2>/dev/null | grep -E "fail2ban|docker-block" || echo "  ⚠️  No tables found"

echo ""
echo "🔧 F2B Wrapper:"
if [ -x /usr/local/bin/f2b ]; then
    echo "  ✅ Installed: /usr/local/bin/f2b"
    /usr/local/bin/f2b version 2>/dev/null || true
else
    echo "  ❌ Not found: /usr/local/bin/f2b"
fi

echo ""
echo "📁 Log Files:"
[ -f /var/log/f2b-wrapper.log ] && echo "  ✅ Main log: /var/log/f2b-wrapper.log" || echo "  ❌ Main log: missing"
[ -f /var/log/f2b-sync.log ] && echo "  ✅ Sync log: /var/log/f2b-sync.log" || echo "  ⚠️  Sync log: missing"
[ -f /var/log/f2b-audit.log ] && echo "  ✅ Audit log: /var/log/f2b-audit.log" || echo "  ⚠️  Audit log: missing"

echo ""
echo "🐋 docker-block v${DOCKER_BLOCK_VERSION}:"
if nft list table inet docker-block &>/dev/null; then
    echo "  ✅ Active (external blocking, localhost allowed)"
    nft list set inet docker-block docker-blocked-ports 2>/dev/null | grep elements | sed 's/^/     /' || echo "     No blocked ports"
else
    echo "  ❌ Not configured"
fi

echo ""
echo "🛡️  Fail2Ban Jails:"
fail2ban-client status 2>/dev/null | grep "Jail list" || echo "  ⚠️  Could not retrieve jail list"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
log "Next Steps"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "1. Reload your bash environment:"
echo "   source ~/.bashrc"
echo ""
echo "2. Check system status:"
echo "   f2b status"
echo "   # or with alias:"
echo "   f2b-status"
echo ""
echo "3. Verify docker-block v${DOCKER_BLOCK_VERSION}:"
echo "   f2b manage docker-info"
echo "   # or:"
echo "   f2b-docker"
echo ""
echo "4. Monitor Fail2Ban activity:"
echo "   f2b monitor watch"
echo "   # or:"
echo "   f2b-watch"
echo ""
highlight "5. NEW v${VERSION} features:"
echo "   # Attack trend analysis"
echo "   f2b monitor trends"
echo "   f2b-trends"
echo ""
echo "   # View jail logs"
echo "   f2b monitor jail-log sshd 50"
echo "   f2b-log sshd 50"
echo ""
echo "   # Export reports"
echo "   f2b report json > /tmp/f2b-report.json"
echo "   f2b report csv > /tmp/f2b-report.csv"
echo "   f2b-json > /tmp/report.json"
echo ""
echo "   # Quick stats"
echo "   f2b stats-quick"
echo "   f2b-quick"
echo ""
echo "6. Full command reference:"
echo "   f2b help"
echo ""
echo "7. Review logs:"
echo "   tail -f /var/log/f2b-wrapper.log"
echo "   tail -f /var/log/fail2ban.log"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
log "Installation v${VERSION} completed at $(date +'%Y-%m-%d %H:%M:%S')"
echo ""

# Feature highlights
echo "╔════════════════════════════════════════════════════════════╗"
echo "║              v${VERSION} FEATURE HIGHLIGHTS                    ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""
highlight "🔒 Lock Mechanism"
echo "   Prevents concurrent operations from conflicting"
echo ""
highlight "✅ Input Validation"
echo "   Validates port numbers (1-65535) and IP addresses"
echo ""
highlight "📊 Attack Trends"
echo "   Analyze attack patterns: last hour, 6h, 24h"
echo "   f2b monitor trends"
echo ""
highlight "📝 Jail Logs"
echo "   Filter logs by specific jail"
echo "   f2b monitor jail-log <jail> [lines]"
echo ""
highlight "💾 Export Reports"
echo "   JSON: f2b report json"
echo "   CSV:  f2b report csv"
echo "   Daily: f2b report daily"
echo ""
highlight "🎯 Enhanced Top Attackers"
echo "   Historical tracking from fail2ban logs"
echo "   f2b monitor top-attackers"
echo ""
highlight "📁 Persistent Logging"
echo "   All operations logged to /var/log/f2b-wrapper.log"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Quick test
info "Running quick functionality test..."
echo ""

if /usr/local/bin/f2b version &>/dev/null; then
    log "✅ F2B wrapper is functional"
else
    warning "⚠️  F2B wrapper test failed"
fi

if [ -f ~/.bashrc ] && grep -q "F2B Wrapper Aliases v${VERSION}" ~/.bashrc 2>/dev/null; then
    log "✅ Bash aliases installed"
else
    warning "⚠️  Bash aliases not detected (run: source ~/.bashrc)"
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
info "For support and detailed logs, review:"
echo "  Installation: $LOG_FILE"
echo "  Wrapper logs: /var/log/f2b-wrapper.log"
echo "  Fail2Ban:     /var/log/fail2ban.log"
echo ""
log "Thank you for using F2B Wrapper v${VERSION}!"
echo ""
echo "Report issues: https://github.com/yourusername/f2b-wrapper"
echo ""

