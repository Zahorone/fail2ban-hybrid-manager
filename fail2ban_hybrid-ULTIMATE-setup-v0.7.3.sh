#!/bin/bash

################################################################################
# FAIL2BAN HYBRID MANAGEMENT - ULTIMATE SETUP v0.7.3
# Complete Installer & Configuration Tool
# FULLY UPDATED for fail2ban_hybrid v0.7.3
#
# Features:
# - Automatic installation to /usr/local/bin/f2b-hybrid
# - Aliases setup in ~/.bashrc
# - Cron job setup (silent monitoring + sync)
# - Email notifications (optional)
# - v0.7.3 with f2b_monitor, f2b_sync_silent, f2b_ban_incremental
#
# Usage: sudo bash fail2ban_hybrid-ULTIMATE-setup-v0.7.3.sh
#
# Version: 0.7.3
# Date: 2025-11-19
################################################################################

set -e

# ============================================================
# CONFIG
# ============================================================

SCRIPT_NAME="fail2ban_hybrid-v0.7.3-COMPLETE.sh"
INSTALL_PATH="/usr/local/bin/f2b-hybrid"
BASHRC_PATH="$HOME/.bashrc"
CRON_MONITOR="/etc/cron.d/f2b-monitor"
CRON_SYNC="/etc/cron.d/f2b-sync"
EMAIL="zahor@tuta.io"

# Farby
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# ============================================================
# HELPERS
# ============================================================

log_info() {
    echo -e "${GREEN}✅ ${1}${NC}"
}

log_warn() {
    echo -e "${YELLOW}⚠️  ${1}${NC}"
}

log_error() {
    echo -e "${RED}❌ ${1}${NC}"
}

log_header() {
    echo -e "${CYAN}${1}${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

# ============================================================
# BANNER
# ============================================================

clear
cat << 'EOF'
╔═══════════════════════════════════════════════════════════════╗
║  🛡️ FAIL2BAN HYBRID ULTIMATE SETUP v0.7.3 🛡️              ║
║                                                              ║
║  Installation & Configuration Tool                         ║
║  GitHub Production Ready                                    ║
║                                                              ║
╚═══════════════════════════════════════════════════════════════╝
EOF

echo ""

# ============================================================
# PRE-FLIGHT CHECK
# ============================================================

log_header "PRE-FLIGHT CHECKS"

if [[ $EUID -ne 0 ]]; then
    log_error "CHYBA: Musíš spustiť ako sudo!"
    log_error "Príkaz: sudo bash $0"
    exit 1
fi

log_info "Running as root"

if [ ! -f "$SCRIPT_NAME" ]; then
    log_error "CHYBA: $SCRIPT_NAME neexistuje v aktuálnom adresári!"
    log_warn "Umiestnite skript do rovnakého adresára ako setup"
    exit 1
fi

log_info "Script $SCRIPT_NAME nájdený"
echo ""

# ============================================================
# KROK 1: INŠTALÁCIA
# ============================================================

log_header "KROK 1: INŠTALÁCIA"

log_warn "Inštalujem $SCRIPT_NAME do $INSTALL_PATH..."

sudo cp "$SCRIPT_NAME" "$INSTALL_PATH"
sudo chmod +x "$INSTALL_PATH"

log_info "Nainštalovaný: $INSTALL_PATH"
echo ""

# ============================================================
# KROK 2: BASHRC ALIASES
# ============================================================

log_header "KROK 2: BASHRC ALIASES"

# Kontrola či už nie sú aliases
if ! grep -q "alias f2b-hybrid=" "$BASHRC_PATH" 2>/dev/null; then
    cat >> "$BASHRC_PATH" << 'EOF'

# ============================================================
# FAIL2BAN HYBRID v0.7.3 ALIASES
# ============================================================

alias f2b-hybrid='$INSTALL_PATH'
alias f2b_compare='$INSTALL_PATH compare'
alias f2b_audit='$INSTALL_PATH audit'
alias f2b_sync='$INSTALL_PATH sync'
alias f2b_monitor='$INSTALL_PATH monitor'
alias f2b_sync_silent='$INSTALL_PATH sync-silent'
alias f2b_ban_incremental='$INSTALL_PATH ban-incremental'
alias f2b_stats='$INSTALL_PATH stats'
alias f2b_find='$INSTALL_PATH find'
alias f2b_status='$INSTALL_PATH status'
alias f2b_restart='$INSTALL_PATH restart'
alias f2b_reload='$INSTALL_PATH reload'
alias f2b_log='$INSTALL_PATH log'

EOF
    log_info "Aliases pridané do ~/.bashrc"
else
    log_warn "Aliases sú už v ~/.bashrc"
fi

echo ""

# ============================================================
# KROK 3: CRON MONITORING
# ============================================================

log_header "KROK 3: CRON SETUP (Silent Monitoring)"

read -p "Chceš nastaviť monitoring s cron (y/n)? " -n 1 -r
echo ""

if [[ $REPLY =~ ^[Yy]$ ]]; then
    # Monitoring cron (*/30 * * * * - len alert pri MISMATCH)
    echo "*/30 * * * * root $INSTALL_PATH monitor >> /var/log/f2b_cron_monitor.log 2>&1" | \
        sudo tee "$CRON_MONITOR" > /dev/null
    log_info "Cron monitoring nastavený: */30 * * * *"
    
    # Sync cron (0 * * * * - len hlás keď je zmena)
    echo "0 * * * * root $INSTALL_PATH sync-silent >> /var/log/f2b_cron_sync.log 2>&1" | \
        sudo tee "$CRON_SYNC" > /dev/null
    log_info "Cron sync-silent nastavený: 0 * * * *"
else
    log_warn "Cron setup preskočený"
fi

echo ""

# ============================================================
# KROK 4: EMAIL NOTIFIKÁCIE
# ============================================================

log_header "KROK 4: EMAIL NOTIFIKÁCIE (VOLITEĽNE)"

read -p "Chceš nastaviť email notifikácie (y/n)? " -n 1 -r
echo ""

if [[ $REPLY =~ ^[Yy]$ ]]; then
    read -p "Zadaj email adresu [$EMAIL]: " USER_EMAIL
    EMAIL="${USER_EMAIL:-$EMAIL}"
    
    log_warn "MANUÁLNA AKTUALIZÁCIA POTREBNÁ:"
    log_warn "1. Otvor: $INSTALL_PATH"
    log_warn "2. Nájdi: # Uncomment pre mail notifikáciu:"
    log_warn "3. Odkomentuj riadky pre mail a nastav:"
    log_warn "   echo ... | mail -s '...' $EMAIL"
    echo ""
else
    log_warn "Email notifikácie preskočené"
fi

echo ""

# ============================================================
# KROK 5: FINÁLNY STATUS
# ============================================================

log_header "✅ INŠTALÁCIA HOTOVÁ!"

echo ""
echo "📋 Nasledujúce príkazy sú dostupné:"
echo ""
echo "  Core functions:"
echo "    f2b_compare        - Porovnaj F2B vs nftables"
echo "    f2b_audit          - Komplexný audit"
echo "    f2b_sync           - Bidirekcná synchronizácia"
echo ""
echo "  Silent Monitoring (nové v0.7.3):"
echo "    f2b_monitor        - Tichý audit, hlási len pri MISMATCH"
echo "    f2b_sync_silent    - Tichý sync, hlási len pri zmene"
echo "    f2b_ban_incremental - Inkrementálna história banov"
echo ""
echo "  Utilities:"
echo "    f2b_status         - Status check"
echo "    f2b_restart        - Restartuj Fail2Ban"
echo "    f2b_reload         - Reload Fail2Ban"
echo "    f2b_stats          - Štatistika"
echo ""
echo "🚀 Začni s:"
echo "  source ~/.bashrc && f2b_audit"
echo ""

# ============================================================
# VERIFICATION
# ============================================================

log_header "VERIFIKÁCIA"

if [ -f "$INSTALL_PATH" ]; then
    log_info "✅ $INSTALL_PATH nainštalovaný"
else
    log_error "❌ Inštalácia zlyhala!"
    exit 1
fi

# Test
if bash "$INSTALL_PATH" help > /dev/null 2>&1; then
    log_info "✅ Help príkaz funguje"
else
    log_error "❌ Skript nie je funkčný!"
    exit 1
fi

echo ""
log_info "🎉 SETUP ÚSPEŠNÝ! v0.7.3 je PRIPRAVENÝ!"
echo ""
