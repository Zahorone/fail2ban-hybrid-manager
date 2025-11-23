#!/bin/bash

################################################################################
# FAIL2BAN HYBRID REPAIR KIT v0.7.3 - MASTER ORCHESTRATOR
# Spúšťa všetky repair skripty v správnom poradí
# FULLY UPDATED for fail2ban_hybrid v0.7.3
#
# Version: 0.7.3 - COMPLETE
# Date: 2025-11-19
# Aligns with: fail2ban_hybrid-v0.7.3-COMPLETE.sh
################################################################################

# Farby
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Cesty
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="/var/log"

# Skripty na spustenie v0.7.3
REPAIR_NFTABLES="$SCRIPT_DIR/repair-nftables-v0.7.3.sh"
REPAIR_FAILBAN="$SCRIPT_DIR/repair-failban-v0.7.3.sh"

# ============================================================
# BANNER
# ============================================================

clear

echo -e "${CYAN}"
cat << 'EOF'

╔══════════════════════════════════════════════════════════════╗
║ 🚀 FAIL2BAN HYBRID REPAIR KIT v0.7.3 - MASTER 🚀 ║
║ ║
║ ✅ NFTables v0.7.3 │ ✅ Fail2Ban v0.7.3 ║
║ ✅ Silent Monitoring │ ✅ Incremental Bans ║
║ ✅ Production Ready │ ✅ GitHub Ready ║
║ ║
╚══════════════════════════════════════════════════════════════╝

EOF
echo -e "${NC}"

# ============================================================
# PRE-FLIGHT CHECK
# ============================================================

log() {
    echo -e "$1"
}

log "${YELLOW}🔍 PRE-FLIGHT CHECKS:${NC}"
log ""

if [[ $EUID -ne 0 ]]; then
    log "${RED}❌ CHYBA: Musíš spustiť ako sudo!${NC}"
    log "  Príkaz: sudo bash $0"
    exit 1
fi

log "${GREEN}✅ Spustený ako sudo${NC}"

if [ ! -f "$REPAIR_NFTABLES" ]; then
    log "${RED}❌ CHYBA: $REPAIR_NFTABLES neexistuje!${NC}"
    exit 1
fi

log "${GREEN}✅ repair-nftables-v0.7.3.sh nájdený${NC}"

if [ ! -f "$REPAIR_FAILBAN" ]; then
    log "${RED}❌ CHYBA: $REPAIR_FAILBAN neexistuje!${NC}"
    exit 1
fi

log "${GREEN}✅ repair-failban-v0.7.3.sh nájdený${NC}"

log ""

# ============================================================
# KROK 1: nftables REPAIR
# ============================================================

log "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
log "${BLUE}STEP 1/2: nftables REPAIR (v0.7.3)${NC}"
log "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
log ""

bash "$REPAIR_NFTABLES"

if [ $? -ne 0 ]; then
    log "${RED}❌ nftables repair ZLYHAL!${NC}"
    exit 1
fi

log ""
log "${GREEN}✅ nftables repair ÚSPEŠNÝ${NC}"
log ""

sleep 2

# ============================================================
# KROK 2: FAIL2BAN REPAIR
# ============================================================

log "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
log "${BLUE}STEP 2/2: FAIL2BAN REPAIR (v0.7.3)${NC}"
log "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
log ""

bash "$REPAIR_FAILBAN"

if [ $? -ne 0 ]; then
    log "${RED}❌ Fail2Ban repair ZLYHAL!${NC}"
    exit 1
fi

log ""
log "${GREEN}✅ Fail2Ban repair ÚSPEŠNÝ${NC}"
log ""

# ============================================================
# FINÁLNY STATUS
# ============================================================

log "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
log "${BLUE}📊 FINÁLNY STATUS${NC}"
log "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
log ""

log "nftables:"
sudo nft list table inet f2b-table 2>/dev/null | head -5

log ""
log "Fail2Ban jails:"
sudo fail2ban-client status 2>/dev/null | grep -E "Currently|jail:" | head -10

log ""
log "${GREEN}✅ REPAIR KOMPLETNÝ - v0.7.3 JE PRIPRAVENÝ!${NC}"
log ""
log "Ďalší krok: source ~/.bashrc && f2b_audit"
log ""
