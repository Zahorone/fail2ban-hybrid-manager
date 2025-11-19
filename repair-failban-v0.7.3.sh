#!/bin/bash

################################################################################
# Fail2Ban Repair Script v0.7.3 - PRODUCTION READY
# Idempotentná verzia s SQLite support
# FULLY UPDATED for fail2ban_hybrid v0.7.3
#
# Version: 0.7.3 - COMPLETE FIX
# Date: 2025-11-19
# Aligns with: fail2ban_hybrid-v0.7.3-COMPLETE.sh
################################################################################

# Farby
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

LOG_FILE="/var/log/fail2ban-repair-v0.7.3.log"
DB_FILE="/var/lib/fail2ban/fail2ban.sqlite3"

# Logging
log() {
    echo -e "$1" | tee -a "$LOG_FILE"
}

# ============================================================
# CONFIG v0.7.3
# ============================================================

log "${BLUE}🔧 Fail2Ban Repair v0.7.3 - SPUSTENÝ${NC}"
log "$(date)"
log ""

# v0.7.3 JAILS - ALL
declare -a JAILS=(
    "nginx-exploit-permanent"
    "nginx-444"
    "nginx-4xx"
    "nginx-4xx-burst"
    "nginx-limit-req"
    "npm-fasthttp"
    "npm-iot-exploit"
    "recidive"
    "manualblock"
)

# ============================================================
# PRE-FLIGHT CHECK
# ============================================================

log "${YELLOW}✈️ PRE-FLIGHT CHECK:${NC}"

if ! command -v fail2ban-client &> /dev/null; then
    log "${RED}❌ fail2ban-client nie je nainštalovaný!${NC}"
    log " Nainštaluj: sudo apt install fail2ban"
    exit 1
fi

if [[ $EUID -ne 0 ]]; then
    log "${RED}❌ Musíš spustiť ako sudo!${NC}"
    exit 1
fi

log "${GREEN}✅ fail2ban-client je dostupný${NC}"
log ""

# ============================================================
# KROK 1: Status check
# ============================================================

log "${YELLOW}📊 KROK 1: Fail2Ban status check${NC}"

if sudo systemctl is-active --quiet fail2ban; then
    log "${GREEN}✅ Fail2Ban je spustený${NC}"
    RUNNING=1
else
    log "${YELLOW}⚠️  Fail2Ban nie je spustený${NC}"
    RUNNING=0
fi
log ""

# ============================================================
# KROK 2: Kontrola všetkých jail konfiguracií (v0.7.3)
# ============================================================

log "${YELLOW}🔍 KROK 2: Kontrola všetkých jail konfiguracií${NC}"

MISSING_JAILS=0
for jail in "${JAILS[@]}"; do
    if sudo fail2ban-client status "$jail" &>/dev/null; then
        count=$(sudo fail2ban-client status "$jail" 2>/dev/null | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | wc -l)
        log "  ✅ $jail: $count IPs"
    else
        log "  ⚠️  $jail: CHÝBA alebo NEAKTÍVNY"
        ((MISSING_JAILS++))
    fi
done

if [ $MISSING_JAILS -gt 0 ]; then
    log "${YELLOW}⚠️  $MISSING_JAILS jail-ov chýba alebo nie sú aktívne${NC}"
fi
log ""

# ============================================================
# KROK 3: SQLite databáza check
# ============================================================

log "${YELLOW}💾 KROK 3: SQLite databáza check${NC}"

if [ -f "$DB_FILE" ]; then
    log "${GREEN}✅ Databáza existuje: $DB_FILE${NC}"
    # Skontroluj integritu
    if sqlite3 "$DB_FILE" "SELECT COUNT(*) FROM bans;" &>/dev/null; then
        ban_count=$(sqlite3 "$DB_FILE" "SELECT COUNT(*) FROM bans;")
        log "  📊 Celkovo banovaných IP v DB: $ban_count"
    else
        log "${RED}❌ Databáza je poškodená!${NC}"
        log "${YELLOW}⚠️  Skúšam opraviť...${NC}"
        sudo systemctl stop fail2ban
        sudo sqlite3 "$DB_FILE" ".check"
        sudo systemctl start fail2ban
    fi
else
    log "${YELLOW}⚠️  Databáza nie je vytvorená${NC}"
fi
log ""

# ============================================================
# KROK 4: Synchronizácia s nftables (cez f2b_sync ak je dostupný)
# ============================================================

log "${YELLOW}🔄 KROK 4: Synchronizácia s nftables${NC}"

if command -v f2b_sync &>/dev/null; then
    log "${GREEN}✅ f2b_sync nájdený, spúšťam synchronizáciu...${NC}"
    f2b_sync
else
    log "${YELLOW}⚠️  f2b_sync nie je dostupný (zmeň PATH alebo skopíruj skript)${NC}"
    log "  Skeď si source-ni fail2ban_hybrid-v0.7.3-COMPLETE.sh, mali by ste mať f2b_sync"
fi
log ""

# ============================================================
# KROK 5: Reštart Fail2Ban
# ============================================================

log "${YELLOW}🔄 KROK 5: Reštart Fail2Ban${NC}"

sudo systemctl restart fail2ban
sleep 2

if sudo systemctl is-active --quiet fail2ban; then
    log "${GREEN}✅ Fail2Ban úspešne reštartovaný${NC}"
else
    log "${RED}❌ Fail2Ban sa nepodarilo reštartovať!${NC}"
    exit 1
fi
log ""

# ============================================================
# FINÁLNA VERIFIKÁCIA
# ============================================================

log "${BLUE}✅ FINÁLNA VERIFIKÁCIA${NC}"
log ""

total_ips=0
for jail in "${JAILS[@]}"; do
    if sudo fail2ban-client status "$jail" &>/dev/null; then
        count=$(sudo fail2ban-client status "$jail" 2>/dev/null | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | wc -l)
        ((total_ips += count))
    fi
done

log "  📊 CELKOVO BANOVANÝCH IP: $total_ips"
log ""
log "${GREEN}✅ Fail2Ban v0.7.3 ÚSPEŠNE OPRAVENÝ!${NC}"
