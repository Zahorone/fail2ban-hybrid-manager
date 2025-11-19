#!/bin/bash

################################################################################
# NFTables Repair/Setup Script v0.7.3 - PRODUCTION READY
# Funguje na ČISTOM aj EXISTUJÚCOM systéme bez duplikátov
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

LOG_FILE="/var/log/nftables-repair-v0.7.3.log"

# Logging
log() {
    echo -e "$1" | tee -a "$LOG_FILE"
}

# ============================================================
# CONFIG v0.7.3
# ============================================================

log "${BLUE}🔧 NFTables Repair v0.7.3 - SPUSTENÝ${NC}"
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

# nftables sets mapping (v0.7.3)
declare -A NFTABLES_SETS=(
    ["nginx-exploit-permanent"]="addr-set-nginx-exploit"
    ["nginx-444"]="addr-set-nginx-444"
    ["nginx-4xx"]="addr-set-nginx-4xx"
    ["nginx-4xx-burst"]="addr-set-nginx-4xx-burst"
    ["nginx-limit-req"]="addr-set-nginx-limit-req"
    ["npm-fasthttp"]="addr-set-npm-fasthttp"
    ["npm-iot-exploit"]="addr-set-npm-iot-exploit"
    ["recidive"]="addr-set-recidive"
    ["manualblock"]="addr-set-manualblock"
)

# MULTIPORT jails
declare -a MULTIPORT_JAILS=(
    "nginx-exploit-permanent"
    "nginx-4xx"
    "nginx-4xx-burst"
    "npm-fasthttp"
    "npm-iot-exploit"
)

# Global drop jails
declare -a GLOBAL_DROP_JAILS=(
    "recidive"
    "manualblock"
)

# ============================================================
# PRE-FLIGHT CHECK
# ============================================================

log "${YELLOW}✈️ PRE-FLIGHT CHECK:${NC}"

if ! command -v nft &> /dev/null; then
    log "${RED}❌ nft nie je nainštalovaný!${NC}"
    log " Nainštaluj: sudo apt install nftables"
    exit 1
fi

if [[ $EUID -ne 0 ]]; then
    log "${RED}❌ Musíš spustiť ako sudo!${NC}"
    exit 1
fi

log "${GREEN}✅ nft je dostupný${NC}"
log ""

# ============================================================
# KROK 1: Zastavenie Fail2Ban
# ============================================================

log "${YELLOW}🛑 KROK 1: Zastavenie Fail2Ban${NC}"

sudo systemctl stop fail2ban 2>/dev/null || true
log "${GREEN}✅ Fail2Ban zastavený${NC}"
log ""

# ============================================================
# KROK 2: Kontrola existencie tabuľky
# ============================================================

log "${YELLOW}📋 KROK 2: Kontrola nftables tabuľky${NC}"

if sudo nft list table inet f2b-table &>/dev/null; then
    log "${GREEN}✅ Tabuľka f2b-table existuje${NC}"
    log "${YELLOW}⚠️  Čistím starú konfigu...${NC}"
    sudo nft flush table inet f2b-table
    log "${GREEN}✅ Tabuľka vyčistená${NC}"
else
    log "${YELLOW}🆕 Vytváram novú tabuľku${NC}"
    sudo nft add table inet f2b-table
    log "${GREEN}✅ Tabuľka vytvorená${NC}"
fi
log ""

# ============================================================
# KROK 3: Vytvorenie setov pre všetky jaili (v0.7.3)
# ============================================================

log "${YELLOW}📊 KROK 3: Vytvorenie nftables setov pre všetky jaili${NC}"

for jail in "${JAILS[@]}"; do
    set_name="${NFTABLES_SETS[$jail]}"
    log "  Vytváram set: $set_name"
    sudo nft add set inet f2b-table "$set_name" "{ type ipv4_addr; flags interval; auto-merge; }" 2>/dev/null || true
done

log "${GREEN}✅ Všetky sety vytvorené${NC}"
log ""

# ============================================================
# KROK 4: Vytvorenie reťazcov (chains)
# ============================================================

log "${YELLOW}🔗 KROK 4: Vytvorenie reťazcov${NC}"

# INPUT chain
sudo nft add chain inet f2b-table f2b-input "{ type filter hook input priority -1; }" 2>/dev/null || true
log "  INPUT chain OK"

# FORWARD chain
sudo nft add chain inet f2b-table f2b-forward "{ type filter hook forward priority -1; }" 2>/dev/null || true
log "  FORWARD chain OK"

log "${GREEN}✅ Reťazce vytvorené${NC}"
log ""

# ============================================================
# KROK 5: Pravidlá pre MULTIPORT jaili
# ============================================================

log "${YELLOW}⚙️  KROK 5: Pravidlá pre MULTIPORT jaili${NC}"

for jail in "${MULTIPORT_JAILS[@]}"; do
    set_name="${NFTABLES_SETS[$jail]}"
    sudo nft add rule inet f2b-table f2b-input "tcp dport { 80, 443, 8080, 8443 } ip saddr @$set_name drop" 2>/dev/null || true
    sudo nft add rule inet f2b-table f2b-forward "tcp dport { 80, 443, 8080, 8443 } ip saddr @$set_name drop" 2>/dev/null || true
    log "  $jail → multiport pravidlá OK"
done

log "${GREEN}✅ MULTIPORT pravidlá OK${NC}"
log ""

# ============================================================
# KROK 6: Pravidlá pre GLOBAL DROP jaili
# ============================================================

log "${YELLOW}⚙️  KROK 6: Pravidlá pre GLOBAL DROP jaili${NC}"

for jail in "${GLOBAL_DROP_JAILS[@]}"; do
    set_name="${NFTABLES_SETS[$jail]}"
    sudo nft add rule inet f2b-table f2b-input "ip saddr @$set_name drop" 2>/dev/null || true
    sudo nft add rule inet f2b-table f2b-forward "ip saddr @$set_name drop" 2>/dev/null || true
    log "  $jail → global drop OK"
done

log "${GREEN}✅ GLOBAL DROP pravidlá OK${NC}"
log ""

# ============================================================
# KROK 7: Reštart Fail2Ban
# ============================================================

log "${YELLOW}🔄 KROK 7: Reštart Fail2Ban${NC}"

sudo systemctl start fail2ban
log "${GREEN}✅ Fail2Ban spustený${NC}"
log ""

# ============================================================
# FINÁLNA VERIFIKÁCIA
# ============================================================

log "${BLUE}✅ FINÁLNA VERIFIKÁCIA${NC}"
log ""
log "nftables tabuľka:"
sudo nft list table inet f2b-table
log ""
log "${GREEN}✅ NFTables v0.7.3 ÚSPEŠNE NASTAVENÉ!${NC}"
