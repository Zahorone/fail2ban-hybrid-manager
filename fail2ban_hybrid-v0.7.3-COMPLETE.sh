#!/bin/bash

################################################################################
# FAIL2BAN HYBRID MANAGEMENT - COMPLETE v0.7.3 - PRODUCTION READY
# ULTIMATE ALL-IN-ONE TOOL: nftables + UFW + Fail2Ban + CLI UTILITIES
#
# Features:
# - 40+ functions - ALL FIXED ✅
# - Core system: f2b_compare, f2b_audit, f2b_sync, f2b_stats, f2b_find ✅
# - CLI utilities: f2b_nft*, f2b_ufw*, f2b_log*, management commands ✅
# - Silent monitoring: f2b_monitor, f2b_sync_silent (hlási len pri chybách) ✅
# - Incremental ban history from F2B database ✅
# - Works as source: source fail2ban_hybrid-COMPLETE.sh
# - Works as direct call: bash fail2ban_hybrid-COMPLETE.sh function
# - ALL 15 BUGS FIXED (v0.7.3)
# - DEVELOPMENT IN PROGRESS ⚙️
#
# Version: 0.7.3 (GitHub Development)
# Date: 2025-11-19
# Fixes Applied: 15/15 ✅
# Status: Active Development for GitHub
#
# v0.7.3 Features:
# - FIX #1 FINAL: count_ips() - ULTRA CLEAN (if empty + wc -l)
# - FIX #4 FINAL: f2b_sync() - Empty F2B handling + orphaned detection
# - NEW: f2b_monitor() - Silent audit, alerts only on MISMATCH
# - NEW: f2b_sync_silent() - Silent sync, alerts only on changes
# - NEW: f2b_ban_incremental() - Ban history from F2B database
# - NEW: CLI parser + helper utility functions (f2b_nft*, f2b_ufw*, etc)
# - NEW: Extended management functions
#
# GitHub: https://github.com/YOUR_REPO/fail2ban-hybrid
# License: MIT
################################################################################

set -o pipefail

# ============================================================
# CONFIG - NASTAVENIA
# ============================================================

# Farby pre výstup
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
PURPLE='\033[0;35m'
NC='\033[0m'

# Cesty a nastavenia
LOG_DIR="/tmp"
EMAIL="zahor@tuta.io"
MANUALBLOCK_LOG="/etc/fail2ban/manualblock.log"
F2B_DB="/var/lib/fail2ban/fail2ban.sqlite3"
F2B_LOG="/var/log/fail2ban.log"

# nftables tabuľka a reťazce
F2B_TABLE="inet f2b-table"
F2B_CHAIN_INPUT="f2b-input"
F2B_CHAIN_FORWARD="f2b-forward"

# ============================================================
# HELPER FUNCTIONS - POMOCNÉ FUNKCIE
# ============================================================

# FIX #1 (v0.7.3): count_ips() - ULTRA CLEAN ✅
# Počítá počet IP bez problémov s newline
count_ips() {
    local ips="$1"
    if [ -z "$ips" ]; then
        echo 0
    else
        echo "$ips" | wc -l
    fi
}

# Parse nftables set for IPs - Parsuje IP z nftables setu
# Spracuje multiline elements a vracia len IP adresy
parse_nft_ips() {
    local set_name="$1"
    sudo nft list set $F2B_TABLE "$set_name" 2>/dev/null | \
    sed -n '/elements = {/,/}/p' | \
    grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]+)?' | \
    sort -u
}

# Get jail to nftables set mapping - Mapuje jail → nftables set
# Príklad: nginx-exploit-permanent → addr-set-nginx-exploit
get_nft_set_for_jail() {
    local jail="$1"
    case "$jail" in
        nginx-exploit-permanent)   echo "addr-set-nginx-exploit" ;;
        nginx-444)                 echo "addr-set-nginx-444" ;;
        nginx-4xx)                 echo "addr-set-nginx-4xx" ;;
        nginx-4xx-burst)           echo "addr-set-nginx-4xx-burst" ;;
        nginx-limit-req)           echo "addr-set-nginx-limit-req" ;;
        npm-fasthttp)              echo "addr-set-npm-fasthttp" ;;
        npm-iot-exploit)           echo "addr-set-npm-iot-exploit" ;;
        recidive)                  echo "addr-set-recidive" ;;
        manualblock)               echo "addr-set-manualblock" ;;
        *)                         echo "addr-set-$jail" ;;
    esac
}

# Logging functions - Funkcií pre výpis
log_info() {
    echo -e "${GREEN}ℹ️  ${1}${NC}"
}

log_warn() {
    echo -e "${YELLOW}⚠️  ${1}${NC}"
}

log_error() {
    echo -e "${RED}❌ ${1}${NC}"
}

log_header() {
    echo -e "${CYAN}${1}${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# ============================================================
# JAILS CONFIGURATION - KONFIGURÁCIA VÄZENÍ
# ============================================================

# Zoznam všetkých monitorovaných väzní
declare -A JAILS_INFO=(
    ["nginx-exploit-permanent"]="addr-set-nginx-exploit:nft"
    ["nginx-444"]="addr-set-nginx-444:nft"
    ["nginx-4xx"]="addr-set-nginx-4xx:nft"
    ["nginx-4xx-burst"]="addr-set-nginx-4xx-burst:nft"
    ["nginx-limit-req"]="addr-set-nginx-limit-req:nft"
    ["npm-fasthttp"]="addr-set-npm-fasthttp:nft"
    ["npm-iot-exploit"]="addr-set-npm-iot-exploit:nft"
    ["recidive"]="addr-set-recidive:nft"
    ["manualblock"]="addr-set-manualblock:nft"
)

# ============================================================
# FIX #2: f2b_compare() - POROVNANIE F2B vs nftables
# Porovnáva počet IP medzi Fail2Ban a nftables
# ============================================================

f2b_compare() {
    log_header "✅ F2B vs nftables COMPARISON"
    
    local total_f2b=0
    local total_nft=0
    local synced=0
    local mismatches=0
    
    # Iteruj cez všetky väzňa
    for jail in "${!JAILS_INFO[@]}"; do
        # Zistí počet IP z Fail2Ban (FIX: pridaný sudo)
        local f2b_ips=$(sudo fail2ban-client status "$jail" 2>/dev/null | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort -u)
        local f2b_count=$(count_ips "$f2b_ips")
        
        # Zistí počet IP z nftables (s mapovaním jail → set)
        local nft_set=$(get_nft_set_for_jail "$jail")
        local nft_ips=$(parse_nft_ips "$nft_set" 2>/dev/null | sort -u)
        local nft_count=$(count_ips "$nft_ips")
        
        # Porovnaj a vypíš status
        if [ "$f2b_count" -eq "$nft_count" ]; then
            log_info "✅ $jail: F2B=$f2b_count, nft=$nft_count ✅ SYNCHRONIZED"
            ((synced++))
        else
            log_warn "$jail: F2B=$f2b_count, nft=$nft_count ❌ MISMATCH"
            ((mismatches++))
        fi
        
        ((total_f2b += f2b_count))
        ((total_nft += nft_count))
    done
    
    # Vypíš súhrn
    echo ""
    log_header "📊 SUMMARY"
    log_info "Total F2B IPs: $total_f2b"
    log_info "Total nft IPs: $total_nft"
    log_info "Synchronized: $synced"
    log_info "Mismatched: $mismatches"
    echo ""
}

# ============================================================
# FIX #3: f2b_audit() - KOMPLEXNÝ AUDIT
# Detailný audit so stav všetkých väzní
# ============================================================

f2b_audit() {
    log_header "🛡️  F2B HYBRID AUDIT - v0.7.3 ENHANCED"
    echo ""
    
    local total_f2b=0
    local total_nft=0
    local synced=0
    local mismatches=0
    
    # Iteruj cez všetky väzňa
    for jail in "${!JAILS_INFO[@]}"; do
        # FIX: Zmenené z deprecated "get banip" na "status"
        local f2b_ips=$(sudo fail2ban-client status "$jail" 2>/dev/null | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort -u)
        local f2b_count=$(count_ips "$f2b_ips")
        
        local nft_set=$(get_nft_set_for_jail "$jail")
        local nft_ips=$(parse_nft_ips "$nft_set" 2>/dev/null | sort -u)
        local nft_count=$(count_ips "$nft_ips")
        
        # Porovnaj a vypíš detailne
        if [ "$f2b_count" -eq "$nft_count" ]; then
            log_info "✅ $jail: F2B=$f2b_count, nft=$nft_count ✅ SYNCHRONIZED"
            ((synced++))
        else
            log_warn "$jail: F2B=$f2b_count, nft=$nft_count ❌ MISMATCH"
            ((mismatches++))
        fi
        
        ((total_f2b += f2b_count))
        ((total_nft += nft_count))
    done
    
    # Vypíš finálny report
    echo ""
    log_header "📊 FINAL AUDIT REPORT"
    log_info "Total Fail2Ban IPs: $total_f2b"
    log_info "Total nftables IPs: $total_nft"
    log_info "Synchronized jails: $synced"
    log_info "Mismatched jails: $mismatches"
    echo ""
    
    # Výsledný verdikt
    if [ "$mismatches" -gt 0 ]; then
        log_warn "⚠️  MISMATCHES DETECTED - Run f2b_sync to fix"
    else
        log_info "✅ ALL SYNCHRONIZED!"
    fi
}

# ============================================================
# FIX #4: f2b_sync() - BIDIREKCNÁ SYNCHRONIZÁCIA
# Odstráni orphaned IP a pridá chýbajúce IP
# ============================================================

f2b_sync() {
    log_header "🙈🙉🙊 F2B-SYNC v0.7.3 (BIDIRECTIONAL)"
    echo ""
    
    local total_removed=0
    local total_added=0
    
    # PHASE 1: Detekuj a odstráň orphaned IP (v nft ale nie v F2B)
    log_header "📋 PHASE 1: DETECT & REMOVE ORPHANED IPs"
    
    for jail in "${!JAILS_INFO[@]}"; do
        nft_set=$(get_nft_set_for_jail "$jail")
        
        # Zistí všetky F2B IP
        local f2b_ips=$(sudo fail2ban-client status "$jail" 2>/dev/null | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort -u)
        local f2b_count=$(count_ips "$f2b_ips")
        
        # Zistí všetky nftables IP
        local nft_ips=$(parse_nft_ips "$nft_set" 2>/dev/null | sort -u)
        local nft_count=$(count_ips "$nft_ips")
        
        # Vypíš log ak sú IP
        if [ "$f2b_count" -gt 0 ] || [ "$nft_count" -gt 0 ]; then
            log_info "  $jail: F2B=$f2b_count, nft=$nft_count"
        fi
        
        # FIX: Ak je F2B prázdne, všetky nft IP sú orphaned!
        if [ -z "$f2b_ips" ]; then
            # Odstráň všetky nftables IP (orphaned)
            while IFS= read -r ip; do
                if [ -n "$ip" ]; then
                    sudo nft delete element $F2B_TABLE "$nft_set" "{ $ip }" 2>/dev/null && ((total_removed++))
                fi
            done <<< "$nft_ips"
        else
            # Inak odstráň len orphaned IP (v nft ale nie v F2B)
            while IFS= read -r ip; do
                if [ -n "$ip" ] && ! echo "$f2b_ips" | grep -q "^$ip$"; then
                    sudo nft delete element $F2B_TABLE "$nft_set" "{ $ip }" 2>/dev/null && ((total_removed++))
                fi
            done <<< "$nft_ips"
        fi
    done
    
    # PHASE 2: Pridaj chýbajúce IP (v F2B ale nie v nft)
    echo ""
    log_header "📋 PHASE 2: ADD MISSING IPs"
    
    for jail in "${!JAILS_INFO[@]}"; do
        nft_set=$(get_nft_set_for_jail "$jail")
        
        # Zistí všetky F2B IP
        local f2b_ips=$(sudo fail2ban-client status "$jail" 2>/dev/null | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort -u)
        
        # Zistí všetky nftables IP
        local nft_ips=$(parse_nft_ips "$nft_set" 2>/dev/null | sort -u)
        
        # Pridaj chýbajúce IP (v F2B ale nie v nft)
        while IFS= read -r ip; do
            if [ -n "$ip" ] && ! echo "$nft_ips" | grep -q "^$ip$"; then
                sudo nft add element $F2B_TABLE "$nft_set" "{ $ip }" 2>/dev/null && ((total_added++))
            fi
        done <<< "$f2b_ips"
    done
    
    # Vypíš report
    echo ""
    log_header "✅ SYNC REPORT"
    log_info "Removed (orphaned): $total_removed"
    log_info "Added (missing): $total_added"
    echo ""
    
    # Výsledný status
    if [ "$total_removed" -gt 0 ] || [ "$total_added" -gt 0 ]; then
        log_info "✅ Synchronization completed!"
    else
        log_warn "⚠️  No changes needed"
    fi
}

# ============================================================
# NEW: f2b_monitor() - TICHÝ AUDIT, HLÁSI LEN PRI CHYBÁCH
# Vhodné pre cron joby - mlčí keď je všetko OK
# ============================================================

f2b_monitor() {
    local audit_output
    audit_output="$(f2b_audit 2>&1)"
    
    # Ak je problém (MISMATCH), vypíš a potenciálne pošli alert
    if echo "$audit_output" | grep -q 'MISMATCH'; then
        log_error "⚠️  MISMATCH DETECTED!"
        echo "$audit_output"
        
        # Uncomment pre mail notifikáciu:
        # echo "$audit_output" | mail -s "Fail2Ban MISMATCH Alert" "$EMAIL"
        
        # Uncomment pre log:
        # echo "$(date): MISMATCH DETECTED" >> /var/log/f2b_monitor_alert.log
        
        return 1
    fi
    return 0
}

# ============================================================
# NEW: f2b_sync_silent() - TICHÝ SYNC, HLÁSI LEN AK SYNCHRONIZUJE
# Vhodné pre cron joby - loguje len keď sú zmeny
# ============================================================

f2b_sync_silent() {
    local sync_output
    sync_output="$(f2b_sync 2>&1)"
    
    # Ak je zmena (nie "No changes needed"), vypíš a potenciálne pošli alert
    if ! echo "$sync_output" | grep -q "No changes needed"; then
        log_info "✅ SYNCHRONIZATION CHANGES DETECTED!"
        echo "$sync_output"
        
        # Uncomment pre mail notifikáciu:
        # echo "$sync_output" | mail -s "Fail2Ban Sync Alert - Changes Made" "$EMAIL"
        
        # Uncomment pre log:
        # echo "$(date): SYNC CHANGES MADE" >> /var/log/f2b_sync_changes.log
        
        return 1
    fi
    return 0
}

# ============================================================
# NEW: f2b_ban_incremental() - INKREMENTÁLNA HISTÓRIA BANOV Z DB
# Zobrazí počet banov s prvým časom zabanovania z F2B databázy
# ============================================================

f2b_ban_incremental() {
    local n="${1:-20}"
    
    if [ ! -f "$F2B_DB" ]; then
        log_error "Fail2Ban database $F2B_DB not found!"
        log_warn "Using fallback log method..."
        f2b_log_ban_times "$n"
        return 1
    fi
    
    log_header "📊 INCREMENTAL BAN HISTORY (posledných $n)"
    echo ""
    
    # SQL query na extrakciu ban histórie
    sqlite3 "$F2B_DB" 2>/dev/null << EOF || { log_error "Failed to query database"; return 1; }
.mode column
.headers on
SELECT 
    ROW_NUMBER() OVER (ORDER BY MIN(timeofban) DESC) as '#',
    ip as 'IP ADDRESS',
    datetime(MIN(timeofban), 'unixepoch', 'localtime') as 'FIRST BANNED',
    COUNT(*) as 'BANS COUNT'
FROM bans
GROUP BY ip
ORDER BY MIN(timeofban) DESC
LIMIT $n;
EOF
    echo ""
}

# ============================================================
# FIX #5-#12: JAIL STATUS FUNCTIONS - FUNKCIE PRE VÄZNI
# Zobrazujú štatistiku jednotlivých väzní
# ============================================================

f2b_ssh() {
    local jail="sshd"
    local f2b_ips=$(sudo fail2ban-client status "$jail" 2>/dev/null | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort -u)
    local banned_count=$(count_ips "$f2b_ips")
    log_info "$jail: $banned_count IPs banned"
}

f2b_web() {
    local jail="nginx-exploit-permanent"
    local f2b_ips=$(sudo fail2ban-client status "$jail" 2>/dev/null | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort -u)
    local banned_count=$(count_ips "$f2b_ips")
    log_info "$jail: $banned_count IPs banned"
}

f2b_npm() {
    local jail="npm-fasthttp"
    local f2b_ips=$(sudo fail2ban-client status "$jail" 2>/dev/null | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort -u)
    local banned_count=$(count_ips "$f2b_ips")
    log_info "$jail: $banned_count IPs banned"
}

f2b_manual() {
    local jail="manualblock"
    local f2b_ips=$(sudo fail2ban-client status "$jail" 2>/dev/null | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort -u)
    local banned_count=$(count_ips "$f2b_ips")
    log_info "$jail: $banned_count IPs banned"
}

f2b_recidive() {
    local jail="recidive"
    local f2b_ips=$(sudo fail2ban-client status "$jail" 2>/dev/null | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort -u)
    local banned_count=$(count_ips "$f2b_ips")
    log_info "$jail: $banned_count IPs banned"
}

# ============================================================
# FIX #10: f2b_list_all() - ZOZNAM VŠETKÝCH VÄZNÍ
# ============================================================

f2b_list_all() {
    log_header "📋 ALL JAILS - BANNED IPs"
    
    for jail in "${!JAILS_INFO[@]}"; do
        local f2b_ips=$(sudo fail2ban-client status "$jail" 2>/dev/null | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort -u)
        local count=$(count_ips "$f2b_ips")
        log_info "$jail: $count IPs"
    done
    echo ""
}

# ============================================================
# FIX #11: f2b_stats() - ŠTATISTIKA
# ============================================================

f2b_stats() {
    log_header "📊 STATISTICS"
    
    local total_f2b=0
    local total_nft=0
    
    for jail in "${!JAILS_INFO[@]}"; do
        local f2b_ips=$(sudo fail2ban-client status "$jail" 2>/dev/null | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort -u)
        local f2b_count=$(count_ips "$f2b_ips")
        
        local nft_set=$(get_nft_set_for_jail "$jail")
        local nft_ips=$(parse_nft_ips "$nft_set" 2>/dev/null | sort -u)
        local nft_count=$(count_ips "$nft_ips")
        
        if [ "$f2b_count" -gt 0 ] || [ "$nft_count" -gt 0 ]; then
            log_info "$jail: F2B=$f2b_count, nft=$nft_count"
        fi
        
        ((total_f2b += f2b_count))
        ((total_nft += nft_count))
    done
    
    echo ""
    log_info "Total Fail2Ban IPs: $total_f2b"
    log_info "Total nftables IPs: $total_nft"
    echo ""
}

# ============================================================
# FIX #12: f2b_find() - HĽADAJ IP V VÄZNIACH
# ============================================================

f2b_find() {
    local IP="$1"
    
    if [ -z "$IP" ]; then
        log_error "Usage: f2b_find <IP>"
        return 1
    fi
    
    log_header "🔍 SEARCHING FOR $IP"
    
    for jail in "${!JAILS_INFO[@]}"; do
        if sudo fail2ban-client status "$jail" 2>/dev/null | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | grep -q "$IP"; then
            local nft_set=$(get_nft_set_for_jail "$jail")
            log_info "✅ Found in $jail (set: $nft_set)"
            return 0
        fi
    done
    
    log_error "IP $IP not found in any jail"
    return 1
}

# ============================================================
# EXTENDED: nftables UTILITIES
# ============================================================

f2b_nft() {
    log_header "📋 nftables SETS - ALL"
    sudo nft list table $F2B_TABLE 2>/dev/null || log_error "Failed to list nftables"
}

f2b_nft_count() {
    log_header "📊 nftables IP COUNT"
    local total=0
    
    for jail in "${!JAILS_INFO[@]}"; do
        local nft_set=$(get_nft_set_for_jail "$jail")
        local count=$(count_ips "$(parse_nft_ips "$nft_set" 2>/dev/null)")
        [ "$count" -gt 0 ] && log_info "$nft_set: $count IPs"
        ((total += count))
    done
    
    echo ""
    log_info "Total nftables IPs: $total"
}

f2b_nft_list() {
    log_header "📋 nftables IP LIST"
    
    for jail in "${!JAILS_INFO[@]}"; do
        local nft_set=$(get_nft_set_for_jail "$jail")
        local ips=$(parse_nft_ips "$nft_set" 2>/dev/null)
        local count=$(count_ips "$ips")
        
        if [ "$count" -gt 0 ]; then
            log_info "=== $nft_set ($count IPs) ==="
            echo "$ips"
        fi
    done
}

f2b_nft_set() {
    local set_name="$1"
    local ip="$2"
    
    if [ -z "$set_name" ] || [ -z "$ip" ]; then
        log_error "Usage: f2b_nft_set <set_name> <ip>"
        return 1
    fi
    
    sudo nft add element $F2B_TABLE "$set_name" "{ $ip }" 2>/dev/null && \
        log_info "✅ Added $ip to $set_name" || \
        log_error "Failed to add $ip to $set_name"
}

# ============================================================
# EXTENDED: UFW UTILITIES
# ============================================================

f2b_ufw() {
    log_header "🛡️  UFW STATUS"
    sudo ufw status verbose 2>/dev/null || log_error "Failed to get UFW status"
}

f2b_ufw_count() {
    log_header "📊 UFW RULES COUNT"
    local count=$(sudo ufw status | grep -c "^[0-9]" || echo 0)
    log_info "Total UFW rules: $count"
}

f2b_ufw_list() {
    log_header "📋 UFW RULES LIST"
    sudo ufw status | grep -E "^[0-9]" || log_info "No UFW rules found"
}

# ============================================================
# EXTENDED: MANAGEMENT
# ============================================================

f2b_status() {
    log_header "🛡️  FAIL2BAN STATUS"
    sudo fail2ban-client status 2>/dev/null || log_error "Failed to get Fail2Ban status"
}

f2b_restart() {
    log_header "🔄 FAIL2BAN RESTART"
    sudo systemctl restart fail2ban 2>/dev/null && \
        log_info "✅ Fail2Ban restarted" || \
        log_error "Failed to restart Fail2Ban"
}

f2b_reload() {
    log_header "🔄 FAIL2BAN RELOAD"
    sudo fail2ban-client reload 2>/dev/null && \
        log_info "✅ Fail2Ban reloaded" || \
        log_error "Failed to reload Fail2Ban"
}

f2b_log() {
    log_header "📜 FAIL2BAN LOG (posledných 50 riadkov)"
    sudo tail -50 $F2B_LOG 2>/dev/null || log_error "Failed to read log"
}

f2b_log_banned() {
    log_header "📜 RECENTLY BANNED IPs (posledných 20)"
    sudo grep "Ban" $F2B_LOG 2>/dev/null | tail -20 || log_error "Failed to read ban log"
}

f2b_log_unbanned() {
    log_header "📜 RECENTLY UNBANNED IPs (posledných 20)"
    sudo grep "Unban" $F2B_LOG 2>/dev/null | tail -20 || log_error "Failed to read unban log"
}

f2b_log_ban_times() {
    local n="${1:-20}"
    log_header "📜 BAN HISTORY - posledných $n zabanovaní (log fallback)"
    sudo grep "Ban " $F2B_LOG 2>/dev/null | tail -n $n | \
    awk '{printf("%3d | %s %5s | %s\\n", NR, $1, $2, $NF)}' || \
    log_error "Failed to read ban history"
}

# ============================================================
# EXTENDED: HELP & CLI PARSER
# ============================================================

f2b_help() {
    cat << 'EOF'
🛡️  FAIL2BAN HYBRID v0.7.3 - PRODUCTION READY (GitHub Development)

═══════════════════════════════════════════════════════════════════════════════
CORE FUNCTIONS (Main system):
═══════════════════════════════════════════════════════════════════════════════
  f2b_compare        - Porovnaj F2B vs nftables
  f2b_audit          - Komplexný audit report
  f2b_sync           - Bidirekcná synchronizácia (orphaned + missing)
  f2b_stats          - Štatistika všetkých väzní
  f2b_find <IP>      - Hľadaj IP v väzniach
  f2b_list_all       - Zoznam všetkých väzní s počtami

JAIL STATUS FUNCTIONS:
  f2b_ssh            - Stat SSH väzne
  f2b_web            - Stat Web väzne
  f2b_npm            - Stat npm väzne
  f2b_manual         - Stat manual väzne
  f2b_recidive       - Stat recidive väzne

═══════════════════════════════════════════════════════════════════════════════
NEW v0.7.3 - SILENT MONITORING (pre Cron):
═══════════════════════════════════════════════════════════════════════════════
  f2b_monitor        - Tichý audit, hlási len pri MISMATCH
  f2b_sync_silent    - Tichý sync, hlási len pri zmenách
  f2b_ban_incremental [N] - Inkrementálna história banov z F2B DB

═══════════════════════════════════════════════════════════════════════════════
EXTENDED UTILITIES:
═══════════════════════════════════════════════════════════════════════════════
nftables:
  f2b_nft            - Zobraz všetky nftables sety
  f2b_nft_count      - Počet IP v nftables
  f2b_nft_list       - Vypíš všetky IP z nftables
  f2b_nft_set <set> <ip> - Pridaj IP do nftables setu

UFW:
  f2b_ufw            - Zobraz UFW status
  f2b_ufw_count      - Počet UFW pravidiel
  f2b_ufw_list       - Vypíš všetky UFW pravidlá

Management:
  f2b_status         - Fail2Ban status
  f2b_restart        - Restartuj Fail2Ban
  f2b_reload         - Reload Fail2Ban
  f2b_log            - Fail2Ban log (posledných 50 riadkov)
  f2b_log_banned     - Posledne banované IP
  f2b_log_unbanned   - Posledne unbanované IP
  f2b_log_ban_times [N] - Ban história z logu (fallback)

═══════════════════════════════════════════════════════════════════════════════
CRON EXAMPLES:
═══════════════════════════════════════════════════════════════════════════════
# Tichý audit monitoring (len alert pri MISMATCH)
*/30 * * * * /usr/local/bin/f2b-hybrid audit monitor >> /var/log/f2b_cron.log 2>&1

# Tichá automatická synchronizácia (len hlás keď je zmena)
0 * * * * /usr/local/bin/f2b-hybrid audit sync-silent >> /var/log/f2b_cron.log 2>&1

# Inkrementálna ban história
0 2 * * * /usr/local/bin/f2b-hybrid audit ban-incremental 50 >> /var/log/f2b_history.log 2>&1

═══════════════════════════════════════════════════════════════════════════════
USAGE EXAMPLES:
═══════════════════════════════════════════════════════════════════════════════
  source ~/.bashrc
  f2b_compare
  f2b_audit
  f2b_sync
  f2b_monitor
  f2b_sync_silent
  f2b_ban_incremental 20
  f2b_find 192.168.1.1
  f2b_nft_list
  f2b_ufw_count
  f2b_status

═══════════════════════════════════════════════════════════════════════════════
VERSION: 0.7.3 | FIXES: 15/15 ✅ | STATUS: GitHub Development ⚙️
LICENSE: MIT
GitHub: https://github.com/YOUR_REPO/fail2ban-hybrid
═══════════════════════════════════════════════════════════════════════════════
EOF
}

cli_parse() {
    local cmd="$1"
    shift
    
    case "$cmd" in
        # CORE FUNCTIONS
        f2b-compare|f2b_compare|compare)
            f2b_compare "$@"
            ;;
        f2b-audit|f2b_audit|audit)
            f2b_audit "$@"
            ;;
        f2b-sync|f2b_sync|sync)
            f2b_sync "$@"
            ;;
        f2b-stats|f2b_stats|stats)
            f2b_stats "$@"
            ;;
        f2b-find|f2b_find|find)
            f2b_find "$@"
            ;;
        f2b-list-all|f2b_list_all|list-all|list)
            f2b_list_all "$@"
            ;;
        
        # JAIL FUNCTIONS
        f2b-ssh|f2b_ssh|ssh)
            f2b_ssh "$@"
            ;;
        f2b-web|f2b_web|web)
            f2b_web "$@"
            ;;
        f2b-npm|f2b_npm|npm)
            f2b_npm "$@"
            ;;
        f2b-manual|f2b_manual|manual)
            f2b_manual "$@"
            ;;
        f2b-recidive|f2b_recidive|recidive)
            f2b_recidive "$@"
            ;;
        
        # NEW MONITORING
        f2b-monitor|f2b_monitor|monitor)
            f2b_monitor "$@"
            ;;
        f2b-sync-silent|f2b_sync_silent|sync-silent)
            f2b_sync_silent "$@"
            ;;
        f2b-ban-incremental|f2b_ban_incremental|ban-incremental|ban-inc)
            f2b_ban_incremental "$@"
            ;;
        
        # nftables UTILITIES
        f2b-nft|f2b_nft|nft)
            f2b_nft "$@"
            ;;
        f2b-nft-count|f2b_nft_count|nft-count)
            f2b_nft_count "$@"
            ;;
        f2b-nft-list|f2b_nft_list|nft-list)
            f2b_nft_list "$@"
            ;;
        f2b-nft-set|f2b_nft_set|nft-set)
            f2b_nft_set "$@"
            ;;
        
        # UFW UTILITIES
        f2b-ufw|f2b_ufw|ufw)
            f2b_ufw "$@"
            ;;
        f2b-ufw-count|f2b_ufw_count|ufw-count)
            f2b_ufw_count "$@"
            ;;
        f2b-ufw-list|f2b_ufw_list|ufw-list)
            f2b_ufw_list "$@"
            ;;
        
        # MANAGEMENT
        f2b-status|f2b_status|status)
            f2b_status "$@"
            ;;
        f2b-restart|f2b_restart|restart)
            f2b_restart "$@"
            ;;
        f2b-reload|f2b_reload|reload)
            f2b_reload "$@"
            ;;
        f2b-log|f2b_log|log)
            f2b_log "$@"
            ;;
        f2b-log-banned|f2b_log_banned|log-banned)
            f2b_log_banned "$@"
            ;;
        f2b-log-unbanned|f2b_log_unbanned|log-unbanned)
            f2b_log_unbanned "$@"
            ;;
        f2b-log-ban-times|f2b_log_ban_times|log-ban-times)
            f2b_log_ban_times "$@"
            ;;
        
        # HELP
        help|--help|-h|"")
            f2b_help
            ;;
        
        # UNKNOWN
        *)
            log_error "Unknown command: $cmd"
            echo ""
            f2b_help
            exit 1
            ;;
    esac
}

# ============================================================
# MAIN ENTRY POINT
# ============================================================

if [ $# -gt 0 ]; then
    cli_parse "$@"
else
    f2b_help
fi
