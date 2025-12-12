#!/bin/bash

################################################################################
# F2B Unified Wrapper v0.23 - PRODUCTION
# Complete Fail2Ban + nftables + docker-block management
#
# v0.23 CHANGES:
# + Docker-block sync integration (f2b sync docker)
# + Real-time dashboard (f2b docker dashboard)
# + Docker info command (f2b docker info)
# + Docker command dispatcher (f2b docker COMMAND)
# + All v0.22 functions preserved
################################################################################

set -o pipefail

VERSION="0.23"
DOCKERBLOCKVERSION="0.3"

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'

# Configuration
F2BTABLE="inet fail2ban-filter"
BACKUPDIR="/var/backups/firewall"
LOGFILE="/var/log/f2b-wrapper.log"
LOCKFILE="/tmp/f2b-wrapper.lock"

# Jails list
JAILS=(
    "sshd"
    "sshd-slowattack"
    "f2b-exploit-critical"
    "f2b-dos-high"
    "f2b-web-medium"
    "nginx-recon-bonus"
    "recidive"
    "manualblock"
    "f2b-fuzzing-payloads"
    "f2b-botnet-signatures"
    "f2b-anomaly-detection"
)

# Jail to nftables set mapping
declare -A SETMAP=(
    ["sshd"]="f2b-sshd"
    ["sshd-slowattack"]="f2b-sshd-slowattack"
    ["f2b-exploit-critical"]="f2b-exploit-critical"
    ["f2b-dos-high"]="f2b-dos-high"
    ["f2b-web-medium"]="f2b-web-medium"
    ["nginx-recon-bonus"]="f2b-nginx-recon-bonus"
    ["recidive"]="f2b-recidive"
    ["manualblock"]="f2b-manualblock"
    ["f2b-fuzzing-payloads"]="f2b-fuzzing-payloads"
    ["f2b-botnet-signatures"]="f2b-botnet-signatures"
    ["f2b-anomaly-detection"]="f2b-anomaly-detection"
)

################################################################################
# LOGGING FUNCTIONS
################################################################################

log_success() {
    echo -e "${GREEN}[OK]${NC} $1" | tee -a "$LOGFILE"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a "$LOGFILE"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1" | tee -a "$LOGFILE"
}

log_info() {
    echo -e "${CYAN}[INFO]${NC} $1" | tee -a "$LOGFILE"
}

log_header() {
    echo -e "\n${BLUE}$1${NC}\n" | tee -a "$LOGFILE"
}

log_alert() {
    echo -e "${MAGENTA}[ALERT]${NC} $1" | tee -a "$LOGFILE"
}

################################################################################
# LOCK MECHANISM (NEW v0.19)
################################################################################

acquire_lock() {
    if [ -f "$LOCKFILE" ]; then
        log_error "Another f2b operation is in progress"
        log_error "If stuck, remove: $LOCKFILE"
        exit 1
    fi
    touch "$LOCKFILE"
    trap 'rm -f "$LOCKFILE"' EXIT INT TERM
}

release_lock() {
    rm -f "$LOCKFILE"
}

################################################################################
# VALIDATION FUNCTIONS (NEW v0.19)
################################################################################

validate_port() {
    local port
    port="$1"
    if ! [[ "$port" =~ ^[0-9]+$ ]] || [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
        log_error "Invalid port number: $port (must be 1-65535)"
        return 1
    fi
    return 0
}

validate_ip() {
    local ip
    ip="$1"
    if [[ ! "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        log_error "Invalid IP address: $ip"
        return 1
    fi
    return 0
}

################################################################################
# HELPER FUNCTIONS
################################################################################

get_f2b_count() {
    local jail
    jail="$1"
    local count
    count=$(sudo fail2ban-client status "$jail" 2>/dev/null | grep "Currently banned" | awk '{print $NF}' | head -n1 | tr -d '[:space:]')
    echo "${count:-0}"
}

get_f2b_ips() {
    local jail
    jail="$1"
    sudo fail2ban-client status "$jail" 2>/dev/null | \
    grep "Banned IP list:" | \
    sed 's/.*Banned IP list:\s*//' | \
    tr ' ' '\n' | \
    grep -E '[0-9]' | \
    sort -u
}

get_nft_ips() {
    local set
    set="$1"
    sudo nft list set "$F2BTABLE" "$set" 2>/dev/null | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort -u
}

count_ips() {
    local ips
    ips="$1"
    if [ -z "$ips" ]; then
        echo "0"
    else
        echo "$ips" | wc -l | tr -d '[:space:]'
    fi
}

################################################################################
# CORE FUNCTIONS
################################################################################

f2b_version() {
    log_header "═══════════════════════════════════════════════════════"
    echo " F2B Wrapper v${VERSION}"
    log_header "═══════════════════════════════════════════════════════"
    echo ""
    echo "Components:"
    echo " - Fail2Ban + nftables integration"
    echo " - Docker port blocking (v${DOCKERBLOCKVERSION})"
    echo " - Enhanced sync & monitoring"
    echo " - Complete management suite"
    echo " - Attack trend analysis"
    echo " - Export reports JSON/CSV"
    echo " - Real-time Dashboard (NEW v0.23)"
    echo " - Docker-block sync (NEW v0.23)"
    echo ""
}

f2b_status() {
    log_header "═══════════════════════════════════════════════════════"
    echo " F2B System Status v${VERSION}"
    log_header "═══════════════════════════════════════════════════════"
    echo ""
    echo "📊 Services:"
    if systemctl is-active --quiet nftables; then
        log_success "nftables: active"
    else
        log_error "nftables: inactive"
    fi
    if systemctl is-active --quiet fail2ban; then
        log_success "fail2ban: active"
    else
        log_error "fail2ban: inactive"
    fi
    if systemctl is-active --quiet ufw; then
        log_success "ufw: active"
    else
        log_warn "ufw: inactive"
    fi

    echo ""
    echo "🛡️ Active Jails:"
    sudo fail2ban-client status 2>/dev/null | grep "Jail list:" | sed 's/.*Jail list:\s*//' | tr ',' '\n' | sed 's/^[ \t]*/ - /' || log_error "Could not retrieve jails"

    echo ""
    echo "📋 NFT Tables:"
    sudo nft list tables 2>/dev/null | grep -E 'fail2ban|docker-block' | sed 's/^/ /' || echo " none"

    echo ""
    echo "🐋 docker-block v${DOCKERBLOCKVERSION}:"
    if sudo nft list table inet docker-block &>/dev/null; then
        log_success "Active (external blocking, localhost allowed)"
        sudo nft list set inet docker-block docker-blocked-ports 2>/dev/null | grep "elements" | sed 's/^\s*/ /' || echo " No blocked ports"
    else
        log_warn "Not configured"
    fi

    echo ""
}

f2b_audit() {
    log_header "═══════════════════════════════════════════════════════"
    echo " Fail2Ban Audit"
    log_header "═══════════════════════════════════════════════════════"
    local total
    total=0
    local clean
    clean=0
    for jail in "${JAILS[@]}"; do
        local count
        count=$(get_f2b_count "$jail" | tr -d '[:space:]')
        count=${count:-0}
        if [ "$count" -eq 0 ]; then
            log_success "[$jail] clean"
            ((clean++))
        else
            log_warn "[$jail] $count IPs"
        fi
        ((total+=count))
    done

    echo ""
    log_info "Total Jails: ${#JAILS[@]}"
    log_info "Clean: $clean"
    log_info "Total IPs: $total"
    if [ "$total" -eq 0 ]; then
        log_success "✅ ALL CLEAN!"
    else
        log_warn "Active bans: $total"
    fi

    echo ""
}

f2b_find() {
    local IP
    IP="$1"
    if [ -z "$IP" ]; then
        log_error "Usage: f2b find <IP>"
        return 1
    fi
    
    if ! validate_ip "$IP"; then
        return 1
    fi
    
    log_header "Searching for $IP"
    
    local found
    found=0
    for jail in "${JAILS[@]}"; do
        if sudo fail2ban-client status "$jail" 2>/dev/null | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | grep -q "$IP"; then
            log_success "Found in jail: $jail"
            
            local bantime
            bantime=$(sudo fail2ban-client get "$jail" bantime 2>/dev/null || echo "unknown")
            log_info "Ban time: $bantime"
            
            local nftset
            nftset="${SETMAP[$jail]}"
            if sudo nft list set "$F2BTABLE" "$nftset" 2>/dev/null | grep -qE "$IP"; then
                log_info "nftables: Present in $nftset"
            else
                log_warn "nftables: NOT in $nftset (sync issue!)"
            fi
            
            # ✅ NOVÉ: kontrola docker-block
            if sudo nft list table inet docker-block &>/dev/null; then
                if sudo nft list set inet docker-block docker-banned-ipv4 2>/dev/null | grep -qE "$IP"; then
                    log_success "docker-block: Present ✅"
                else
                    log_warn "docker-block: NOT present (sync needed)"
                fi
            else
                log_info "docker-block: Table not configured"
            fi
            
            found=1
        fi
    done
    
    echo ""
    if [ "$found" -eq 0 ]; then
        log_error "IP $IP not found in any jail"
        return 1
    else
        log_success "Search complete"
        return 0
    fi
}

################################################################################
# SYNC FUNCTIONS
################################################################################

f2b_sync_check() {
    log_header "═══════════════════════════════════════════════════════"
    echo " Fail2Ban ↔ nftables Sync Check"
    log_header "═══════════════════════════════════════════════════════"
    echo ""
    local ALLSYNCED
    ALLSYNCED=true
    for jail in "${JAILS[@]}"; do
        local F2BCOUNT
        F2BCOUNT=$(get_f2b_count "$jail" | tr -d '[:space:]')
        local nftset
        nftset="${SETMAP[$jail]}"
        local NFTCOUNT
        NFTCOUNT=$(get_nft_ips "$nftset" | wc -l | tr -d '[:space:]')
        local DIFF
        DIFF=$((F2BCOUNT - NFTCOUNT))
        local DIFFABS=${DIFF#-}
        if [ "$F2BCOUNT" -eq "$NFTCOUNT" ]; then
            log_success "[$jail] $F2BCOUNT == $NFTCOUNT"
        elif [ "$DIFFABS" -le 1 ]; then
            log_success "[$jail] $F2BCOUNT == $NFTCOUNT (±1 range merge)"
        else
            log_warn "[$jail] F2B=$F2BCOUNT, nft=$NFTCOUNT (MISMATCH)"
            ALLSYNCED=false
        fi
    done

    echo ""
    if $ALLSYNCED; then
        log_success "[OK] All jails synchronized!"
    else
        log_warn "Some jails out of sync - run 'f2b sync force'"
    fi

    echo ""
}

f2b_sync_enhanced() {
    log_header "F2B SYNC ENHANCED (Bidirectional)"
    local removed
    removed=0
    local added
    added=0
    log_header "Phase 1: Remove orphaned IPs"
    for jail in "${JAILS[@]}"; do
        local nftset
        nftset="${SETMAP[$jail]}"
        local f2b_ips
        f2b_ips=$(get_f2b_ips "$jail")
        local nft_ips
        nft_ips=$(get_nft_ips "$nftset")
        local f2b_count
        f2b_count=$(count_ips "$f2b_ips")
        local nft_count
        nft_count=$(count_ips "$nft_ips")
        log_info "[$jail] F2B=$f2b_count, NFT=$nft_count"
        if [ -z "$f2b_ips" ]; then
            while read -r ip; do
                [ -n "$ip" ] && sudo nft delete element "$F2BTABLE" "$nftset" "{ $ip }" 2>/dev/null && ((removed++))
            done <<< "$nft_ips"
        else
            while read -r ip; do
                [ -n "$ip" ] && ! echo "$f2b_ips" | grep -q "$ip" && sudo nft delete element "$F2BTABLE" "$nftset" "{ $ip }" 2>/dev/null && ((removed++))
            done <<< "$nft_ips"
        fi
    done

    echo ""
    log_header "Phase 2: Add missing IPs"
    for jail in "${JAILS[@]}"; do
        local nftset
        nftset="${SETMAP[$jail]}"
        local f2b_ips
        f2b_ips=$(get_f2b_ips "$jail")
        local nft_ips
        nft_ips=$(get_nft_ips "$nftset")
        while read -r ip; do
            [ -n "$ip" ] && ! echo "$nft_ips" | grep -q "$ip" && sudo nft add element "$F2BTABLE" "$nftset" "{ $ip }" 2>/dev/null && ((added++))
        done <<< "$f2b_ips"
    done

    echo ""
    log_header "SYNC REPORT"
    log_success "Removed orphaned: $removed"
    log_success "Added missing: $added"
    if [ "$removed" -gt 0 ] || [ "$added" -gt 0 ]; then
        log_success "✅ Synchronization completed!"
    else
        log_warn "No changes needed"
    fi

    echo ""
}

f2b_sync_force() {
    f2b_sync_enhanced
    f2b_sync_check
}

sync_silent() {
    # Silent sync for cron - logs only errors
    local LOG_FILE
    LOG_FILE="/var/log/f2b-sync.log"
    local CHANGES
    CHANGES=0

    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Starting silent sync..." >> "$LOG_FILE"
    for jail in "${JAILS[@]}"; do
        local nftset
        nftset="${SETMAP[$jail]}"
        local f2b_ips
        f2b_ips=$(get_f2b_ips "$jail")
        local nft_ips
        nft_ips=$(get_nft_ips "$nftset")

        # Remove orphaned
        if [ -z "$f2b_ips" ]; then
            while read -r ip; do
                [ -n "$ip" ] && sudo nft delete element "$F2BTABLE" "$nftset" "{ $ip }" 2>/dev/null && ((CHANGES++)) && echo " Removed orphan: $ip from $jail" >> "$LOG_FILE"
            done <<< "$nft_ips"
        else
            while read -r ip; do
                [ -n "$ip" ] && ! echo "$f2b_ips" | grep -q "$ip" && sudo nft delete element "$F2BTABLE" "$nftset" "{ $ip }" 2>/dev/null && ((CHANGES++)) && echo " Removed orphan: $ip from $jail" >> "$LOG_FILE"
            done <<< "$nft_ips"
        fi

        # Add missing
        while read -r ip; do
            [ -n "$ip" ] && ! echo "$nft_ips" | grep -q "$ip" && sudo nft add element "$F2BTABLE" "$nftset" "{ $ip }" 2>/dev/null && ((CHANGES++)) && echo " Added missing: $ip to $jail" >> "$LOG_FILE"
        done <<< "$f2b_ips"
    done

    if [ "$CHANGES" -eq 0 ]; then
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] Sync OK - no changes" >> "$LOG_FILE"
    else
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] Sync completed - $CHANGES changes" >> "$LOG_FILE"
    fi
}

################################################################################
# F2B DOCKER SYNC (NEW v0.23)
################################################################################

f2b_sync_docker() {
    log_header "═══════════════════════════════════════════════════════"
    echo "  F2B ↔ Docker-Block Bidirectional Sync"
    log_header "═══════════════════════════════════════════════════════"
    echo ""

    # ✅ PRE-SYNC: Najprv synchronizuj fail2ban → nft sety
    log_info "Pre-sync: Synchronizing fail2ban → nftables..."
    sync_silent
    echo ""

    # Kontrola docker-block tabuľky
    if ! sudo nft list table inet docker-block &>/dev/null; then
        log_error "docker-block table NOT FOUND"
        log_info  "Install with: bash 03-install-docker-block-v03.sh"
        echo ""
        return 1
    fi

    # Log pre docker sync
    local LOG_FILE="/var/log/f2b-docker-sync.log"
    touch "$LOG_FILE"

    log_info "Starting docker-block sync (union of all F2B sets)..."
    echo ""

    # Sady z inet fail2ban-filter
    local SETS=(
        "f2b-sshd"
        "f2b-sshd-slowattack"
        "f2b-exploit-critical"
        "f2b-dos-high"
        "f2b-web-medium"
        "f2b-nginx-recon-bonus"
        "f2b-recidive"
        "f2b-manualblock"
        "f2b-fuzzing-payloads"
        "f2b-botnet-signatures"
        "f2b-anomaly-detection"
    )

    ############################################################################
    # IPv4 SYNC - UNION approach
    ############################################################################

    # 1. ALL IPv4 z VŠETKÝCH fail2ban setov (UNION)
    local F2B_IPS
    F2B_IPS=$(
        for SET in "${SETS[@]}"; do
            sudo nft list set inet fail2ban-filter "$SET" 2>/dev/null \
                | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' || true
        done | sort | uniq
    )

    # 2. Aktuálne IPv4 v docker-block
    local DOCKER_IPS
    DOCKER_IPS=$(
        sudo nft list set inet docker-block docker-banned-ipv4 2>/dev/null \
            | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort | uniq || true
    )

    # 3. PRIDAJ - v F2B ALE NIE v docker-block
    while IFS= read -r IP; do
        [ -z "$IP" ] && continue

        if ! echo "$DOCKER_IPS" | grep -q "^$IP$"; then
            sudo nft add element inet docker-block docker-banned-ipv4 { "$IP" timeout 1h } 2>/dev/null || true
            echo "[$(date +'%Y-%m-%d %H:%M:%S')] ADDED: $IP" | tee -a "$LOG_FILE"
        fi
    done <<< "$F2B_IPS"

    # 4. ODSTRÁŇ - v docker-block ALE NIE v F2B
    while IFS= read -r IP; do
        [ -z "$IP" ] && continue

        if ! echo "$F2B_IPS" | grep -q "^$IP$"; then
            sudo nft delete element inet docker-block docker-banned-ipv4 { "$IP" } 2>/dev/null || true
            echo "[$(date +'%Y-%m-%d %H:%M:%S')] REMOVED: $IP (no longer in fail2ban)" | tee -a "$LOG_FILE"
        fi
    done <<< "$DOCKER_IPS"

    ############################################################################
    # IPv6 SYNC - UNION approach
    ############################################################################

    # 1. ALL IPv6 z VŠETKÝCH fail2ban setov
    F2B_IPS=$(
        for SET in "${SETS[@]}"; do
            sudo nft list set inet fail2ban-filter "$SET-v6" 2>/dev/null \
                | grep -oE '([0-9a-f:]+:[0-9a-f:]+)' || true
        done | sort | uniq
    )

    # 2. Aktuálne IPv6 v docker-block
    DOCKER_IPS=$(
        sudo nft list set inet docker-block docker-banned-ipv6 2>/dev/null \
            | grep -oE '([0-9a-f:]+:[0-9a-f:]+)' | sort | uniq || true
    )

    # 3. PRIDAJ IPv6
    while IFS= read -r IP; do
        [ -z "$IP" ] && continue

        if ! echo "$DOCKER_IPS" | grep -q "^$IP$"; then
            sudo nft add element inet docker-block docker-banned-ipv6 { "$IP" timeout 1h } 2>/dev/null || true
            echo "[$(date +'%Y-%m-%d %H:%M:%S')] ADDED (IPv6): $IP" | tee -a "$LOG_FILE"
        fi
    done <<< "$F2B_IPS"

    # 4. ODSTRÁŇ IPv6
    while IFS= read -r IP; do
        [ -z "$IP" ] && continue

        if ! echo "$F2B_IPS" | grep -q "^$IP$"; then
            sudo nft delete element inet docker-block docker-banned-ipv6 { "$IP" } 2>/dev/null || true
            echo "[$(date +'%Y-%m-%d %H:%M:%S')] REMOVED (IPv6): $IP (no longer in fail2ban)" | tee -a "$LOG_FILE"
        fi
    done <<< "$DOCKER_IPS"

    ####################################################################
    # STATS: JAIL vs UNIQUE vs DOCKER
    ####################################################################

    # X: všetky IP naprieč jailmi (sumár ako report csv)
    local TOTAL_JAIL_IPS=0
    local ALL_JAIL_IPS

    ALL_JAIL_IPS=$(
        for jail in "${JAILS[@]}"; do
            sudo fail2ban-client status "$jail" 2>/dev/null \
              | grep "Banned IP list:" \
              | sed 's/.*Banned IP list:\s*//' \
              | tr ' ' '\n'
        done | grep -E '([0-9]{1,3}\.){3}[0-9]{1,3}' || true
    )

    if [ -n "$ALL_JAIL_IPS" ]; then
        TOTAL_JAIL_IPS=$(echo "$ALL_JAIL_IPS" | wc -l | tr -d '[:space:]')
    fi

    # Z: unikátne IP v jailoch (UNION)
    local UNIQUE_IPS=0
    local UNIQUE_LIST

    UNIQUE_LIST=$(echo "$ALL_JAIL_IPS" | sort -u)
    if [ -n "$UNIQUE_LIST" ]; then
        UNIQUE_IPS=$(echo "$UNIQUE_LIST" | wc -l | tr -d '[:space:]')
    fi

    # Y: duplicitné výskyty
    local DUPLICATES=0
    if [ "$TOTAL_JAIL_IPS" -gt "$UNIQUE_IPS" ]; then
        DUPLICATES=$((TOTAL_JAIL_IPS - UNIQUE_IPS))
    fi

    # W: IP v docker-block
    local DOCKER_IP_COUNT=0
    DOCKER_IP_COUNT=$(sudo nft list set inet docker-block docker-banned-ipv4 2>/dev/null \
                   | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | wc -l | tr -d '[:space:]')
    DOCKER_IP_COUNT=${DOCKER_IP_COUNT:-0}

    echo ""
    log_header "SYNC METRICS"
    log_info    "Jails: ${TOTAL_JAIL_IPS} IP (duplicates: ${DUPLICATES}, unique: ${UNIQUE_IPS})"
    log_info    "Docker-block: ${DOCKER_IP_COUNT} IP (unique expected: ${UNIQUE_IPS})"

    if [ "$DOCKER_IP_COUNT" -eq "$UNIQUE_IPS" ]; then
        log_success "✅ Numbers aligned: unique_jails == docker-block"
    else
        log_warn "⚠️  Numbers differ: unique_jails=${UNIQUE_IPS}, docker-block=${DOCKER_IP_COUNT}"
    fi

    # Summary
    local FINAL_COUNT
    FINAL_COUNT=$(sudo nft list set inet docker-block docker-banned-ipv4 2>/dev/null \
                    | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | wc -l)
    FINAL_COUNT=${FINAL_COUNT:-0}

    echo "[$(date +'%Y-%m-%d %H:%M:%S')] Sync complete - IPv4: $FINAL_COUNT IPs in docker-block" \
        | tee -a "$LOG_FILE"

    echo ""
    log_success "Docker-block sync complete"
    log_info    "IPv4 in docker-block: $FINAL_COUNT"
    echo ""
}


################################################################################
# F2B DOCKER DASHBOARD (NEW v0.23)
################################################################################

f2b_docker_dashboard() {
    while true; do
        clear
        
        log_header "╔═══════════════════════════════════════════════════════╗"
        log_header "║  F2B DOCKER-BLOCK REAL-TIME DASHBOARD v${VERSION}    ║"
        log_header "║  $(date '+%Y-%m-%d %H:%M:%S')                           ║"
        log_header "╚═══════════════════════════════════════════════════════╝"
        echo ""
        
        echo "🐋 DOCKER-BLOCK STATUS:"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        
        if sudo nft list table inet docker-block &>/dev/null; then
            log_success "Table: ACTIVE"
            
            local ipv4_count
            ipv4_count=$(sudo nft list set inet docker-block docker-banned-ipv4 2>/dev/null | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | wc -l)
            
            local ipv6_count
            ipv6_count=$(sudo nft list set inet docker-block docker-banned-ipv6 2>/dev/null | grep -oE '([0-9a-f:]+:[0-9a-f:]+)' | wc -l || echo "0")
            
            local blocked_ports
            blocked_ports=$(sudo nft list set inet docker-block docker-blocked-ports 2>/dev/null | grep -oE '[0-9]+' | head -1)
            
            echo "  IPv4 Banned: $ipv4_count IPs"
            echo "  IPv6 Banned: $ipv6_count IPs"
            if [ -n "$blocked_ports" ]; then
                echo "  Blocked Ports: $blocked_ports"
            fi
        else
            log_error "Table: NOT FOUND"
        fi
        
        echo ""
        echo "🔥 FAIL2BAN STATUS:"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        
        local total=0
        local active_jails=0
        
        for jail in "${JAILS[@]}"; do
            local count
            count=$(get_f2b_count "$jail" | tr -d '[:space:]')
            count=${count:-0}
            
            if [ "$count" -gt 0 ]; then
                printf "  %-30s %s\n" "$jail:" "${RED}$count IPs${NC}"
                ((active_jails++))
                ((total+=count))
            fi
        done
        
        if [ "$active_jails" -eq 0 ]; then
            log_success "  All jails clean ✅"
        else
            echo ""
            echo "  Active Jails: $active_jails | Total: $total IPs"
        fi
        
        echo ""
        echo "⚠️ RECENT ATTACKS (Last hour):"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        
        local lasthour
        lasthour=$(grep "$(date -d '1 hour ago' '+%Y-%m-%d %H')" /var/log/fail2ban.log 2>/dev/null | grep -c "Ban" || echo "0")
        
        if [ "$lasthour" -gt 50 ]; then
            log_alert "CRITICAL: $lasthour attacks! 🚨"
        elif [ "$lasthour" -gt 20 ]; then
            log_warn "HIGH: $lasthour attacks"
        elif [ "$lasthour" -gt 0 ]; then
            log_info "Medium: $lasthour attacks"
        else
            log_success "LOW: 0 attacks ✅"
        fi
        
        echo ""
        echo "🎯 TOP 5 ATTACKERS:"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        
        if [ -f /var/log/fail2ban.log ]; then
            local rank=1
            grep -h "Ban" /var/log/fail2ban.log 2>/dev/null | tail -500 | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort | uniq -c | sort -rn | head -5 | while read -r count ip; do
                printf "  %d. ${YELLOW}%-15s${NC} %s attacks\n" "$rank" "$ip" "$count"
                ((rank++))
            done
        else
            log_error "Log file not found"
        fi
        
        echo ""
        echo "📊 SYNC STATUS:"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        
        local f2b_total=0
        for jail in "${JAILS[@]}"; do
            local count
            count=$(get_f2b_count "$jail" | tr -d '[:space:]')
            count=${count:-0}
            ((f2b_total+=count))
        done
        
        if [ "$f2b_total" -eq "$ipv4_count" ]; then
            log_success "Fail2Ban ↔ Docker-Block: SYNCED ✅"
        else
            log_warn "Fail2Ban: $f2b_total, Docker-Block: $ipv4_count (DIFF: $((f2b_total - ipv4_count)))"
        fi
        
        if sudo crontab -l 2>/dev/null | grep -q "f2b-docker-sync"; then
            log_success "Auto-sync: ACTIVE (every minute) ✅"
        else
            log_error "Auto-sync: NOT CONFIGURED"
        fi
        
        echo ""
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "Press Ctrl+C to exit | Refresh in 5 seconds..."
        echo ""
        
        sleep 5
    done
}

f2b_docker_commands() {
    case "$2" in
        dashboard)
            f2b_docker_dashboard
            ;;
        info)
            f2b_docker_info
            ;;
        sync)
            f2b_sync_docker
            ;;
        *)
            cat <<EOF
Usage: f2b docker COMMAND

COMMANDS:
  dashboard     Real-time monitoring dashboard
  info          Show docker-block configuration
  sync          Synchronize fail2ban ↔ docker-block

Examples:
  sudo f2b docker dashboard
  sudo f2b docker info
  sudo f2b docker sync
EOF
            ;;
    esac
}

################################################################################
# MANAGE FUNCTIONS
################################################################################

manage_block_port() {
    local port
    port="$1"
    if [ -z "$port" ]; then
        log_error "Usage: manage block-port <port>"
        return 1
    fi

    if ! validate_port "$port"; then
        return 1
    fi

    log_header "Blocking port $port (persistent)"

    if sudo nft add element inet docker-block docker-blocked-ports "{ $port }" 2>/dev/null; then
        log_success "Port $port added to runtime"
    else
        log_warn "Port $port might already be in runtime set"
    fi

    local NFT_DOCKER_CONF="/etc/nftables/docker-block.nft"

    if [ ! -f "$NFT_DOCKER_CONF" ]; then
        log_error "Config file not found: $NFT_DOCKER_CONF"
        return 1
    fi

    local CURRENT_PORTS
    CURRENT_PORTS=$(sudo nft list set inet docker-block docker-blocked-ports 2>/dev/null | \
    grep -oE '[0-9]+' | sort -un | tr '\n' ',' | sed 's/,$//')

    if [ -z "$CURRENT_PORTS" ]; then
        log_warn "No ports in runtime set"
        return 0
    fi

    sudo cp "$NFT_DOCKER_CONF" "${NFT_DOCKER_CONF}.backup-$(date +%Y%m%d-%H%M%S)" 2>/dev/null || true

    sudo sed -i '/set docker-blocked-ports {/,/}/c\
set docker-blocked-ports {\
type inet_service\
flags interval\
auto-merge\
elements = { '"$CURRENT_PORTS"' }\
}' "$NFT_DOCKER_CONF"

    log_success "Port $port persisted to $NFT_DOCKER_CONF"
    log_info "Blocked ports: $CURRENT_PORTS"

    echo ""
}

manage_unblock_port() {
    local port
    port="$1"
    if [ -z "$port" ]; then
        log_error "Usage: manage unblock-port <port>"
        return 1
    fi

    if ! validate_port "$port"; then
        return 1
    fi

    log_header "Unblocking port $port (persistent)"

    if sudo nft delete element inet docker-block docker-blocked-ports "{ $port }" 2>/dev/null; then
        log_success "Port $port removed from runtime"
    else
        log_error "Port $port not found in runtime"
        return 1
    fi

    local NFT_DOCKER_CONF="/etc/nftables/docker-block.nft"

    if [ ! -f "$NFT_DOCKER_CONF" ]; then
        log_error "Config file not found: $NFT_DOCKER_CONF"
        return 1
    fi

    local CURRENT_PORTS
    CURRENT_PORTS=$(sudo nft list set inet docker-block docker-blocked-ports 2>/dev/null | \
    grep -oE '[0-9]+' | sort -un | tr '\n' ',' | sed 's/,$//')

    sudo cp "$NFT_DOCKER_CONF" "${NFT_DOCKER_CONF}.backup-$(date +%Y%m%d-%H%M%S)" 2>/dev/null || true

    if [ -z "$CURRENT_PORTS" ]; then
        sudo sed -i '/set docker-blocked-ports {/,/}/c\
set docker-blocked-ports {\
type inet_service\
flags interval\
auto-merge\
elements = { }\
}' "$NFT_DOCKER_CONF"

        log_success "Port $port removed - no ports left in set"
    else
        sudo sed -i '/set docker-blocked-ports {/,/}/c\
set docker-blocked-ports {\
type inet_service\
flags interval\
auto-merge\
elements = { '"$CURRENT_PORTS"' }\
}' "$NFT_DOCKER_CONF"

        log_success "Port $port removed - remaining: $CURRENT_PORTS"
    fi

    echo ""
}

manage_list_blocked_ports() {
    log_header "BLOCKED PORTS"
    sudo nft list set inet docker-block docker-blocked-ports 2>/dev/null || log_warn "No blocked ports or docker-block table missing"

    echo ""
}

manage_manual_ban() {
    local ip
    ip="$1"
    local timeout
    timeout="${2:-7d}"
    if [ -z "$ip" ]; then
        log_error "Usage: manage manual-ban <ip> [timeout]"
        return 1
    fi

    if ! validate_ip "$ip"; then
        return 1
    fi

    log_header "Banning $ip ($timeout)"

    if sudo nft add element "$F2BTABLE" f2b-manualblock "{ $ip timeout $timeout }" 2>/dev/null; then
        log_success "Banned"
    else
        log_warn "Already banned"
    fi

    echo ""
}

manage_manual_unban() {
    local ip
    ip="$1"
    if [ -z "$ip" ]; then
        log_error "Usage: manage manual-unban <ip>"
        return 1
    fi

    if ! validate_ip "$ip"; then
        return 1
    fi

    log_header "Unbanning $ip"

    if sudo nft delete element "$F2BTABLE" f2b-manualblock "{ $ip }" 2>/dev/null; then
        log_success "Unbanned"
    else
        log_error "Not found"
    fi

    echo ""
}

manage_unban_all() {
    local ip
    ip="$1"
    if [ -z "$ip" ]; then
        log_error "Usage: manage unban-all <ip>"
        return 1
    fi

    if ! validate_ip "$ip"; then
        return 1
    fi

    log_header "Unbanning $ip from ALL jails"

    echo ""

    local found
    found=0
    local unbanned
    unbanned=0

    for jail in "${JAILS[@]}"; do
        if sudo fail2ban-client status "$jail" 2>/dev/null | grep -q "$ip"; then
            found=1
            if sudo fail2ban-client set "$jail" unbanip "$ip" 2>/dev/null; then
                log_success "[$jail] unbanned"
                ((unbanned++))
            else
                log_warn "[$jail] failed to unban"
            fi
        fi
    done

    echo ""

    if [ "$found" -eq 0 ]; then
        log_warn "IP $ip not found in any fail2ban jail"
        log_info "Checking nftables sets..."
    else
        log_success "Unbanned from $unbanned fail2ban jail(s)"
        log_info "Running sync to update nftables..."
    fi

    local removed
    removed=0

    for jail in "${JAILS[@]}"; do
        local nftset
        nftset="${SETMAP[$jail]}"
        if sudo nft list set "$F2BTABLE" "$nftset" 2>/dev/null | grep -q "$ip"; then
            if sudo nft delete element "$F2BTABLE" "$nftset" "{ $ip }" 2>/dev/null; then
                log_info "Removed from nftables: $nftset"
                ((removed++))
            fi
        fi
    done

    if [ "$removed" -gt 0 ]; then
        log_success "Removed from $removed nftables set(s)"
    elif [ "$found" -eq 0 ]; then
        log_warn "IP $ip not found anywhere"
    else
        log_success "Sync completed"
    fi

    echo ""
}

manage_reload() {
    log_header "Reloading firewall"
    if sudo nft -c -f /etc/nftables.conf 2>/dev/null; then
        log_success "Syntax OK"
    else
        log_error "Syntax error"
        return 1
    fi

    if sudo systemctl reload nftables 2>/dev/null; then
        log_success "Reloaded"
    else
        sudo systemctl restart nftables
        log_success "Restarted"
    fi

    echo ""
}

manage_backup() {
    local file
    file="$BACKUPDIR/firewall-$(date +%Y%m%d-%H%M%S).tar.gz"
    mkdir -p "$BACKUPDIR"
    log_header "Backing up..."
    sudo tar czf "$file" \
    /etc/nftables.conf \
    /etc/nftables.d/ \
    /etc/nftables/*.nft \
    /etc/fail2ban/jail.d/ \
    2>/dev/null || true

    log_success "Backup: $file"

    echo ""
}

f2b_docker_info() {
    echo ""
    log_header "🐋 docker-block v${DOCKERBLOCKVERSION} - Status"
    echo ""

    if sudo nft list table inet docker-block &>/dev/null; then
        log_success "docker-block table: ACTIVE"
        echo ""

        echo "Behavior:"
        echo " • localhost (127.0.0.1): ALLOWED"
        echo " • Docker bridge (docker0): ALLOWED"
        echo " • External access: BLOCKED"
        echo ""

        echo "Blocked ports:"
        sudo nft list set inet docker-block docker-blocked-ports 2>/dev/null | grep "elements" || echo " (none)"

    else
        log_error "docker-block table: NOT FOUND"
        echo ""

        echo "To install:"
        echo " bash docker-block-v0.3-fix.sh"
    fi

    echo ""
}

################################################################################
# MONITOR FUNCTIONS
################################################################################

monitor_status() {
    log_header "FIREWALL STATUS"
    echo ""

    echo "Services:"
    echo " nftables: $(sudo systemctl is-active nftables)"
    echo " fail2ban: $(sudo systemctl is-active fail2ban)"
    echo " ufw: $(sudo systemctl is-active ufw)"
    echo ""

    echo "Active Jails:"
    local active
    active=0
    for jail in "${JAILS[@]}"; do
        local count
        count=$(get_f2b_count "$jail" | tr -d '[:space:]')
        count=${count:-0}
        if [ "$count" -gt 0 ]; then
            echo " $jail: $count"
            ((active++))
        fi
    done

    if [ "$active" -eq 0 ]; then
        echo " (all clean)"
    fi

    echo ""
}

monitor_show_bans() {
    local jail
    jail="${1:-all}"
    log_header "BANNED IPs"
    if [ "$jail" = "all" ]; then
        for j in "${JAILS[@]}"; do
            local ips
            ips=$(get_f2b_ips "$j")
            if [ -n "$ips" ]; then
                echo "$j:"
                echo "$ips" | sed 's/^/ /'
                echo ""
            fi
        done
    else
        local ips
        ips=$(get_f2b_ips "$jail")
        if [ -n "$ips" ]; then
            echo "$jail:"
            echo "$ips" | sed 's/^/ /'
        else
            log_warn "No IPs banned in $jail"
        fi
    fi

    echo ""
}

monitor_top_attackers() {
    log_header "TOP ATTACKERS (Historical)"
    if [ ! -f /var/log/fail2ban.log ]; then
        log_error "Fail2Ban log not found"
        return 1
    fi

    local temp_file
    temp_file="/tmp/attackers-$$.tmp"

    grep -h "Ban" /var/log/fail2ban.log 2>/dev/null | \
    tail -1000 | \
    grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | \
    sort | uniq -c | sort -rn | head -10 > "$temp_file" 2>/dev/null || true

    if [ ! -s "$temp_file" ]; then
        log_info "No attack data available"
        rm -f "$temp_file"
        return 0
    fi

    echo ""

    local rank
    rank=1
    while IFS= read -r line; do
        local count
        count=$(echo "$line" | awk '{print $1}')
        local ip
        ip=$(echo "$line" | awk '{print $2}')
        echo -e "${YELLOW}$rank.${NC} $ip ${RED}($count bans)${NC}"
        rank=$((rank + 1))
    done < "$temp_file"
    rm -f "$temp_file"

    echo ""
}

monitor_watch() {
    while true; do
        clear
        echo "=========================================="
        echo " REAL-TIME MONITORING"
        echo "=========================================="
        echo ""

        local total
        total=0
        for jail in "${JAILS[@]}"; do
            local count
            count=$(get_f2b_count "$jail" | tr -d '[:space:]')
            count=${count:-0}
            if [ "$count" -gt 0 ]; then
                echo " $jail: $count"
                ((total+=count))
            fi
        done

        echo ""
        echo "Total: $total"
        echo ""
        echo "Updated: $(date '+%H:%M:%S')"
        echo "Press Ctrl+C to exit"
        echo ""
        sleep 5
    done
}

monitor_jail_log() {
    local jail
    jail="$1"
    local lines
    lines="${2:-20}"
    if [ -z "$jail" ]; then
        log_error "Usage: monitor jail-log <jail> [lines]"
        return 1
    fi

    log_header "Recent activity for jail: $jail"
    echo ""

    if [ ! -f /var/log/fail2ban.log ]; then
        log_error "Fail2Ban log not found"
        return 1
    fi

    grep "\[$jail\]" /var/log/fail2ban.log 2>/dev/null | tail -n "$lines" || \
    log_warn "No logs found for $jail"

    echo ""
}

monitor_trends() {
    log_header "ATTACK TREND ANALYSIS"
    if [ ! -f /var/log/fail2ban.log ]; then
        log_error "Fail2Ban log not found"
        return 1
    fi

    echo ""

    local last_hour
    last_hour=$(grep "$(date -d '1 hour ago' +%Y-%m-%d\ %H)" /var/log/fail2ban.log 2>/dev/null | grep -c "Ban\|Found" || echo "0")

    local last_6h
    last_6h=$(grep "$(date -d '6 hours ago' +%Y-%m-%d)" /var/log/fail2ban.log 2>/dev/null | grep -c "Ban\|Found" || echo "0")

    local last_24h
    last_24h=$(grep "$(date -d '1 day ago' +%Y-%m-%d)" /var/log/fail2ban.log 2>/dev/null | grep -c "Ban\|Found" || echo "0")

    echo -e "Last hour: ${YELLOW}$last_hour${NC} attempts"
    echo -e "Last 6h: ${YELLOW}$last_6h${NC} attempts"
    echo -e "Last 24h: ${YELLOW}$last_24h${NC} attempts"
    echo ""

    last_hour=$(echo "$last_hour" | tr -d '[:space:]' | grep -oE '^[0-9]+$' || echo "0")
    last_6h=$(echo "$last_6h" | tr -d '[:space:]' | grep -oE '^[0-9]+$' || echo "0")
    last_24h=$(echo "$last_24h" | tr -d '[:space:]' | grep -oE '^[0-9]+$' || echo "0")

    if [ "$last_hour" -gt 50 ]; then
        log_alert "⚠️ CRITICAL: HIGH ATTACK INTENSITY!"
        echo ""
        log_info "Recommended actions:"
        log_info " • Review logs: f2b monitor jail-log <jail>"
        log_info " • Check top attackers: f2b monitor top-attackers"
        log_info " • Consider enabling stricter rules"
    elif [ "$last_hour" -gt 20 ]; then
        log_warn "⚠️ WARNING: Elevated attack activity"
    else
        log_success "✅ Attack levels normal"
    fi

    echo ""
}

################################################################################
# REPORT FUNCTIONS (NEW v0.19)
################################################################################

report_json() {
    log_header "JSON EXPORT"
    local total_bans
    total_bans=0
    local jail_stats
    jail_stats=""
    for jail in "${JAILS[@]}"; do
        local count
        count=$(get_f2b_count "$jail")
        total_bans=$((total_bans + count))
        jail_stats="${jail_stats} \"$jail\": $count,\n"
    done

    jail_stats=$(echo -e "$jail_stats" | sed '$ s/,$//')

    cat << EOF
{
"timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
"version": "$VERSION",
"services": {
"nftables": "$(systemctl is-active nftables 2>/dev/null || echo 'unknown')",
"fail2ban": "$(systemctl is-active fail2ban 2>/dev/null || echo 'unknown')",
"docker_block": "$(sudo nft list table inet docker-block &>/dev/null && echo 'active' || echo 'inactive')"
},
"statistics": {
"total_bans": $total_bans,
"jails": {
$(echo -e "$jail_stats")
}
},
"generated_by": "F2B Wrapper v$VERSION"
}
EOF

    echo ""
}

report_csv() {
    log_header "CSV EXPORT"
    echo "Timestamp,Jail,Banned_IPs,Status"
    for jail in "${JAILS[@]}"; do
        local count
        count=$(get_f2b_count "$jail")
        local status
        status="active"
        [ "$count" -eq 0 ] && status="clean"
        echo "$(date +%Y-%m-%d\ %H:%M:%S),$jail,$count,$status"
    done

    echo ""
}

report_daily() {
    log_header "DAILY REPORT"
    echo "Generated: $(date '+%Y-%m-%d %H:%M:%S')"
    echo ""

    echo "Services:"
    echo " nftables: $(systemctl is-active nftables 2>/dev/null || echo 'unknown')"
    echo " fail2ban: $(systemctl is-active fail2ban 2>/dev/null || echo 'unknown')"
    echo ""

    echo "Jail Statistics:"
    local total
    total=0
    for jail in "${JAILS[@]}"; do
        local count
        count=$(get_f2b_count "$jail")
        [ "$count" -gt 0 ] && echo " $jail: $count"
        total=$((total + count))
    done

    echo ""
    echo "Total banned IPs: $total"
    echo ""

    echo "Top 5 Attackers:"
    if [ -f /var/log/fail2ban.log ]; then
        grep -h "Ban" /var/log/fail2ban.log 2>/dev/null | \
        tail -500 | \
        grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | \
        sort | uniq -c | sort -rn | head -5 | \
        awk '{print " " $2 " (" $1 " bans)"}'
    else
        echo " (log not available)"
    fi

    echo ""
}

audit_silent() {
    local LOG_FILE
    LOG_FILE="/var/log/f2b-audit.log"
    local TOTAL
    TOTAL=0

    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Audit started" >> "$LOG_FILE"
    for jail in "${JAILS[@]}"; do
        local count
        count=$(get_f2b_count "$jail")
        TOTAL=$((TOTAL + count))
        [ "$count" -gt 0 ] && echo " $jail: $count IPs" >> "$LOG_FILE"
    done

    if [ "$TOTAL" -eq 0 ]; then
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] Status: ALL CLEAN" >> "$LOG_FILE"
    else
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] Total banned: $TOTAL" >> "$LOG_FILE"
    fi
}

stats_quick() {
    local total
    total=0
    for jail in "${JAILS[@]}"; do
        local count
        count=$(get_f2b_count "$jail")
        total=$((total + count))
    done

    echo "Total: $total | nftables: $(systemctl is-active nftables 2>/dev/null) | fail2ban: $(systemctl is-active fail2ban 2>/dev/null)"
}

################################################################################
# HELP
################################################################################

show_help() {
    cat << 'EOF'

═══════════════════════════════════════════════════════════════════
F2B UNIFIED WRAPPER v0.23
Fail2Ban + nftables Complete Management
═══════════════════════════════════════════════════════════════════

USAGE: f2b [args]

CORE:
  status                 Show comprehensive status
  audit                  Audit all jails
  find <IP>              Find IP in jails
  version                Show version info

SYNC:
  sync check             Verify F2B ↔ nftables sync
  sync enhanced          Enhanced bidirectional sync
  sync force             Force sync + verify
  sync silent            Silent sync (for cron)
  sync docker            Docker-block sync (NEW v0.23)

DOCKER (NEW v0.23):
  docker dashboard       Real-time monitoring dashboard
  docker info            Show docker-block configuration
  docker sync            Synchronize fail2ban ↔ docker-block

MANAGE - PORT BLOCKING:
  manage block-port <port>           Block Docker port
  manage unblock-port <port>         Unblock port
  manage list-blocked-ports          List blocked ports
  manage docker-info                 Show docker-block status

MANAGE - IP BAN/UNBAN:
  manage manual-ban <IP> [time]      Ban IP manually
  manage manual-unban <IP>           Unban IP
  manage unban-all <IP>              Unban IP from ALL jails

MANAGE - SYSTEM:
  manage reload                      Reload firewall
  manage backup                      Backup configuration

MONITOR:
  monitor status                     System overview
  monitor show-bans [jail]           Show banned IPs
  monitor top-attackers              Top 10 attackers (historical)
  monitor watch                      Real-time monitoring
  monitor jail-log <jail> [lines]    Show jail log
  monitor trends                     Attack trend analysis

REPORTS:
  report json                        Export as JSON
  report csv                         Export as CSV
  report daily                       Daily summary report

SILENT (for cron):
  audit-silent                       Silent audit
  stats-quick                        Quick stats

EXAMPLES:
  sudo f2b status
  sudo f2b audit
  sudo f2b find 1.2.3.4
  sudo f2b sync force
  sudo f2b docker dashboard          (NEW v0.23 - live monitoring!)
  sudo f2b sync docker               (NEW v0.23 - docker sync)
  sudo f2b manage block-port 8081
  sudo f2b manage manual-ban 192.0.2.1 30d
  sudo f2b monitor trends
  sudo f2b monitor jail-log sshd 50
  sudo f2b report json > /tmp/f2b-report.json
  sudo f2b monitor watch

ALIASES (if configured):
  f2b-status, f2b-audit, f2b-sync, f2b-find, f2b-watch
  f2b-block-port, f2b-unblock-port, f2b-list-ports
  f2b-ban, f2b-unban
  f2b-docker-dashboard, f2b-docker-sync, f2b-sync-docker (NEW v0.23)

═══════════════════════════════════════════════════════════════════

EOF
}

################################################################################
# MAIN ROUTING
################################################################################

main() {
    # Acquire lock for write operations
    case "$1" in
        sync|manage)
            acquire_lock
            ;;
    esac

    case "$1" in
        # Core commands
        status)
            f2b_status
            ;;
        audit)
            f2b_audit
            ;;
        find)
            f2b_find "$2"
            ;;
        version|--version|-v)
            f2b_version
            ;;

        # Sync commands
        sync)
            case "$2" in
                check) f2b_sync_check ;;
                enhanced) f2b_sync_enhanced ;;
                force) f2b_sync_force ;;
                silent) sync_silent ;;
                docker) f2b_sync_docker ;;
                *) show_help ;;
            esac
            ;;

        # Docker commands (NEW v0.23)
        docker)
            f2b_docker_commands "$@"
            ;;

        # Manage commands
        manage)
            case "$2" in
                block-port) manage_block_port "$3" ;;
                unblock-port) manage_unblock_port "$3" ;;
                list-blocked-ports) manage_list_blocked_ports ;;
                docker-info) f2b_docker_info ;;
                manual-ban) manage_manual_ban "$3" "$4" ;;
                manual-unban) manage_manual_unban "$3" ;;
                unban-all) manage_unban_all "$3" ;;
                reload) manage_reload ;;
                backup) manage_backup ;;
                *) show_help ;;
            esac
            ;;

        # Monitor commands
        monitor)
            case "$2" in
                status) monitor_status ;;
                show-bans) monitor_show_bans "$3" ;;
                top-attackers) monitor_top_attackers ;;
                watch) monitor_watch ;;
                jail-log) monitor_jail_log "$3" "$4" ;;
                trends) monitor_trends ;;
                *) show_help ;;
            esac
            ;;

        # Report commands
        report)
            case "$2" in
                json) report_json ;;
                csv) report_csv ;;
                daily) report_daily ;;
                *) show_help ;;
            esac
            ;;

        # Silent commands (for cron)
        audit-silent)
            audit_silent
            ;;

        stats-quick)
            stats_quick
            ;;

        # Help
        help|--help|-h|"")
            show_help
            ;;

        *)
            log_error "Unknown command: $1"
            show_help
            return 1
            ;;
    esac

    # Initialize log file
    mkdir -p "$(dirname "$LOGFILE")"
    touch "$LOGFILE"
}

main "$@"
