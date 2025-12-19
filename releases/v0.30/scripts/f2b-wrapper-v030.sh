#!/bin/bash

################################################################################
# F2B Unified Wrapper v0.24 - PRODUCTION
# Complete Fail2Ban + nftables + docker-block management
#
# REQUIREMENTS:
# - fail2ban
# - nftables
# - jq (JSON processor) - install: sudo apt install jq
#
# v0.24 CHANGES (2025-12-14):
# + Fixed docker-block IP counting using jq for accurate element count
# + Fixed duplicate log entries in docker-sync (removed tee -a)
# + Improved find command docker-block detection (nft get element)
# + Enhanced docker sync to handle nftables auto-merge ranges
# + Updated sync messaging: info for ±1-5 diff (auto-merge normal)
# + Fixed main() structure - moved log init to function start
# + All v0.23 functions preserved and enhanced
#
# v0.23 CHANGES:
# + Docker-block sync integration (f2b sync docker)
# + Real-time dashboard (f2b docker dashboard)
# + Docker info command (f2b docker info)
# + Docker command dispatcher (f2b docker COMMAND)
################################################################################
################################################################################
# Component: F2B Wrapper
# Part of: Fail2Ban Hybrid Nftables Manager
################################################################################

set -o pipefail
# shellcheck disable=SC2034
RELEASE="v0.30"
# shellcheck disable=SC2034
VERSION="0.30"
# shellcheck disable=SC2034
BUILD_DATE="2025-12-19"
# shellcheck disable=SC2034
COMPONENT_NAME="F2B-WRAPPER"
# shellcheck disable=SC2034
DOCKERBLOCKVERSION="0.4"

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
NPM_LOG_DIR="/opt/rustnpm/data/logs"

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
# JQ HELPER FUNCTIONS (NEW v025)


################################################################################
# JQ HELPER FUNCTIONS (NEW v025)
################################################################################
jq_check_installed() {
    if ! command -v jq &>/dev/null; then
        log_warn "jq not installed - falling back to grep/awk"
        return 1
    fi
    return 0
}

clean_number() {
    local val="$1"
    # Remove newlines, carriage returns, and extract only numbers
    val=$(echo "$val" | tr -d '\n\r' | grep -oE '[0-9]+' | head -1)
    echo "${val:-0}"
}

jq_safe_parse() {
    local input="$1"
    local query="$2"
    if ! jq_check_installed; then
        echo "{}"
        return 1
    fi
    echo "$input" | jq empty 2>/dev/null && echo "$input" | jq -r "$query" 2>/dev/null || echo "{}"
}

jq_prettify() {
    if jq_check_installed; then
        jq -C '.' 2>/dev/null || cat
    else
        cat
    fi
}


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
    local mode="${1:---human}"

    case "$mode" in
        --json)
            local binary_path
            binary_path=$(readlink -f "$(command -v f2b)" 2>/dev/null || echo "/usr/local/bin/f2b")

            local jails_count=0
            if systemctl is-active --quiet fail2ban 2>/dev/null; then
                jails_count=$(
                    fail2ban-client status 2>/dev/null \
                        | grep "Jail list:" \
                        | sed 's/.*://' \
                        | tr ',' '\n' \
                        | grep -c . \
                        || echo 0
                )
            fi

            cat <<EOF
{
  "release": "$RELEASE",
  "version": "$VERSION",
  "build_date": "$BUILD_DATE",
  "binary_path": "$binary_path",
  "components": {
    "dockerblock": "$DOCKERBLOCKVERSION",
    "jails_count": $jails_count,
    "nftables_table": "inet fail2ban-filter"
  }
}
EOF
            ;;

        --short)
            echo "$RELEASE"
            ;;

        --human|*)
            log_header "═══════════════════════════════════════════════"
            echo "  F2B Hybrid Manager"
            echo "  Release: $RELEASE"
            echo "  Build: $BUILD_DATE"
            log_header "═══════════════════════════════════════════════"
            echo ""

            echo "Runtime:"
            local f2b_path
            f2b_path=$(command -v f2b 2>/dev/null || echo "not in PATH")
            echo "  Binary: $f2b_path"

            if [ -x "$f2b_path" ] && [ "$f2b_path" != "not in PATH" ]; then
                local checksum
                checksum=$(sha256sum "$f2b_path" 2>/dev/null | awk '{print $1}' | cut -c1-16 || echo "unavailable")
                echo "  Checksum: sha256:${checksum}..."
            fi
            echo ""

            echo "Components:"
            echo "  - Fail2Ban nftables integration"
            echo "  - Docker port blocking v$DOCKERBLOCKVERSION"
            echo "  - Enhanced sync monitoring"
            echo "  - Attack analysis & reporting"
            echo "  - Real-time Dashboard"
            echo ""

            if systemctl is-active --quiet fail2ban 2>/dev/null; then
                echo "Configuration:"

                if nft list table inet fail2ban-filter &>/dev/null 2>&1; then
                    echo "  - Table: inet fail2ban-filter ✓"

                    local jails_active
                    jails_active=$(
                        fail2ban-client status 2>/dev/null \
                            | grep "Jail list:" \
                            | sed 's/.*://' \
                            | tr ',' '\n' \
                            | grep -c . \
                            || echo 0
                    )
                    echo "  - Jails: $jails_active active"

                    # Sets: count only wrapper-managed sets (SETMAP), split v4/v6
                    local sets_v4=0
                    local sets_v6=0
                    local missing_v6=0

                    local jail setname
                    for jail in "${JAILS[@]}"; do
                        setname="${SETMAP[$jail]}"
                        [ -z "$setname" ] && continue

                        # v4 set
                        if sudo nft list set inet fail2ban-filter "$setname" &>/dev/null; then
                            ((sets_v4++))
                        fi

                        # v6 set (expected as "${setname}-v6" in your design)
                        if sudo nft list set inet fail2ban-filter "${setname}-v6" &>/dev/null; then
                            ((sets_v6++))
                        else
                            ((missing_v6++))
                        fi
                    done

                    local sets_total=$((sets_v4 + sets_v6))
                    echo "  - Sets: $sets_total ($sets_v4 v4 + $sets_v6 v6, missing v6: $missing_v6)"
                else
                    echo "  - Table: inet fail2ban-filter (not found)"
                fi
            else
                echo "Configuration:"
                echo "  - Fail2Ban: not running"
            fi
            echo ""

            echo "Usage:"
            echo "  f2b help            - Show all commands"
            echo "  f2b status          - System status"
            echo "  f2b version --json  - JSON output"
            echo "  f2b version --short - Short version"
            ;;
    esac
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
    if sudo ufw status 2>/dev/null | grep -q "Status: active"; then
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
                
                # ✨ NOVÉ - Ukáž metadata ak je jq dostupné
                if jq_check_installed; then
                    local metadata
                    metadata=$(sudo nft --json list set inet fail2ban-filter "$nftset" 2>/dev/null | \
                        jq -r ".nftables[] | select(.set.elem) | .set.elem[] | select(.elem) | \
                        select(.elem.val == \"$IP\") | \
                        \"  ↳ timeout: \(.elem.timeout // \"permanent\"), expires: \(.elem.expires // \"never\")\"" 2>/dev/null)
                    
                    if [ -n "$metadata" ]; then
                        echo -e "${CYAN}$metadata${NC}"
                    fi
                fi
            else
                log_warn "nftables: NOT in $nftset (sync issue!)"
            fi
            
            # Check docker-block
            if sudo nft list table inet docker-block &>/dev/null; then
                if sudo nft get element inet docker-block docker-banned-ipv4 "{ \"$IP\" }" &>/dev/null; then
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
        log_info  "Install with: bash 03-install-docker-block-v04.sh"
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
    # IPv4 SYNC - UNION approach with nft get element
    ############################################################################

    # 1. ALL IPv4 z VŠETKÝCH fail2ban setov (UNION)
    local F2B_IPS
    F2B_IPS=$(
        for SET in "${SETS[@]}"; do
            sudo nft list set inet fail2ban-filter "$SET" 2>/dev/null \
                | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' || true
        done | sort | uniq
    )

    # 2. PRIDAJ - v F2B ALE NIE v docker-block (test cez nft get element)
    while IFS= read -r IP; do
        [ -z "$IP" ] && continue

        # ✅ Testuj členstvo priamo v nftables (funguje aj pre auto-merged rozsahy)
        if ! sudo nft get element inet docker-block docker-banned-ipv4 "{ $IP }" &>/dev/null; then
            sudo nft add element inet docker-block docker-banned-ipv4 "{ $IP timeout 1h }" 2>/dev/null || true
            echo "[$(date +'%Y-%m-%d %H:%M:%S')] ADDED: $IP" >> "$LOG_FILE"
        fi
    done <<< "$F2B_IPS"

    # 3. ODSTRÁŇ - v docker-block ALE NIE v F2B
    # Pre removal musíme získať skutočné IP z docker-block
    local DOCKER_IPS
    DOCKER_IPS=$(
        sudo nft list set inet docker-block docker-banned-ipv4 2>/dev/null \
            | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort | uniq || true
    )

    while IFS= read -r IP; do
        [ -z "$IP" ] && continue

        # Skontroluj či IP JE v niektorom fail2ban sete
        if ! echo "$F2B_IPS" | grep -q "^$IP$"; then
            sudo nft delete element inet docker-block docker-banned-ipv4 "{ $IP }" 2>/dev/null || true
            echo "[$(date +'%Y-%m-%d %H:%M:%S')] REMOVED: $IP (no longer in fail2ban)" >> "$LOG_FILE"
        fi
    done <<< "$DOCKER_IPS"

    ############################################################################
    # IPv6 SYNC - UNION approach with nft get element
    ############################################################################

    # 1. ALL IPv6 z VŠETKÝCH fail2ban setov
    F2B_IPS=$(
        for SET in "${SETS[@]}"; do
            sudo nft list set inet fail2ban-filter "$SET-v6" 2>/dev/null \
                | grep -oE '([0-9a-f:]+:[0-9a-f:]+)' || true
        done | sort | uniq
    )

    # 2. PRIDAJ IPv6 (test cez nft get element)
    while IFS= read -r IP; do
        [ -z "$IP" ] && continue

        if ! sudo nft get element inet docker-block docker-banned-ipv6 "{ $IP }" &>/dev/null; then
            sudo nft add element inet docker-block docker-banned-ipv6 "{ $IP timeout 1h }" 2>/dev/null || true
            echo "[$(date +'%Y-%m-%d %H:%M:%S')] ADDED (IPv6): $IP" >> "$LOG_FILE"
        fi
    done <<< "$F2B_IPS"

    # 3. ODSTRÁŇ IPv6
    DOCKER_IPS=$(
        sudo nft list set inet docker-block docker-banned-ipv6 2>/dev/null \
            | grep -oE '([0-9a-f:]+:[0-9a-f:]+)' | sort | uniq || true
    )

    while IFS= read -r IP; do
        [ -z "$IP" ] && continue

        if ! echo "$F2B_IPS" | grep -q "^$IP$"; then
            sudo nft delete element inet docker-block docker-banned-ipv6 "{ $IP }" 2>/dev/null || true
            echo "[$(date +'%Y-%m-%d %H:%M:%S')] REMOVED (IPv6): $IP (no longer in fail2ban)" >> "$LOG_FILE"
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

    # W: IP v docker-block - ✅ PRESNÝ COUNT s jq
    local DOCKER_IP_COUNT
    DOCKER_IP_COUNT=$(sudo nft -j list set inet docker-block docker-banned-ipv4 2>/dev/null \
                   | jq -r '.nftables[] | select(.set.elem) | .set.elem | length' 2>/dev/null \
                   | head -1)
    DOCKER_IP_COUNT=${DOCKER_IP_COUNT:-0}

    echo ""
    log_header "SYNC METRICS"
    log_info    "Jails: ${TOTAL_JAIL_IPS} IP (duplicates: ${DUPLICATES}, unique: ${UNIQUE_IPS})"
    log_info    "Docker-block: ${DOCKER_IP_COUNT} elements (auto-merge may differ from IP count)"
    # Tolerancia ±5 pre auto-merge
    local DIFF=$((UNIQUE_IPS - DOCKER_IP_COUNT))
    local DIFF_ABS=${DIFF#-}  # absolútna hodnota

    if [ "$DOCKER_IP_COUNT" -eq "$UNIQUE_IPS" ]; then
        log_success "✅ Perfect sync: ${UNIQUE_IPS} == ${DOCKER_IP_COUNT}"
    elif [ "$DIFF_ABS" -le 5 ]; then
        log_info "ℹ️  Minor difference (±${DIFF_ABS}) - normal due to nftables auto-merge"
    else
        log_warn "⚠️  Significant difference: unique_jails=${UNIQUE_IPS}, docker-block=${DOCKER_IP_COUNT}"
fi


    # Summary - ✅ PRESNÝ COUNT s jq
    local FINAL_COUNT
    FINAL_COUNT=$(sudo nft -j list set inet docker-block docker-banned-ipv4 2>/dev/null \
                    | jq -r '.nftables[] | select(.set.elem) | .set.elem | length' 2>/dev/null \
                    | head -1)
    FINAL_COUNT=${FINAL_COUNT:-0}

    echo "[$(date +'%Y-%m-%d %H:%M:%S')] Sync complete - IPv4: $FINAL_COUNT IPs in docker-block" \
        >> "$LOG_FILE"

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
            ipv4_count=$(clean_number "$(sudo nft list set inet docker-block docker-banned-ipv4 2>/dev/null | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | wc -l)")
            
            local ipv6_count
            ipv6_count=$(clean_number "$(sudo nft list set inet docker-block docker-banned-ipv6 2>/dev/null | grep -oE '([0-9a-f:]+:[0-9a-f:]+)' | wc -l)")
            
            local blocked_ports
            blocked_ports=$(clean_number "$(sudo nft list set inet docker-block docker-blocked-ports 2>/dev/null | grep -oE '[0-9]+' | head -1)")
            
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
                printf "  %-30s %b\n" "$jail:" "${RED}$count IPs${NC}"
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

        # Use same method as monitor_trends() - Ban + Found
        local last_hour
            last_hour=$(grep "$(date -d '1 hour ago' '+%Y-%m-%d %H')" /var/log/fail2ban.log 2>/dev/null | grep -c "Ban\|Found" || echo "0")
            last_hour=$(clean_number "$last_hour")

        if [ "$last_hour" -gt 50 ]; then
            log_alert "⚠️  CRITICAL: $last_hour attempts!"
        elif [ "$last_hour" -gt 20 ]; then
            log_warn "⚠️  HIGH: $last_hour attempts"
        elif [ "$last_hour" -gt 0 ]; then
            log_info "🟡 MEDIUM: $last_hour attempts"
        else
            log_success "✅ QUIET: $last_hour attempts"
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
        echo " bash 03-install-docker-block-v04.sh"
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
            local count
            count=$(get_f2b_count "$j" | tr -d '[:space:]')
            count=${count:-0}
            
            if [ "$count" -gt 0 ]; then
                echo -e "${YELLOW}$j${NC} ($count IPs):"
                
                # ✨ NOVÉ - Zobraz IPs s metadata ak je jq dostupné
                if jq_check_installed; then
                    local nftset
                    nftset="${SETMAP[$j]}"
                    sudo nft --json list set inet fail2ban-filter "$nftset" 2>/dev/null | \
                        jq -r '.nftables[] | select(.set.elem) | .set.elem[] | select(.elem) | 
                        "  \(.elem.val), timeout: \(.elem.timeout // "permanent"), expires: \(.elem.expires // "never")"' 2>/dev/null || \
                        get_f2b_ips "$j" | while read -r ip; do echo "  $ip"; done
                else
                    # Fallback bez metadata
                    get_f2b_ips "$j" | while read -r ip; do echo "  $ip"; done
                fi
                echo ""
            fi
        done
    else
        local count
        count=$(get_f2b_count "$jail" | tr -d '[:space:]')
        count=${count:-0}
        
        if [ "$count" -gt 0 ]; then
            echo -e "${YELLOW}$jail${NC} ($count IPs):"
            
            # ✨ NOVÉ - Zobraz IPs s metadata
            if jq_check_installed; then
                local nftset
                nftset="${SETMAP[$jail]}"
                sudo nft --json list set inet fail2ban-filter "$nftset" 2>/dev/null | \
                    jq -r '.nftables[] | select(.set.elem) | .set.elem[] | select(.elem) | 
                    "  \(.elem.val), timeout: \(.elem.timeout // "permanent"), expires: \(.elem.expires // "never")"' 2>/dev/null || \
                    get_f2b_ips "$jail" | while read -r ip; do echo "  $ip"; done
            else
                # Fallback bez metadata
                get_f2b_ips "$jail" | while read -r ip; do echo "  $ip"; done
            fi
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

    # Sanitize numeric values
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
# ATTACK ANALYSIS FUNCTIONS (NEW v025)
################################################################################

analyze_npm_http_status() {
    log_header "NPM HTTP Status Analysis"
    echo ""

    local ACCESS_LOGS="$NPM_LOG_DIR/*_access.log"

    if ! sudo test -f "$NPM_LOG_DIR/proxy-host-1_access.log"; then
        log_warn "No NPM logs found at $NPM_LOG_DIR"
        return 1
    fi

    local RECENT_LOGS
    RECENT_LOGS=$(sudo tail -5000 "$ACCESS_LOGS" 2>/dev/null)

    # Count status codes
    local STATUS_400 STATUS_403 STATUS_404 STATUS_444 STATUS_499 STATUS_500
    STATUS_400=$(clean_number "$(echo "$RECENT_LOGS" | grep -c ' 400 ' 2>/dev/null)")
    STATUS_403=$(clean_number "$(echo "$RECENT_LOGS" | grep -c ' 403 ' 2>/dev/null)")
    STATUS_404=$(clean_number "$(echo "$RECENT_LOGS" | grep -c ' 404 ' 2>/dev/null)")
    STATUS_444=$(clean_number "$(echo "$RECENT_LOGS" | grep -c ' 444 ' 2>/dev/null)")
    STATUS_499=$(clean_number "$(echo "$RECENT_LOGS" | grep -c ' 499 ' 2>/dev/null)")
    STATUS_500=$(clean_number "$(echo "$RECENT_LOGS" | grep -c ' 500 ' 2>/dev/null)")

    local TOTAL_ERRORS=$((STATUS_400 + STATUS_403 + STATUS_404 + STATUS_444 + STATUS_499 + STATUS_500))

    echo " 400 Bad Request:      $STATUS_400 (malformed requests)"
    echo " 403 Forbidden:        $STATUS_403 (blocked by rules)"
    echo " 404 Not Found:        $STATUS_404 (scanner probes)"
    echo " 444 Connection Closed: $STATUS_444 (NPM rejected)"
    echo " 499 Client Closed:    $STATUS_499 (timeout)"
    echo " 500 Internal Error:   $STATUS_500"
    echo " ────────────────────────"
    echo " Total Error Responses: $TOTAL_ERRORS / 5000 requests"
    echo ""

    # Threat level assessment
    if [ "$TOTAL_ERRORS" -gt 1000 ]; then
        logalert "⚠️  HIGH ERROR RATE - Active attack in progress!"
    elif [ "$TOTAL_ERRORS" -gt 200 ]; then
        log_warn "⚠️  Elevated error rate - Scanning activity"
    else
        log_success "✅ Normal error rate"
    fi

    echo ""

    # Export metadata for summary
    export NPM_TOTAL_ERRORS="$TOTAL_ERRORS"
    export NPM_STATUS_404="$STATUS_404"
    export RECENT_LOGS
}

analyze_npm_attack_patterns() {
    log_header "NPM Attack Patterns (Last 24h)"
    echo ""

    if ! sudo test -f "$NPM_LOG_DIR/proxy-host-1_access.log"; then
        log_warn "No NPM logs available"
        return 1
    fi

    local ALL_LOGS
    ALL_LOGS=$(sudo cat "$NPM_LOG_DIR"/*_access.log 2>/dev/null)

    # Detect attack patterns
    local SQL_INJ PATH_TRAV PHP_EXPLOIT SHELL_RCE SCANNER GIT_EXPOSE
    SQL_INJ=$(clean_number "$(echo "$ALL_LOGS" | grep -iEc "union.*select|sqlmap|' and|' or|benchmark" 2>/dev/null)")
    PATH_TRAV=$(clean_number "$(echo "$ALL_LOGS" | grep -Ec "\.\./|\.\.\\\\\\\\" 2>/dev/null)")
    PHP_EXPLOIT=$(clean_number "$(echo "$ALL_LOGS" | grep -iEc "wp-admin|phpMyAdmin|admin\.php" 2>/dev/null)")
    SHELL_RCE=$(clean_number "$(echo "$ALL_LOGS" | grep -iEc "cmd=|exec=|/bin/bash|/bin/sh" 2>/dev/null)")
    SCANNER=$(clean_number "$(echo "$ALL_LOGS" | grep -iEc "nikto|nmap|masscan|sqlmap" 2>/dev/null)")
    GIT_EXPOSE=$(clean_number "$(echo "$ALL_LOGS" | grep -Ec "\.git/|\.env|\.config" 2>/dev/null)")

    echo " SQL Injection:        $SQL_INJ attempts"
    echo " Path Traversal:       $PATH_TRAV attempts"
    echo " PHP Exploits:         $PHP_EXPLOIT attempts"
    echo " Shell/RCE:            $SHELL_RCE attempts"
    echo " Scanner/Bot:          $SCANNER attempts"
    echo " Git/Config Exposure:  $GIT_EXPOSE attempts"

    # Calculate total and make it global (remove 'local')
    TOTAL_NPM_ATTACKS=$((SQL_INJ + PATH_TRAV + PHP_EXPLOIT + SHELL_RCE + SCANNER + GIT_EXPOSE))
    
    echo " ────────────────────────"
    echo " Total NPM Attacks:    $TOTAL_NPM_ATTACKS"
    echo ""

    # Export for summary (OPRAVENÉ - už je nastavená, len export)
    export TOTAL_NPM_ATTACKS
}


analyze_probed_paths() {
    log_header "Top 10 Most Probed Paths (404)"
    echo ""

    if [ -n "$RECENT_LOGS" ] && [ "$NPM_STATUS_404" -gt 0 ]; then
        echo "$RECENT_LOGS" | grep ' 404 ' | awk '{print $7}' | \
            sort | uniq -c | sort -rn | head -10 | \
            awk '{printf "  %5d x %s\n", $1, $2}'
    else
        echo "  None"
    fi

    echo ""
}

# ═══════════════════════════════════════════════════════════
# SSH ATTACK ANALYSIS FUNCTIONS
# ═══════════════════════════════════════════════════════════

analyze_ssh_attacks() {
    log_header "SSH Attack Analysis (Last 24h)"
    echo ""

    if [ ! -f /var/log/fail2ban.log ]; then
        log_warn "fail2ban.log not found"
        return 1
    fi

    # precise 24h window (fail2ban.log starts with ISO timestamp)
    local CUTOFF TMP_F2B
    CUTOFF="$(date -d '24 hours ago' '+%Y-%m-%d %H:%M:%S')"
    TMP_F2B="$(mktemp)"
    awk -v c="$CUTOFF" 'substr($0,1,19) >= c {print}' /var/log/fail2ban.log > "$TMP_F2B" 2>/dev/null

    # --- BAN EVENTS (new vs extensions) ---
    local SSHD_NEW SSHD_EXT SSHD_EVENTS
    local SLOW_NEW SLOW_EXT SLOW_EVENTS
    SSHD_NEW=$(clean_number "$(grep '\[sshd\]' "$TMP_F2B" 2>/dev/null \
        | grep ' Ban ' | grep -vc 'Increase Ban')")
    SSHD_EXT=$(clean_number "$(grep '\[sshd\]' "$TMP_F2B" 2>/dev/null | grep -c 'Increase Ban' || echo 0)")
    SSHD_EVENTS=$((SSHD_NEW + SSHD_EXT))

    SLOW_NEW=$(clean_number "$(grep '\[sshd-slowattack\]' "$TMP_F2B" 2>/dev/null \
        | grep ' Ban ' | grep -vc 'Increase Ban')")
    SLOW_EXT=$(clean_number "$(grep '\[sshd-slowattack\]' "$TMP_F2B" 2>/dev/null | grep -c 'Increase Ban' || echo 0)")
    SLOW_EVENTS=$((SLOW_NEW + SLOW_EXT))

    local TOTAL_SSH_BAN_EVENTS
    TOTAL_SSH_BAN_EVENTS=$((SSHD_EVENTS + SLOW_EVENTS))

    # --- ATTEMPTS (for consistency with timeline/top attackers) ---
    # Prefer BanFound (if your fail2ban logs it), else Found, else fallback to Ban (new only)
    local SSH_ATTEMPTS
    if grep -Eq '\[(sshd|sshd-slowattack)\].*(BanFound| Found )' "$TMP_F2B" 2>/dev/null; then
        SSH_ATTEMPTS=$(clean_number "$(
            grep -E '\[(sshd|sshd-slowattack)\]' "$TMP_F2B" 2>/dev/null | \
            grep -Ec 'BanFound| Found '
        )")
    else
        SSH_ATTEMPTS=$(clean_number "$(
            grep -E '\[(sshd|sshd-slowattack)\]' "$TMP_F2B" 2>/dev/null | \
            grep ' Ban ' | grep -vc 'Increase Ban'
        )")
    fi

    # auth.log breakdown (optional; may be 0 and that's OK)
    local FAILED_PASS=0 INVALID_USER=0 CONN_ATTEMPTS=0 PREAUTH_FAIL=0
    if [ -f /var/log/auth.log ]; then
        local AUTH_TODAY AUTH_YESTERDAY
        AUTH_TODAY=$(date '+%b %d')
        AUTH_YESTERDAY=$(date -d '1 day ago' '+%b %d')

        FAILED_PASS=$(clean_number "$(grep -E "^($AUTH_TODAY|$AUTH_YESTERDAY)" /var/log/auth.log 2>/dev/null | grep -c "Failed password" || echo "0")")
        INVALID_USER=$(clean_number "$(grep -E "^($AUTH_TODAY|$AUTH_YESTERDAY)" /var/log/auth.log 2>/dev/null | grep -c "Invalid user" || echo "0")")
        CONN_ATTEMPTS=$(clean_number "$(grep -E "^($AUTH_TODAY|$AUTH_YESTERDAY)" /var/log/auth.log 2>/dev/null | grep -c "Connection from" || echo "0")")
        PREAUTH_FAIL=$(clean_number "$(grep -E "^($AUTH_TODAY|$AUTH_YESTERDAY)" /var/log/auth.log 2>/dev/null | grep -c "Disconnected from authenticating user" || echo "0")")
    fi

    printf " %-20s %d attempts\n" "Failed Passwords:" "$FAILED_PASS"
    printf " %-20s %d attempts\n" "Invalid Users:" "$INVALID_USER"
    printf " %-20s %d\n"          "Connection Attempts:" "$CONN_ATTEMPTS"
    printf " %-20s %d\n"          "Preauth Failures:" "$PREAUTH_FAIL"
    echo " ────────────────────────"

    printf " %-20s %d\n" "SSH Attempts (24h):" "$SSH_ATTEMPTS"
    printf " %-20s %d (new: %d, extensions: %d)\n" "SSHD Ban events:" "$SSHD_EVENTS" "$SSHD_NEW" "$SSHD_EXT"
    printf " %-20s %d (new: %d, extensions: %d)\n" "Slow Ban events:" "$SLOW_EVENTS" "$SLOW_NEW" "$SLOW_EXT"
    printf " %-20s %d\n" "Total Ban events:" "$TOTAL_SSH_BAN_EVENTS"
    echo ""

    if [ "$TOTAL_SSH_BAN_EVENTS" -gt 0 ]; then
        echo " Recent SSH ban activity:"
        grep -E '\[(sshd|sshd-slowattack)\]' "$TMP_F2B" 2>/dev/null | \
            grep ' Ban ' | grep -v 'Increase Ban' | tail -5 | \
            while IFS= read -r line; do
                local timestamp ip
                timestamp=$(echo "$line" | awk '{print $1, $2}' | cut -d',' -f1)
                ip=$(echo "$line" | grep -oP ' Ban \K[0-9.]+')
                [ -n "$ip" ] && printf "  %s → %s\n" "$timestamp" "$ip"
            done
        echo ""
    fi

    rm -f "$TMP_F2B"

    # Exports:
    # - TOTAL_SSH_ATTACKS used by summary: set it to attempts so it matches timeline better.
    export TOTAL_SSH_ATTACKS=$SSH_ATTEMPTS
    export SSH_BAN_EVENTS=$TOTAL_SSH_BAN_EVENTS
    export INVALID_USER
}

analyze_ssh_top_attackers() {
    log_header "Top 10 SSH Attacking IPs (fail2ban.log attempts)"
    echo ""

    if [ ! -f /var/log/fail2ban.log ]; then
        echo "  No data available"
        echo ""
        return 0
    fi

    local CUTOFF TMP_F2B
    CUTOFF="$(date -d '24 hours ago' '+%Y-%m-%d %H:%M:%S')"
    TMP_F2B="$(mktemp)"
    awk -v c="$CUTOFF" 'substr($0,1,19) >= c {print}' /var/log/fail2ban.log > "$TMP_F2B" 2>/dev/null

    # Prefer attempt markers; fallback to Ban (new only)
    local IP_STREAM
    if grep -Eq '\[(sshd|sshd-slowattack)\].*(BanFound| Found )' "$TMP_F2B" 2>/dev/null; then
        IP_STREAM=$(
            grep -E '\[(sshd|sshd-slowattack)\]' "$TMP_F2B" 2>/dev/null | \
            grep -E 'BanFound| Found ' | \
            grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}'
        )
        # label could be "attempts"
    else
        IP_STREAM=$(
            grep -E '\[(sshd|sshd-slowattack)\]' "$TMP_F2B" 2>/dev/null | \
            grep ' Ban ' | grep -v 'Increase Ban' | \
            grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}'
        )
        # fallback label could be "bans"
    fi

    if [ -z "$IP_STREAM" ]; then
        echo "  No attacks detected"
        rm -f "$TMP_F2B"
        echo ""
        return 0
    fi

    echo "$IP_STREAM" | sort | uniq -c | sort -rn | head -10 | \
    while read -r count ip; do
        local BANNED=""
        if sudo nft get element inet docker-block docker-banned-ipv4 "{ $ip }" &>/dev/null 2>&1; then
            BANNED="DOCKER-BLOCKED"
        elif sudo fail2ban-client status sshd 2>/dev/null | grep -q "$ip"; then
            BANNED="F2B-BANNED"
        elif sudo nft list set inet fail2ban-filter f2b-sshd 2>/dev/null | grep -q "$ip"; then
            BANNED="NFT-BLOCKED"
        else
            BANNED="(unbanned)"
        fi
        printf "  %-15s %6d attempts  %s\n" "$ip" "$count" "$BANNED"
    done

    rm -f "$TMP_F2B"
    echo ""
}

analyze_ssh_usernames() {
    log_header "Top 10 Targeted SSH Usernames"
    echo ""

    if [ ! -f /var/log/auth.log ]; then
        echo "  auth.log not available"
        echo ""
        return 0
    fi

    if [ "${INVALID_USER:-0}" -eq 0 ]; then
        echo "  No invalid user attempts"
        echo ""
        return 0
    fi

    local AUTH_TODAY AUTH_YESTERDAY
    AUTH_TODAY=$(date '+%b %d')
    AUTH_YESTERDAY=$(date -d '1 day ago' '+%b %d')

    grep -E "^($AUTH_TODAY|$AUTH_YESTERDAY)" /var/log/auth.log 2>/dev/null | \
        grep "Invalid user" | awk '{print $8}' | \
        sort | uniq -c | sort -rn | head -10 | \
        while read -r count username; do
            printf "  ${CYAN}%-20s${NC} %3d attempts\n" "$username" "$count"
        done

    echo ""
}

analyze_f2b_current_bans() {
    log_header "Currently Banned IPs by Jail"
    echo ""

    local has_bans=false

    for jail in "${JAILS[@]}"; do
        local count
        count=$(get_f2b_count "$jail" | tr -d ' ')
        count=$(clean_number "$count")

        if [ "$count" -gt 0 ]; then
            printf "  [%-25s] %3d IPs\n" "$jail" "$count"
            has_bans=true
        fi
    done

    if [ "$has_bans" = false ]; then
        echo "  All jails clean"
    fi

    echo ""
}

analyze_recent_bans() {
    log_header "Last 20 Ban Events"
    echo ""

    if [ ! -f /var/log/fail2ban.log ]; then
        echo "  No fail2ban log available"
        echo ""
        return 0
    fi

    sudo grep "Ban" /var/log/fail2ban.log 2>/dev/null | tail -20 | \
        grep -oE '[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}.*Ban [0-9.]+' | \
        awk '{print "  "$1, $2, "→", $NF}' || echo "  No recent bans"

    echo ""
}

security_summary_recommendations() {
    log_header "╔════════════════════════════════════════════════════════════╗"
    log_header "║          SECURITY SUMMARY & RECOMMENDATIONS                ║"
    log_header "╚════════════════════════════════════════════════════════════╝"
    echo ""

    # Get Fail2Ban banned count (OPRAVENÉ)
    local TOTAL_BANNED=0
    for jail in $(sudo fail2ban-client status 2>/dev/null | grep "Jail list" | sed 's/.*://;s/,//g'); do
        count=$(sudo fail2ban-client status "$jail" 2>/dev/null | grep "Currently banned" | awk '{print $4}')
        if [ ! -z "$count" ]; then
            TOTAL_BANNED=$((TOTAL_BANNED + count))
        fi
    done
    TOTAL_BANNED=$(clean_number "$TOTAL_BANNED")

    # Get Docker-block count
    local DOCKER_BLOCKED
    if jq_check_installed; then
        DOCKER_BLOCKED=$(clean_number "$(sudo nft -j list set inet docker-block docker-banned-ipv4 2>/dev/null | \
            jq -r '.nftables[] | select(.set.elem) | .set.elem | length' 2>/dev/null | head -1)")
    else
        DOCKER_BLOCKED=$(sudo nft list set inet docker-block docker-banned-ipv4 2>/dev/null | \
            grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | wc -l)
    fi

    # Get attack detections (fallback ak export zlyhal)
    local NPM_DETECTED="${TOTAL_NPM_ATTACKS:-0}"
    local SSH_DETECTED="${TOTAL_SSH_ATTACKS:-0}"

    # Get total attempts from fail2ban.log (same method as trends)
    local day_ago
    day_ago=$(date --date='24 hours ago' '+%Y-%m-%d')
    local TOTAL_ATTEMPTS
    TOTAL_ATTEMPTS=$(grep "$day_ago" /var/log/fail2ban.log 2>/dev/null \
    | grep -c "Ban\|Found" || echo "0")
    TOTAL_ATTEMPTS=$(clean_number "$TOTAL_ATTEMPTS")

    echo "Protection Status:"
    echo "  • Fail2Ban Banned:     $TOTAL_BANNED IPs"
    echo "  • Docker-Block Active: $DOCKER_BLOCKED IPs"
    echo "  • NPM Attacks Detected: $NPM_DETECTED"
    echo "  • SSH Attacks Detected: $SSH_DETECTED"
    echo ""

    echo "Attack Summary (24h):"
    echo "  • Total Attack Attempts: $TOTAL_ATTEMPTS"

    if [ "$SSH_DETECTED" -gt "$NPM_DETECTED" ]; then
        echo -e "  • Primary Vector: ${YELLOW}SSH${NC}"
    else
        echo -e "  • Primary Vector: ${YELLOW}HTTP/NPM${NC}"
    fi
    echo ""

    # Risk assessment (OPRAVENÉ thresholds)
    if [ "$TOTAL_ATTEMPTS" -gt 10000 ]; then
        log_alert "⚠️  CRITICAL - Very high attack activity"
        echo ""
        echo "Recommendations:"
        echo "  • Monitor: sudo f2b monitor watch"
        echo "  • Review: sudo f2b monitor top-attackers"
        echo "  • Check: sudo f2b docker dashboard"
    elif [ "$TOTAL_ATTEMPTS" -gt 5000 ]; then
        log_warn "⚠️  WARNING - Elevated attack activity"
        echo ""
        echo "Recommendations:"
        echo "  • Review: sudo f2b monitor trends"
        echo "  • Check: sudo f2b monitor top-attackers"
    elif [ "$TOTAL_ATTEMPTS" -gt 1000 ]; then
        log_info "🟡 MODERATE - Normal attack pattern"
        echo ""
        log_success "✅ Defenses are working effectively"
    else
        log_success "✅ QUIET - Low activity"
        echo ""
        echo "Your defenses are working well!"
    fi

    echo ""
}

report_attack_analysis() {
    local mode="${1:-all}"

    # Create temp file for sharing data between functions
    local TEMP_DATA="/tmp/f2b-attack-analysis-$$.dat"
    true > "$TEMP_DATA"  # Clear/create file

    log_header "═══════════════════════════════════════════════════════════"
    log_header "  COMPLETE ATTACK ANALYSIS - NPM + SSH (v025)"
    log_header "═══════════════════════════════════════════════════════════"
    echo ""

    # NPM Analysis
    if [ "$mode" = "all" ] || [ "$mode" = "npm-only" ]; then
        log_header "═══════════════════════════════════════════════════════════"
        log_header "  NGINX PROXY MANAGER (NPM) ANALYSIS"
        log_header "═══════════════════════════════════════════════════════════"
        echo ""

        analyze_npm_http_status
        analyze_npm_attack_patterns
        # Save NPM count to temp file
        echo "NPM_ATTACKS=${TOTAL_NPM_ATTACKS:-0}" >> "$TEMP_DATA"
        analyze_probed_paths
    fi

    # SSH Analysis
    if [ "$mode" = "all" ] || [ "$mode" = "ssh-only" ]; then
        log_header "═══════════════════════════════════════════════════════════"
        log_header "  SSH ATTACK ANALYSIS"
        log_header "═══════════════════════════════════════════════════════════"
        echo ""

        analyze_ssh_attacks
        # Save SSH count to temp file
        echo "SSH_ATTACKS=${TOTAL_SSH_ATTACKS:-0}" >> "$TEMP_DATA"
        analyze_ssh_top_attackers
        analyze_ssh_usernames
    fi

    # Fail2Ban Status (always)
    log_header "═══════════════════════════════════════════════════════════"
    log_header "  FAIL2BAN PROTECTION STATUS"
    log_header "═══════════════════════════════════════════════════════════"
    echo ""

    analyze_f2b_current_bans
    analyze_recent_bans
        # ✅ PRIDAJ TIMELINE
    report_attack_timeline

    # Summary (always) - pass temp file path
    security_summary_recommendations "$TEMP_DATA"
    
    # Cleanup
    rm -f "$TEMP_DATA"
}

################################################################################
# Attack Timeline Report v0.25
################################################################################

report_attack_timeline() {
    log_header "╔════════════════════════════════════════════════════════════╗"
    log_header "║              ATTACK WAVE TIMELINE (Last 24h)               ║"
    log_header "╚════════════════════════════════════════════════════════════╝"
    echo ""

    if [ ! -f /var/log/fail2ban.log ]; then
        log_warn "Fail2Ban log not found"
        return 1
    fi

    # Get hourly attack counts for last 24 hours
    # shellcheck disable=SC2034
    local current_hour
    # shellcheck disable=SC2034
    current_hour=$(date '+%H')
    local -a hours
    local -a counts
    local max_count=0
    local total_count=0

    # Collect data for each hour (going backwards 24 hours)
    for i in {23..0}; do
    local hour_ago
        hour_ago=$(date -d "$i hours ago" '+%Y-%m-%d %H')
    local count
        count=$(grep "$hour_ago" /var/log/fail2ban.log 2>/dev/null \
        | grep -c "Ban\|Found" || echo "0")
        count=$(clean_number "$count")
        
        hours+=("$(date -d "$i hours ago" '+%H:00')")
        counts+=("$count")
        total_count=$((total_count + count))
        
        # Track maximum for scaling
        if [ "$count" -gt "$max_count" ]; then
            max_count=$count
        fi
    done

    # Calculate average
    local avg_count=$((total_count / 24))

    # Display timeline (show every 3 hours to fit screen)
    local bar_width=30
    
    for i in {23..0..3}; do
        local idx=$((23 - i))
        local hour="${hours[$idx]}"
        local count="${counts[$idx]}"
        
        # Calculate bar length (scaled to max_count)
        local bar_length=0
        if [ "$max_count" -gt 0 ]; then
            bar_length=$((count * bar_width / max_count))
        fi
        
        # Create bar
        local bar=""
        for ((j=0; j<bar_length; j++)); do
            bar+="█"
        done
        for ((j=bar_length; j<bar_width; j++)); do
            bar+="░"
        done
        
        # Determine severity level and color
        local level=""
        local color=""
        if [ "$count" -gt 200 ]; then
            level="CRITICAL"
            color="${RED}"
        elif [ "$count" -gt 100 ]; then
            level="HIGH"
            color="${YELLOW}"
        elif [ "$count" -gt 50 ]; then
            level="ELEVATED"
            color="${CYAN}"
        elif [ "$count" -gt 0 ]; then
            level="MODERATE"
            color="${GREEN}"
        else
            level="QUIET"
            color="${DARK_GRAY}"
        fi
        
        # Print timeline row - ✅ OPRAVENÉ
        printf "%5s  │ %s  ${color}%4d attempts/h  %-10s${NC}\n" \
            "$hour" "$bar" "$count" "$level"
    done
    
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    printf "Total 24h: ${YELLOW}%d${NC} attempts  |  Average: ${CYAN}%d/h${NC}  |  Peak: ${RED}%d/h${NC}\n" \
        "$total_count" "$avg_count" "$max_count"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""

    # Attack intensity assessment
    if [ "$max_count" -gt 200 ]; then
        log_alert "⚠️  CRITICAL WAVE - Peak attack intensity detected!"
        echo ""
        echo "Recommendations:"
        echo "  • Monitor in real-time: sudo f2b monitor watch"
        echo "  • Review attackers: sudo f2b monitor top-attackers"
        echo "  • Check dashboard: sudo f2b docker dashboard"
    elif [ "$max_count" -gt 100 ]; then
        log_warn "⚠️  HIGH ACTIVITY - Significant attack waves detected"
        echo ""
        echo "Recommendations:"
        echo "  • Review: sudo f2b monitor trends"
        echo "  • Check sync: sudo f2b sync check"
    elif [ "$total_count" -gt 1000 ]; then
        log_info "🟡 SUSTAINED ACTIVITY - Continuous attack pattern"
        echo ""
        log_success "✅ Defenses are handling the load effectively"
    else
        log_success "✅ NORMAL ACTIVITY - Low attack volume"
    fi
    
    echo ""
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
  version [--json|--short] Show version info
  version --json           Machine-readable JSON
  version --short          Short version string (v0.30)
  

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
  report timeline                                  Attack wave timeline (24h)
  report attack-analysis [--npm-only|--ssh-only]
                           Show comprehensive attack analysis (NEW v0.25)

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
  sudo f2b report attack-analysis
  sudo f2b report timeline
  sudo f2b report export json

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
    # Initialize log file
    mkdir -p "$(dirname "$LOGFILE")"
    touch "$LOGFILE"
    
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
            f2b_version "$2"
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
            acquire_lock  # ✅ Lock pre všetky report príkazy
            case "$2" in
                json) report_json ;;
                csv) report_csv ;;
                daily) report_daily ;;
                attack-analysis)
                    case "$3" in
                        --npm-only) report_attack_analysis "npm-only" ;;
                        --ssh-only) report_attack_analysis "ssh-only" ;;
                        *) report_attack_analysis "all" ;;
                    esac
                    ;;
                timeline)
                    report_attack_timeline  # ✅ Už máme lock vyššie
                    ;;
                *)
                    release_lock  # ✅ Uvoľni lock pred help
                    show_help
                    ;;
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
}

main "$@"
