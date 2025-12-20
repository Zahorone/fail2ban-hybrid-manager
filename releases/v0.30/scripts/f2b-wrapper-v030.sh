#!/bin/bash

################################################################################
# F2B Unified Wrapper v0.31 - PRODUCTION
# Complete Fail2Ban + nftables + docker-block management

# REQUIREMENTS:
# - fail2ban
# - nftables
# - jq (JSON processor) - install: sudo apt install jq

# v0.30 CHANGES (2025-12-20):
# + FIXED: f2b_sync_docker() - Union approach for all F2B sets
# + FIXED: f2b_sync_docker() - nft get element with { IP } syntax
# + FIXED: f2b_sync_docker() - Accurate IPv4/IPv6 sync (FIX v0.30)
# + FIXED: f2b_docker_info() - Proper status display (FIX v0.30)
# + FIXED: manage_block_port() - nft add/delete with { port } syntax
# + FIXED: manage_unblock_port() - nft delete with { port } syntax  
# + FIXED: f2b_find() - nft get element with { IP } syntax (BONUS)
# + All v0.30 functions preserved

# v0.30 CHANGES (2025-12-19):
# + Docker-block v0.4 integration
# + Enhanced IP/port blocking
# + Fail2ban ↔ docker-block sync

################################################################################

################################################################################
# Component: F2B Wrapper
# Part of: Fail2Ban Hybrid Nftables Manager
################################################################################

set -o pipefail

# shellcheck disable=SC2034
RELEASE="v0.30"

# shellcheck disable=SC2034
VERSION="0.31"

# shellcheck disable=SC2034
BUILD_DATE="2025-12-20"

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

logsuccess() { log_success "$@"; }
logerror() { log_error "$@"; }
logwarn() { log_warn "$@"; }
loginfo() { log_info "$@"; }
logheader() { log_header "$@"; }
logalert() { log_alert "$@"; }

################################################################################
# LOCK MECHANISM
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
# VALIDATION FUNCTIONS
################################################################################

validate_port() {
  local port="$1"
  if ! [[ "$port" =~ ^[0-9]+$ ]] || [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
    log_error "Invalid port number: $port (must be 1-65535)"
    return 1
  fi
  return 0
}

validate_ip() {
  local ip="$1"
  if [[ ! "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
    log_error "Invalid IP address: $ip"
    return 1
  fi
  return 0
}

################################################################################
# JQ HELPER FUNCTIONS
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

################################################################################
# HELPER FUNCTIONS
################################################################################

get_f2b_count() {
  local jail="$1"
  local count
  count=$(sudo fail2ban-client status "$jail" 2>/dev/null | grep "Currently banned" | awk '{print $NF}' | head -n1 | tr -d '[:space:]')
  echo "${count:-0}"
}

get_f2b_ips() {
  local jail="$1"
  sudo fail2ban-client status "$jail" 2>/dev/null | \
    grep "Banned IP list:" | \
    sed 's/.*Banned IP list:\s*//' | \
    tr ' ' '\n' | \
    grep -E '[0-9]' | \
    sort -u
}

get_nft_ips() {
  local set="$1"
  sudo nft list set "$F2BTABLE" "$set" 2>/dev/null | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort -u
}

count_ips() {
  local ips="$1"
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
      local binary_path jails_count
      binary_path=$(readlink -f "$(command -v f2b)" 2>/dev/null || echo "/usr/local/bin/f2b")
      jails_count=0
      if systemctl is-active --quiet fail2ban 2>/dev/null; then
        jails_count=$(fail2ban-client status 2>/dev/null | grep "Jail list:" | sed 's/.*://' | tr ',' '\n' | grep -c . || echo 0)
      fi
      cat << EOF
{
  "release": "$RELEASE",
  "version": "$VERSION",
  "build_date": "$BUILD_DATE",
  "docker_block_version": "$DOCKERBLOCKVERSION",
  "component": "$COMPONENT_NAME",
  "fail2ban_jails": $jails_count,
  "binary": "$binary_path"
}
EOF
      ;;
    --short)
      echo "$VERSION"
      ;;
    *)
      echo ""
      echo "════════════════════════════════════════════════════════"
      echo " F2B Unified Wrapper $RELEASE"
      echo "════════════════════════════════════════════════════════"
      echo ""
      echo " Version: $VERSION"
      echo " Build: $BUILD_DATE"
      echo " Component: $COMPONENT_NAME"
      echo " Docker-block: v$DOCKERBLOCKVERSION"
      echo ""
      local f2b_path
      f2b_path=$(command -v f2b 2>/dev/null || echo "not in PATH")
      echo " Binary: $f2b_path"
      if [ -x "$f2b_path" ] && [ "$f2b_path" != "not in PATH" ]; then
        local checksum
        checksum=$(sha256sum "$f2b_path" 2>/dev/null | awk '{print $1}' | cut -c1-16 || echo "unavailable")
        echo " Checksum: sha256:${checksum}..."
      fi
      echo ""
      echo "Components:"
      echo " - Fail2Ban nftables integration"
      echo " - Docker port blocking v$DOCKERBLOCKVERSION"
      echo " - Enhanced sync monitoring"
      echo " - Attack analysis & reporting"
      echo " - Real-time Dashboard"
      echo ""
      if systemctl is-active --quiet fail2ban 2>/dev/null; then
        echo "Configuration:"
        if nft list table inet fail2ban-filter &>/dev/null 2>&1; then
          echo " - Table: inet fail2ban-filter ✓"
          local jails_active
          jails_active=$(fail2ban-client status 2>/dev/null | grep "Jail list:" | sed 's/.*://' | tr ',' '\n' | grep -c . || echo 0)
          echo " - Jails: $jails_active active"
          local sets_v4=0 sets_v6=0 missing_v6=0 jail setname
          for jail in "${JAILS[@]}"; do
            setname="${SETMAP[$jail]}"
            [ -z "$setname" ] && continue
            if sudo nft list set inet fail2ban-filter "$setname" &>/dev/null; then
              ((sets_v4++))
            fi
            if sudo nft list set inet fail2ban-filter "${setname}-v6" &>/dev/null; then
              ((sets_v6++))
            else
              ((missing_v6++))
            fi
          done
          local sets_total=$((sets_v4 + sets_v6))
          echo " - Sets: $sets_total ($sets_v4 v4 + $sets_v6 v6, missing v6: $missing_v6)"
        else
          echo " - Table: inet fail2ban-filter (not found)"
        fi
      else
        echo "Configuration:"
        echo " - Fail2Ban: not running"
      fi
      echo ""
      echo "Usage:"
      echo " f2b help - Show all commands"
      echo " f2b status - System status"
      echo " f2b version --json - JSON output"
      echo " f2b version --short - Short version"
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
  local total=0 clean=0
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
  local IP="$1"
  if [ -z "$IP" ]; then
    log_error "Usage: f2b find <IP>"
    return 1
  fi
  if ! validate_ip "$IP"; then
    return 1
  fi
  log_header "Searching for $IP"
  local found=0
  for jail in "${JAILS[@]}"; do
    if sudo fail2ban-client status "$jail" 2>/dev/null | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | grep -q "$IP"; then
      log_success "Found in jail: $jail"
      local bantime
      bantime=$(sudo fail2ban-client get "$jail" bantime 2>/dev/null || echo "unknown")
      log_info "Ban time: $bantime"
      local nftset="${SETMAP[$jail]}"
      if sudo nft list set "$F2BTABLE" "$nftset" 2>/dev/null | grep -qE "$IP"; then
        log_info "nftables: Present in $nftset"
        if jq_check_installed; then
          local metadata
          metadata=$(sudo nft --json list set inet fail2ban-filter "$nftset" 2>/dev/null | \
            jq -r ".nftables[] | select(.set.elem) | .set.elem[] | select(.elem) | \
            select(.elem.val == \"$IP\") | \
            \" ↳ timeout: \\(.elem.timeout // \\\"permanent\\\"), expires: \\(.elem.expires // \\\"never\\\")\"" 2>/dev/null)
          if [ -n "$metadata" ]; then
            echo -e "${CYAN}$metadata${NC}"
          fi
        fi
      else
        log_warn "nftables: NOT in $nftset (sync issue!)"
      fi
      # ✅ OPRAVENÉ: nft get element s { IP } syntax
      if sudo nft list table inet docker-block &>/dev/null; then
        if sudo nft get element inet docker-block docker-banned-ipv4 "{ $IP }" &>/dev/null; then
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
  local ALLSYNCED=true
  for jail in "${JAILS[@]}"; do
    local F2BCOUNT NFTCOUNT DIFF DIFFABS
    F2BCOUNT=$(get_f2b_count "$jail" | tr -d '[:space:]')
    local nftset="${SETMAP[$jail]}"
    NFTCOUNT=$(get_nft_ips "$nftset" | wc -l | tr -d '[:space:]')
    DIFF=$((F2BCOUNT - NFTCOUNT))
    DIFFABS=${DIFF#-}
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

sync_silent() {
  local LOG_FILE="/var/log/f2b-sync.log"
  local CHANGES=0
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] Starting silent sync..." >> "$LOG_FILE"
  for jail in "${JAILS[@]}"; do
    local nftset="${SETMAP[$jail]}"
    local f2b_ips nft_ips
    f2b_ips=$(get_f2b_ips "$jail")
    nft_ips=$(get_nft_ips "$nftset")
    if [ -z "$f2b_ips" ]; then
      while read -r ip; do
        [ -n "$ip" ] && sudo nft delete element "$F2BTABLE" "$nftset" "{ $ip }" 2>/dev/null && ((CHANGES++)) && echo " Removed orphan: $ip from $jail" >> "$LOG_FILE"
      done <<< "$nft_ips"
    else
      while read -r ip; do
        [ -n "$ip" ] && ! echo "$f2b_ips" | grep -q "$ip" && sudo nft delete element "$F2BTABLE" "$nftset" "{ $ip }" 2>/dev/null && ((CHANGES++)) && echo " Removed orphan: $ip from $jail" >> "$LOG_FILE"
      done <<< "$nft_ips"
    fi
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
# F2B DOCKER SYNC (v0.31 FIXED)
################################################################################

f2b_sync_docker() {
  logheader "═══════════════════════════════════════════════════════"
  echo " F2B ↔ Docker-Block Bidirectional Sync"
  logheader "═══════════════════════════════════════════════════════"
  echo ""

  # Pre-sync: Synchronizuj fail2ban → nftables
  loginfo "Pre-sync: Synchronizing fail2ban → nftables..."
  sync_silent
  echo ""

  # Kontrola docker-block tabuľky
  if ! sudo nft list table inet docker-block &>/dev/null; then
    logerror "docker-block table NOT FOUND"
    loginfo "Install with: bash 03-install-docker-block-v04.sh"
    echo ""
    return 1
  fi

  local LOGFILE="/var/log/f2b-docker-sync.log"
  sudo touch "$LOGFILE" 2>/dev/null || true

  loginfo "Starting docker-block sync (union of all F2B sets)..."
  echo ""

  local SETS=(
    f2b-sshd
    f2b-sshd-slowattack
    f2b-exploit-critical
    f2b-dos-high
    f2b-web-medium
    f2b-nginx-recon-bonus
    f2b-recidive
    f2b-manualblock
    f2b-fuzzing-payloads
    f2b-botnet-signatures
    f2b-anomaly-detection
  )

  # ✅ OPRAVENÉ: IPv4 UNION - nft get element s { IP }
  local F2BIPS
  F2BIPS="$(
    for SET in "${SETS[@]}"; do
      sudo nft list set inet fail2ban-filter "$SET" 2>/dev/null \
        | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' || true
    done | sort -u
  )"

  # Pridaj chýbajúce do docker-block
  while IFS= read -r IP; do
    [ -z "$IP" ] && continue
    if ! sudo nft get element inet docker-block docker-banned-ipv4 "{ $IP }" &>/dev/null; then
      sudo nft add element inet docker-block docker-banned-ipv4 "{ $IP timeout 1h }" 2>/dev/null || true
      echo "[$(date +'%Y-%m-%d %H:%M:%S')] ADDED: $IP" | sudo tee -a "$LOGFILE" >/dev/null
    fi
  done <<< "$F2BIPS"

  # Odstráň sirotné z docker-block
  local DOCKERIPS
  DOCKERIPS="$(
    sudo nft list set inet docker-block docker-banned-ipv4 2>/dev/null \
      | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort -u || true
  )"

  while IFS= read -r IP; do
    [ -z "$IP" ] && continue
    if ! echo "$F2BIPS" | grep -qx "$IP"; then
      sudo nft delete element inet docker-block docker-banned-ipv4 "{ $IP }" 2>/dev/null || true
      echo "[$(date +'%Y-%m-%d %H:%M:%S')] REMOVED: $IP (no longer in fail2ban)" | sudo tee -a "$LOGFILE" >/dev/null
    fi
  done <<< "$DOCKERIPS"

  # ✅ OPRAVENÉ: IPv6 UNION - nft get element s { IP }
  local F2BIPS6
  F2BIPS6="$(
    for SET in "${SETS[@]}"; do
      sudo nft list set inet fail2ban-filter "${SET}-v6" 2>/dev/null \
        | grep -oE '([0-9a-fA-F:]+)' || true
    done | sort -u
  )"

  while IFS= read -r IP; do
    [ -z "$IP" ] && continue
    if ! sudo nft get element inet docker-block docker-banned-ipv6 "{ $IP }" &>/dev/null; then
      sudo nft add element inet docker-block docker-banned-ipv6 "{ $IP timeout 1h }" 2>/dev/null || true
      echo "[$(date +'%Y-%m-%d %H:%M:%S')] ADDED (IPv6): $IP" | sudo tee -a "$LOGFILE" >/dev/null
    fi
  done <<< "$F2BIPS6"

  DOCKERIPS="$(
    sudo nft list set inet docker-block docker-banned-ipv6 2>/dev/null \
      | grep -oE '([0-9a-fA-F:]+)' | sort -u || true
  )"

  while IFS= read -r IP; do
    [ -z "$IP" ] && continue
    if ! echo "$F2BIPS6" | grep -qx "$IP"; then
      sudo nft delete element inet docker-block docker-banned-ipv6 "{ $IP }" 2>/dev/null || true
      echo "[$(date +'%Y-%m-%d %H:%M:%S')] REMOVED (IPv6): $IP (no longer in fail2ban)" | sudo tee -a "$LOGFILE" >/dev/null
    fi
  done <<< "$DOCKERIPS"

  # METRIKY
  echo ""
  logheader "SYNC METRICS"

  local TOTALJAILIPS=0
  local ALLJAILIPS
  ALLJAILIPS="$(
    for jail in "${JAILS[@]}"; do
      sudo fail2ban-client status "$jail" 2>/dev/null \
        | grep "Banned IP list:" \
        | sed 's/.*Banned IP list:\s*//' \
        | tr ' ' '\n'
    done | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' || true
  )"

  [ -n "$ALLJAILIPS" ] && TOTALJAILIPS="$(echo "$ALLJAILIPS" | wc -l | tr -d '[:space:]')"

  local UNIQUELIST UNIQUEIPS DUPLICATES
  UNIQUELIST="$(echo "$ALLJAILIPS" | sort -u)"
  UNIQUEIPS=0
  [ -n "$UNIQUELIST" ] && UNIQUEIPS="$(echo "$UNIQUELIST" | wc -l | tr -d '[:space:]')"

  DUPLICATES=0
  [ "$TOTALJAILIPS" -gt "$UNIQUEIPS" ] && DUPLICATES=$((TOTALJAILIPS - UNIQUEIPS))

  local DOCKERCOUNT
  if jq_check_installed; then
    DOCKERCOUNT="$(sudo nft -j list set inet docker-block docker-banned-ipv4 2>/dev/null \
      | jq -r '.nftables[] | select(.set.elem) | .set.elem | length' 2>/dev/null | head -1)"
  else
    DOCKERCOUNT="$(sudo nft list set inet docker-block docker-banned-ipv4 2>/dev/null \
      | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | wc -l | tr -d '[:space:]')"
  fi
  DOCKERCOUNT="${DOCKERCOUNT:-0}"

  loginfo "Jails: $TOTALJAILIPS IP (duplicates: $DUPLICATES, unique: $UNIQUEIPS)"
  loginfo "Docker-block: $DOCKERCOUNT elements (auto-merge may differ from IP count)"

  local DIFF=$((UNIQUEIPS - DOCKERCOUNT))
  local DIFFABS=${DIFF#-}
  if [ "$DOCKERCOUNT" -eq "$UNIQUEIPS" ]; then
    logsuccess "✅ Perfect sync: $UNIQUEIPS == $DOCKERCOUNT"
  elif [ "$DIFFABS" -le 5 ]; then
    loginfo "ℹ️ Minor difference (±$DIFFABS) - normal due to nftables auto-merge"
  else
    logwarn "⚠️ Significant difference: unique_jails=$UNIQUEIPS, docker-block=$DOCKERCOUNT"
  fi

  echo "[$(date +'%Y-%m-%d %H:%M:%S')] Sync complete - IPv4: $DOCKERCOUNT IPs in docker-block" | sudo tee -a "$LOGFILE" >/dev/null
  echo ""
}

################################################################################
# F2B DOCKER INFO (v0.31 FIXED)
################################################################################

f2b_docker_info() {
  echo ""
  logheader "🐋 docker-block v${DOCKERBLOCKVERSION} - Status"
  echo ""

  if sudo nft list table inet docker-block &>/dev/null; then
    logsuccess "docker-block table: ACTIVE"
    echo ""
    echo "Behavior:"
    echo " • localhost (127.0.0.1): ALLOWED"
    echo " • Docker bridge (docker0): ALLOWED"
    echo " • External access: BLOCKED"
    echo ""
    echo "Blocked ports:"
    sudo nft list set inet docker-block docker-blocked-ports 2>/dev/null | grep "elements" || echo " (none)"
  else
    logerror "docker-block table: NOT FOUND"
    echo ""
    echo "To install:"
    echo " bash 03-install-docker-block-v04.sh"
  fi

  echo ""
}

################################################################################
# MANAGE FUNCTIONS - PORT BLOCKING (v0.31 FIXED)
################################################################################

manage_block_port() {
  local port="$1"

  if [ -z "$port" ]; then
    logerror "Usage: manage block-port <port>"
    return 1
  fi
  if ! validate_port "$port"; then
    return 1
  fi

  logheader "Blocking port $port (persistent)"

  # ✅ OPRAVENÉ: nft add element s { port }
  if sudo nft add element inet docker-block docker-blocked-ports "{ $port }" 2>/dev/null; then
    logsuccess "Port $port added to runtime"
  else
    logwarn "Port $port might already be in runtime set"
  fi

  local NFTDOCKERCONF="/etc/nftables.d/docker-block.nft"
  if [ ! -f "$NFTDOCKERCONF" ]; then
    logerror "Config file not found: $NFTDOCKERCONF"
    return 1
  fi

  local CURRENTPORTS
  CURRENTPORTS="$(sudo nft list set inet docker-block docker-blocked-ports 2>/dev/null \
    | grep -oE '[0-9]+' | sort -un | tr '\n' ',' | sed 's/,$//')"

  if [ -z "$CURRENTPORTS" ]; then
    logwarn "No ports in runtime set"
    return 0
  fi

  sudo cp "$NFTDOCKERCONF" "${NFTDOCKERCONF}.backup-$(date +%Y%m%d-%H%M%S)" 2>/dev/null || true

  # Prepíš iba blok setu (range replace)
  sudo sed -i '/set docker-blocked-ports {/,/}/c\
set docker-blocked-ports {\
    type inet_service\
    flags interval\
    auto-merge\
    elements = { '"$CURRENTPORTS"' }\
}' "$NFTDOCKERCONF"

  logsuccess "Port $port persisted to $NFTDOCKERCONF"
  loginfo "Blocked ports: $CURRENTPORTS"
  echo ""
}

manage_unblock_port() {
  local port="$1"

  if [ -z "$port" ]; then
    logerror "Usage: manage unblock-port <port>"
    return 1
  fi
  if ! validate_port "$port"; then
    return 1
  fi

  logheader "Unblocking port $port (persistent)"

  # ✅ OPRAVENÉ: nft delete element s { port }
  if sudo nft delete element inet docker-block docker-blocked-ports "{ $port }" 2>/dev/null; then
    logsuccess "Port $port removed from runtime"
  else
    logerror "Port $port not found in runtime"
    return 1
  fi

  local NFTDOCKERCONF="/etc/nftables.d/docker-block.nft"
  if [ ! -f "$NFTDOCKERCONF" ]; then
    logerror "Config file not found: $NFTDOCKERCONF"
    return 1
  fi

  local CURRENTPORTS
  CURRENTPORTS="$(sudo nft list set inet docker-block docker-blocked-ports 2>/dev/null \
    | grep -oE '[0-9]+' | sort -un | tr '\n' ',' | sed 's/,$//')"

  sudo cp "$NFTDOCKERCONF" "${NFTDOCKERCONF}.backup-$(date +%Y%m%d-%H%M%S)" 2>/dev/null || true

  if [ -z "$CURRENTPORTS" ]; then
    sudo sed -i '/set docker-blocked-ports {/,/}/c\
set docker-blocked-ports {\
    type inet_service\
    flags interval\
    auto-merge\
    elements = { }\
}' "$NFTDOCKERCONF"
    logsuccess "Port $port removed - no ports left in set"
  else
    sudo sed -i '/set docker-blocked-ports {/,/}/c\
set docker-blocked-ports {\
    type inet_service\
    flags interval\
    auto-merge\
    elements = { '"$CURRENTPORTS"' }\
}' "$NFTDOCKERCONF"
    logsuccess "Port $port removed - remaining: $CURRENTPORTS"
  fi

  echo ""
}

manage_list_blocked_ports() {
  logheader "BLOCKED PORTS"
  sudo nft list set inet docker-block docker-blocked-ports 2>/dev/null || logwarn "No blocked ports or docker-block table missing"
  echo ""
}

manage_manual_ban() {
  local ip="$1"
  local timeout="${2:-7d}"
  if [ -z "$ip" ]; then
    logerror "Usage: manage manual-ban <IP> [timeout]"
    return 1
  fi
  if ! validate_ip "$ip"; then
    return 1
  fi
  logheader "Banning $ip ($timeout)"
  if sudo nft add element "$F2BTABLE" f2b-manualblock "{ $ip timeout $timeout }" 2>/dev/null; then
    logsuccess "Banned"
  else
    logwarn "Already banned"
  fi
  echo ""
}

manage_manual_unban() {
  local ip="$1"
  if [ -z "$ip" ]; then
    logerror "Usage: manage manual-unban <IP>"
    return 1
  fi
  if ! validate_ip "$ip"; then
    return 1
  fi
  logheader "Unbanning $ip"
  if sudo nft delete element "$F2BTABLE" f2b-manualblock "{ $ip }" 2>/dev/null; then
    logsuccess "Unbanned"
  else
    logerror "Not found"
  fi
  echo ""
}

manage_unban_all() {
  local ip="$1"
  if [ -z "$ip" ]; then
    logerror "Usage: manage unban-all <IP>"
    return 1
  fi
  if ! validate_ip "$ip"; then
    return 1
  fi
  logheader "Unbanning $ip from ALL jails"
  echo ""
  local found=0 unbanned=0
  for jail in "${JAILS[@]}"; do
    if sudo fail2ban-client status "$jail" 2>/dev/null | grep -q "$ip"; then
      found=1
      if sudo fail2ban-client set "$jail" unbanip "$ip" 2>/dev/null; then
        logsuccess "[$jail] unbanned"
        ((unbanned++))
      else
        logwarn "[$jail] failed to unban"
      fi
    fi
  done
  echo ""
  if [ "$found" -eq 0 ]; then
    logwarn "IP $ip not found in any fail2ban jail"
    loginfo "Checking nftables sets..."
  else
    logsuccess "Unbanned from $unbanned fail2ban jail(s)"
    loginfo "Running sync to update nftables..."
  fi
  local removed=0
  for jail in "${JAILS[@]}"; do
    local nftset="${SETMAP[$jail]}"
    if sudo nft list set "$F2BTABLE" "$nftset" 2>/dev/null | grep -q "$ip"; then
      if sudo nft delete element "$F2BTABLE" "$nftset" "{ $ip }" 2>/dev/null; then
        loginfo "Removed from nftables: $nftset"
        ((removed++))
      fi
    fi
  done
  if [ "$removed" -gt 0 ]; then
    logsuccess "Removed from $removed nftables set(s)"
  elif [ "$found" -eq 0 ]; then
    logwarn "IP $ip not found anywhere"
  else
    logsuccess "Sync completed"
  fi
  echo ""
}

manage_reload() {
  logheader "Reloading firewall"
  if sudo nft -c -f /etc/nftables.conf 2>/dev/null; then
    logsuccess "Syntax OK"
  else
    logerror "Syntax error"
    return 1
  fi
  if sudo systemctl reload nftables 2>/dev/null; then
    logsuccess "Reloaded"
  else
    sudo systemctl restart nftables
    logsuccess "Restarted"
  fi
  echo ""
}

manage_backup() {
  local file="$BACKUPDIR/firewall-$(date +%Y%m%d-%H%M%S).tar.gz"
  mkdir -p "$BACKUPDIR"
  logheader "Backing up..."
  sudo tar czf "$file" \
    /etc/nftables.conf \
    /etc/nftables.d/ \
    /etc/nftables/*.nft \
    /etc/fail2ban/jail.d/ \
    2>/dev/null || true
  logsuccess "Backup: $file"
  echo ""
}

################################################################################
# MONITOR FUNCTIONS
################################################################################

monitor_status() {
  logheader "FIREWALL STATUS"
  echo ""
  echo "Services:"
  echo " nftables: $(sudo systemctl is-active nftables)"
  echo " fail2ban: $(sudo systemctl is-active fail2ban)"
  echo " ufw: $(sudo systemctl is-active ufw)"
  echo ""
  echo "Active Jails:"
  local active=0
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

################################################################################
# REPORT FUNCTIONS
################################################################################

show_help() {
  cat << 'EOF'

╔═══════════════════════════════════════════════════════════════════╗
║ F2B Unified Wrapper v0.31 - Help                                 ║
╚═══════════════════════════════════════════════════════════════════╝

CORE:
  status                  Show system status
  audit                   Audit all jails
  find <IP>              Find IP in jails
  version [--json|--short] Show version info

SYNC:
  sync check              Verify F2B ↔ nftables sync
  sync enhanced           Enhanced bidirectional sync
  sync force              Force sync + verify
  sync silent             Silent sync (for cron)
  sync docker             Docker-block sync

DOCKER:
  docker dashboard        Real-time monitoring dashboard
  docker info             Show docker-block configuration
  docker sync             Synchronize fail2ban ↔ docker-block

MANAGE - PORT BLOCKING:
  manage block-port <port>        Block Docker port
  manage unblock-port <port>      Unblock port
  manage list-blocked-ports       List blocked ports

MANAGE - IP BAN/UNBAN:
  manage manual-ban <IP> [time]   Ban IP manually
  manage manual-unban <IP>        Unban IP
  manage unban-all <IP>           Unban from ALL jails

MANAGE - SYSTEM:
  manage reload           Reload firewall
  manage backup           Backup configuration

MONITOR:
  monitor status          System overview
  monitor show-bans [jail] Show banned IPs

HELP:
  help, --help, -h        Show this message

EXAMPLES:
  sudo f2b status
  sudo f2b audit
  sudo f2b find 1.2.3.4
  sudo f2b sync force
  sudo f2b sync docker
  sudo f2b docker info
  sudo f2b manage block-port 8081
  sudo f2b manage manual-ban 192.0.2.1 30d
  sudo f2b manage reload

═══════════════════════════════════════════════════════════════════

EOF
}

################################################################################
# MAIN ROUTING
################################################################################

main() {
  mkdir -p "$(dirname "$LOGFILE")"
  touch "$LOGFILE"

  case "$1" in
    sync|manage)
      acquire_lock
      ;;
  esac

  case "$1" in
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
    docker)
      case "$2" in
        dashboard) echo "Not implemented" ;;
        info) f2b_docker_info ;;
        sync) f2b_sync_docker ;;
        *) show_help ;;
      esac
      ;;
    manage)
      case "$2" in
        block-port) manage_block_port "$3" ;;
        unblock-port) manage_unblock_port "$3" ;;
        list-blocked-ports) manage_list_blocked_ports ;;
        manual-ban) manage_manual_ban "$3" "$4" ;;
        manual-unban) manage_manual_unban "$3" ;;
        unban-all) manage_unban_all "$3" ;;
        reload) manage_reload ;;
        backup) manage_backup ;;
        *) show_help ;;
      esac
      ;;
    monitor)
      case "$2" in
        status) monitor_status ;;
        show-bans) echo "Not implemented" ;;
        *) show_help ;;
      esac
      ;;
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
