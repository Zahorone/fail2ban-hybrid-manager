#!/bin/bash

################################################################################
# F2B Unified Wrapper v0.33 - PRODUCTION
# Complete Fail2Ban + nftables + docker-block management
#
# REQUIREMENTS:
# - fail2ban
# - nftables
# - jq (JSON processor) - install: sudo apt install jq
#
# v0.33 CHANGES (2026-01-01):
#   - Added nginx-php-errors jail/set awareness (12 jails, 24 nft sets)
#   - Minor output updates to reflect v0.33 infrastructure
#
# v0.32 CHANGES (2025-12-20):
#   - Lock mechanizmus (/tmp/f2b-wrapper.lock) proti paralelným runom
#   - Vylepšené validate_port()/validate_ip() (IPv6 check cez ip(8) + fallback)
#   - jq helpery + bezpečnejšie JSON parsovanie (nft -j …) / prettify výstupov
#   - Reporty (report json/csv/daily), audit-silent, stats-quick
#   - Attack analysis + rozšírený version output
#
# v0.31 CHANGES:
#   - Docker sync union pre všetky F2B sety + správna { IP } syntax
#   - Korektný IPv4/IPv6 sync + opravené docker info
#   - manage block/unblock port ({ port } syntax)
#   - All v0.30 functions preserved
################################################################################
# Component: F2B Wrapper
#
# Part of: Fail2Ban Hybrid Nftables Manager
################################################################################

set -o pipefail

# Meta
# shellcheck disable=SC2034
RELEASE="v0.33"
# shellcheck disable=SC2034
VERSION="0.33"
# shellcheck disable=SC2034
BUILD_DATE="2026-01-01"
# shellcheck disable=SC2034
COMPONENT_NAME="F2B-WRAPPER"
# shellcheck disable=SC2034
DOCKER_BLOCK_VERSION="0.4"

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
DARK_GRAY='\033[0;90m'
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
  "nginx-php-errors"
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
  ["nginx-php-errors"]="f2b-nginx-php-errors"
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

# Short aliases (v0.31 style)
logsuccess() { log_success "$@"; }
logerror()  { log_error   "$@"; }
logwarn()   { log_warn    "$@"; }
loginfo()   { log_info    "$@"; }
logheader() { log_header  "$@"; }
logalert()  { log_alert   "$@"; }

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

  # IPv4
  if [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
    return 0
  fi

  # IPv6 – jednoduchý, ale prísnejší check cez ip(8)
  if command -v ip >/dev/null 2>&1; then
    if ip -6 addr add "$ip/128" dev lo 2>/dev/null; then
      ip -6 addr del "$ip/128" dev lo 2>/dev/null
      return 0
    else
      logerror "Invalid IP address: $ip"
      return 1
    fi
  fi

  # Fallback: dnešná heuristika
  if [[ "$ip" =~ ^[0-9a-fA-F:]+$ ]] && [[ "$ip" == *:* ]]; then
    return 0
  fi

  logerror "Invalid IP address: $ip"
  return 1
}

################################################################################
# JQ HELPER FUNCTIONS
################################################################################

jq_check_installed() {
  if ! command -v jq >/dev/null 2>&1; then
    log_warn "jq not installed - falling back to grep/awk"
    return 1
  fi
  return 0
}

clean_number() {
  local val="$1"
  # Remove non-digits, keep first numeric token, default to 0
  val=$(echo "$val" | tr -d '\r\n' | grep -oE '[0-9]+' | head -1)
  echo "${val:-0}"
}

jq_safe_parse() {
  local input="$1"
  local query="$2"

  if ! jq_check_installed; then
    echo ""
    return 1
  fi

  # First: basic validation (no output, just syntax check)
  echo "$input" | jq '.' >/dev/null 2>&1 || {
    echo ""
    return 1
  }

  # Then: apply query, raw output
  echo "$input" | jq -r "$query" 2>/dev/null
}

jq_prettify() {
  if jq_check_installed; then
    jq -C . 2>/dev/null || cat
  else
    cat
  fi
}

cleanup_tmp() { [ -n "${1:-}" ] && rm -f "$1"; }

################################################################################
# HELPER FUNCTIONS (Fail2Ban & nftables, IPv4 + IPv6)
################################################################################

# get_f2b_count JAIL [all|v4|v6]
#  - all: celkový počet z fail2ban (pôvodné správanie)
#  - v4: iba IPv4 (počítané cez get_f2b_ips + grep)
#  - v6: iba IPv6
get_f2b_count() {
  local jail="$1"
  local family="${2:-all}"   # all|v4|v6

  case "$family" in
    all)
      # zachovaj pôvodné správanie (rýchle)
      local count
      count=$(sudo fail2ban-client status "$jail" 2>/dev/null \
        | grep "Currently banned" \
        | awk '{print $NF}' \
        | head -n1 \
        | tr -d '[:space:]')
      echo "${count:-0}"
      ;;
    v4)
      get_f2b_ips "$jail" | grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}$' | wc -l | tr -d '[:space:]'
      ;;
    v6)
      get_f2b_ips "$jail" | grep -F ':' | wc -l | tr -d '[:space:]'
      ;;
    *)
      log_error "get_f2b_count: invalid family '$family' (use all|v4|v6)"
      return 1
      ;;
  esac
}

get_f2b_ips() {
  local jail="$1"

  sudo fail2ban-client status "$jail" 2>/dev/null \
    | awk '/Banned IP list:/ {
        sub(/^.*Banned IP list:[[:space:]]*/, "", $0);
        print;
        exit
      }' \
    | tr ' ' '\n' \
    | while IFS= read -r tok; do
        [[ -z "$tok" ]] && continue
        # TITLE Keep current fast heuristics
        if [[ "$tok" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
          echo "$tok"
          continue
        fi
        if [[ "$tok" =~ ^[0-9a-fA-F:]+$ ]] && [[ "$tok" == *:* ]]; then
          echo "$tok"
          continue
        fi
      done \
    | sort -u
}

get_nft_ips() {
  local set="$1"

  # TITLE IPv4/IPv6 IP extraction from nftables set with optional JSON parsing

  if jq_check_installed; then
    # TITLE Prefer JSON parsing when jq is available (supports both elem schemas)
    sudo nft -j list set "$F2BTABLE" "$set" 2>/dev/null \
      | jq -r '
          .nftables[]
          | select(.set? and .set.elem?)
          | .set.elem[]
          | if type == "string" then .
            elif type == "object" then (.elem.val // empty)
            else empty
            end
        ' 2>/dev/null \
      | sed '/^$/d' \
      | sort -u
  else
    # TITLE Fallback: regex-based parsing (current behavior)
    if [[ "$set" == *-v6 ]]; then
      sudo nft list set "$F2BTABLE" "$set" 2>/dev/null \
        | grep -oE '[0-9a-fA-F:]+' \
        | grep -F ':' \
        | sort -u
    else
      sudo nft list set "$F2BTABLE" "$set" 2>/dev/null \
        | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' \
        | sort -u
    fi
  fi
}


# count_ips LIST
#  - pomocná funkcia pre „počet riadkov IP“ s default 0
count_ips() {
  local ips="$1"
  if [ -z "$ips" ]; then
    echo "0"
  else
    echo "$ips" | wc -l | tr -d ' '
  fi
}

# F2B ALERT NOW – rýchly status za posledných N minút (default 5)
f2b_alert_now() {
    local minutes="${1:-5}"
    local log="/var/log/fail2ban.log"

    if [ ! -f "$log" ]; then
        logerror "Fail2Ban log not found: $log"
        return 1
    fi

    log_header "F2B ALERT NOW (last ${minutes} minutes)"

    # časový prah
    local since
    since=$(date -d "-${minutes} min" +"%Y-%m-%d %H:%M:%S")

    local bans_raw attempts_raw

    # reálne nové bany (bez Restore Ban)
    bans_raw=$(awk -v since="$since" '
        $1" "$2 >= since && $0 ~ /fail2ban.actions/ && $0 ~ / Ban / && $0 !~ /Restore Ban/ { print }
    ' "$log")

    # všetky útoky (Found) – vrátane tých, čo neskončia banom
    attempts_raw=$(awk -v since="$since" '
        $1" "$2 >= since && $0 ~ /fail2ban.filter/ && $0 ~ / Found / { print }
    ' "$log")

    # počty
    local bans_count attempts_count
    bans_count=$(echo "$bans_raw" | grep -c . 2>/dev/null || true)
    attempts_count=$(echo "$attempts_raw" | grep -c . 2>/dev/null || true)

    bans_count="$(clean_number "${bans_count:-0}")"
    attempts_count="$(clean_number "${attempts_count:-0}")"



    # Level podľa počtu reálnych banov
    local level="LOW"
    if   [ "$bans_count" -ge 200 ]; then level="CRITICAL"
    elif [ "$bans_count" -ge 50  ]; then level="HIGH"
    elif [ "$bans_count" -ge 10  ]; then level="MODERATE"
    fi

    # per-jail count
    local jail_stats
    jail_stats=$(echo "$bans_raw" \
        | awk '{
            jail=""
            for (i=1; i<=NF; i++) {
                if ($i ~ /^\[.*\]$/) {
                    jail=$i
                    gsub(/[][]/, "", jail)
                }
            }
            if (jail != "") c[jail]++
        }
        END {
            for (j in c) {
                printf "%s(%d) ", j, c[j]
            }
        }')

    loginfo "Bans (${minutes}m): ${bans_count}"
    loginfo "Attempts    : ${attempts_count}"
    loginfo "Level       : ${level}"
    [ -n "$jail_stats" ] && loginfo "Jails       : ${jail_stats}"

    case "$level" in
        LOW)      logsuccess "Status: LOW – safe for maintenance." ;;
        MODERATE) logwarn    "Status: MODERATE – watch during changes." ;;
        HIGH)     logalert   "Status: HIGH – avoid major config changes now." ;;
        CRITICAL) logalert   "Status: CRITICAL – do NOT change NPM/nginx, monitor live (f2b monitor watch)." ;;
    esac
}

################################################################################
# CORE FUNCTIONS
################################################################################

# f2b_version [--json|--short|--human]
#  --json  : strojovo spracovateľný výstup
#  --short : iba VERSION string (na skripty)
#  --human : pekný ľudský výstup (default)
f2b_version() {
  local mode="${1:---human}"
  local binary_path
  local jails_count=0

  case "$mode" in
    --json)
      binary_path=$(readlink -f "$(command -v f2b 2>/dev/null)" 2>/dev/null \
        || echo "/usr/local/bin/f2b")

      if systemctl is-active --quiet fail2ban 2>/dev/null; then
        jails_count=$(fail2ban-client status 2>/dev/null \
          | grep "Jail list" \
          | sed 's/.*Jail list:\s*//' \
          | tr ',' '\n' \
          | grep -c '.')
      fi

      cat <<EOF
{
  "release": "${RELEASE}",
  "version": "${VERSION}",
  "builddate": "${BUILD_DATE}",
  "dockerblock_version": "${DOCKER_BLOCK_VERSION}",
  "component": "${COMPONENT_NAME}",
  "fail2ban_jails": ${jails_count},
  "binary": "${binary_path}"
}
EOF
      ;;

    --short)
      echo "${VERSION}"
      ;;

    --human|*)
      log_header "F2B Unified Wrapper ${RELEASE}"
      echo
      echo "Version      : ${VERSION}"
      echo "Build        : ${BUILD_DATE}"
      echo "Component    : ${COMPONENT_NAME}"
      echo "Docker-block : v${DOCKER_BLOCK_VERSION}"
      echo

      local f2b_path checksum
      f2b_path="$(command -v f2b 2>/dev/null || echo "not in PATH")"
      echo "Binary       : ${f2b_path}"
      if [ -x "${f2b_path}" ] && [ "${f2b_path}" != "not in PATH" ]; then
        checksum=$(sha256sum "${f2b_path}" 2>/dev/null | awk '{print $1}' | cut -c1-16)
        echo "Checksum     : sha256:${checksum:-unavailable}"
      fi
      echo

      echo "Components:"
      echo "  - Fail2Ban nftables integration"
      echo "  - Docker port blocking v${DOCKER_BLOCK_VERSION}"
      echo "  - Enhanced sync monitoring"
      echo "  - Attack analysis reporting"
      echo "  - Real-time Dashboard"
      echo

      if systemctl is-active --quiet fail2ban 2>/dev/null; then
        echo "Configuration:"
        if nft list table inet fail2ban-filter >/dev/null 2>&1; then
          echo "  - Table inet fail2ban-filter"

          local jails_active sets_v4 sets_v6 missing_v6 setname jail
          jails_active=$(fail2ban-client status 2>/dev/null \
            | grep "Jail list" \
            | sed 's/.*Jail list:\s*//' \
            | tr ',' '\n' \
            | grep -c '.')
          echo "  - Jails: ${jails_active} active"

          sets_v4=0
          sets_v6=0
          missing_v6=0

          for jail in "${JAILS[@]}"; do
            setname="${SETMAP[$jail]}"
            [ -z "${setname}" ] && continue

            if sudo nft list set inet fail2ban-filter "${setname}" >/dev/null 2>&1; then
              sets_v4=$((sets_v4 + 1))
            fi
            if sudo nft list set inet fail2ban-filter "${setname}-v6" >/dev/null 2>&1; then
              sets_v6=$((sets_v6 + 1))
            else
              missing_v6=$((missing_v6 + 1))
            fi
          done

          local sets_total
          sets_total=$((sets_v4 + sets_v6))
          echo "  - Sets: ${sets_total} (v4: ${sets_v4}, v6: ${sets_v6}, missing v6: ${missing_v6})"

          if [ "${missing_v6}" -eq 0 ] && [ "${sets_v6}" -gt 0 ]; then
            echo "  - IPv6 readiness: READY (all mapped jails have -v6 sets)"
          else
            echo "  - IPv6 readiness: INCOMPLETE (${missing_v6} jails without -v6 sets)"
          fi
        else
          echo "  - Table inet fail2ban-filter: NOT FOUND"
        fi
      else
        echo "Configuration:"
        echo "  - Fail2Ban not running"
      fi

      echo
      echo "Usage:"
      echo "  f2b help            - Show all commands"
      echo "  f2b status          - System status"
      echo "  f2b version --json  - JSON output"
      echo "  f2b version --short - Short version"
      ;;
  esac
}

# f2b_status – rýchly prehľad služieb a jadra konfigurácie
f2b_status() {
  log_header "F2B System Status v${VERSION}"
  echo

  echo "Services:"
  if systemctl is-active --quiet nftables 2>/dev/null; then
    log_success "nftables active"
  else
    log_error   "nftables inactive"
  fi

  if systemctl is-active --quiet fail2ban 2>/dev/null; then
    log_success "fail2ban active"
  else
    log_error   "fail2ban inactive"
  fi

  if sudo ufw status 2>/dev/null | grep -q "Status: active"; then
    log_success "ufw active"
  else
    log_warn    "ufw inactive"
  fi

  echo
  echo "Active Jails:"
  if ! fail2ban-client status 2>/dev/null | grep "Jail list" >/dev/null 2>&1; then
    log_error "Could not retrieve jails"
  else
    fail2ban-client status 2>/dev/null \
      | grep "Jail list" \
      | sed 's/.*Jail list:\s*//' \
      | tr ',' '\n' \
      | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' \
      | while read -r jail; do
          [ -z "${jail}" ] && continue
          local count
          count=$(get_f2b_count "${jail}" all | tr -d ' ')
          echo "  - ${jail}: ${count} IPs"
        done
  fi

  echo
  echo "NFT Tables:"
  local tables
  tables=$(sudo nft list tables 2>/dev/null | grep -E "fail2ban|docker-block" | sed 's/^/  - /')
  if [ -n "${tables}" ]; then
    echo "${tables}"
  else
    echo "  - none"
  fi

  echo
  echo "docker-block v${DOCKER_BLOCK_VERSION}:"
  if sudo nft list table inet docker-block >/dev/null 2>&1; then
    log_success "Active external blocking, localhost allowed"
    sudo nft list set inet docker-block docker-blocked-ports 2>/dev/null \
      | grep "elements" \
      | sed 's/.*elements = //'
    if [ "${PIPESTATUS[0]}" -ne 0 ]; then
      echo "  No blocked ports"
    fi
  else
    log_warn "Not configured"
  fi
}

# f2b_audit – jednoduchý audit počtu IP v jailoch
f2b_audit() {
  log_header "Fail2Ban Audit"
  local total=0
  local clean=0

  for jail in "${JAILS[@]}"; do
    local count
    count=$(get_f2b_count "${jail}" all | tr -d ' ')
    count=${count:-0}
    if [ "${count}" -eq 0 ]; then
      log_success "${jail} clean"
      clean=$((clean + 1))
    else
      log_warn    "${jail} ${count} IPs"
    fi
    total=$((total + count))
  done

  echo
  log_info "Total Jails : ${#JAILS[@]}"
  log_info "Clean       : ${clean}"
  log_info "Total IPs   : ${total}"

  if [ "${total}" -eq 0 ]; then
    log_success "ALL CLEAN!"
  else
    log_warn "Active bans: ${total}"
  fi
}

f2b_find() {
  local IP="$1"

  if [ -z "$IP" ]; then
    log_error "Usage: f2b find <IP>"
    return 1
  fi

  # Detect IP family (v4 / v6)
  local IP_FAMILY=""
  if [[ "$IP" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
    IP_FAMILY="4"
  elif [[ "$IP" =~ ^[0-9a-fA-F:]+$ ]] && [[ "$IP" == *:* ]]; then
    IP_FAMILY="6"
  else
    log_error "Invalid IP address: $IP"
    return 1
  fi

  log_header "Searching for $IP"
  local found=0

  for jail in "${JAILS[@]}"; do
    # Find in jail (no parsing of set output; only check Fail2Ban state)
    if sudo fail2ban-client status "$jail" 2>/dev/null | grep -Fq "$IP"; then
      log_success "Found in jail: $jail"

      local bantime
      bantime=$(sudo fail2ban-client get "$jail" bantime 2>/dev/null || echo "unknown")
      log_info "Ban time: $bantime"

      local nftset="${SETMAP[$jail]}"
      if [ -z "$nftset" ]; then
        log_warn "nftables: No set mapping for jail '$jail' (SETMAP missing)"
      else
        local set_to_check="$nftset"
        [ "$IP_FAMILY" = "6" ] && set_to_check="${nftset}-v6"

        if ! sudo nft list set $F2BTABLE "$set_to_check" &>/dev/null; then
          log_warn "nftables: Set not found: $set_to_check"
        elif sudo nft get element $F2BTABLE "$set_to_check" "{ $IP }" &>/dev/null; then
          log_info "nftables: Present in $set_to_check"

          # Metadata (best-effort; ignore errors)
          if jq_check_installed; then
            local metadata
            metadata=$(
              sudo nft --json list set inet fail2ban-filter "$set_to_check" 2>/dev/null | \
                jq -r ".nftables[] | select(.set.elem) | .set.elem[] | select(.elem) |
                      select(.elem.val == \"$IP\") |
                      \"  ↳ timeout: \(.elem.timeout // \\\"permanent\\\"), expires: \(.elem.expires // \\\"never\\\")\"" 2>/dev/null
            )
            [ -n "$metadata" ] && echo -e "${CYAN}$metadata${NC}"
          fi
        else
          log_warn "nftables: NOT in $set_to_check (sync issue!)"
        fi
      fi

      # docker-block membership
      if sudo nft list table inet docker-block &>/dev/null; then
        if [ "$IP_FAMILY" = "4" ]; then
          if sudo nft get element inet docker-block docker-banned-ipv4 "{ $IP }" &>/dev/null; then
            log_success "docker-block: Present ✅"
          else
            log_warn "docker-block: NOT present (sync needed)"
          fi
        else
          if sudo nft get element inet docker-block docker-banned-ipv6 "{ $IP }" &>/dev/null; then
            log_success "docker-block: Present ✅"
          else
            log_warn "docker-block: NOT present (sync needed)"
          fi
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
  fi

  log_success "Search complete"
  return 0
}

################################################################################
# SYNC FUNCTIONS
################################################################################

# f2b_sync_check – porovná F2B a nft counts pre každý jail (v4 + v6)
f2b_sync_check() {
  log_header "═══════════════════════════════════════════════════════"
  echo " Fail2Ban ↔ nftables Sync Check (IPv4 + IPv6)"
  log_header "═══════════════════════════════════════════════════════"
  echo ""

  local ALLSYNCED=true

  for jail in "${JAILS[@]}"; do
    local nftset="${SETMAP[$jail]}"

    # F2B counts (v4/v6)
    local F4 F6
    F4="$(get_f2b_ips "$jail" | grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}$' | wc -l | tr -d '[:space:]')"
    F6="$(get_f2b_ips "$jail" | grep -F ':' | wc -l | tr -d '[:space:]')"

    # nftables counts (v4/v6)
    local N4 N6
    N4=0; N6=0

    if [ -n "$nftset" ]; then
      # v4 set
      if sudo nft list set "$F2BTABLE" "$nftset" &>/dev/null; then
        N4="$(get_nft_ips "$nftset" | wc -l | tr -d '[:space:]')"
      fi
      # v6 set (expected name: ${nftset}-v6)
      if sudo nft list set "$F2BTABLE" "${nftset}-v6" &>/dev/null; then
        N6="$(get_nft_ips "${nftset}-v6" | wc -l | tr -d '[:space:]')"
      fi
    fi

    local DIFF4 DIFF6 DIFF4ABS DIFF6ABS
    DIFF4=$((F4 - N4)); DIFF4ABS=${DIFF4#-}
    DIFF6=$((F6 - N6)); DIFF6ABS=${DIFF6#-}

    # Výpis pre jail
    if [ "$F4" -eq "$N4" ] && [ "$F6" -eq "$N6" ]; then
      log_success "[$jail] v4: $F4==$N4, v6: $F6==$N6"
    else
      # IPv4 časť
      if [ "$F4" -eq "$N4" ]; then
        log_info    "[$jail] IPv4: F2B=$F4, nft=$N4 (OK)"
      elif [ "$DIFF4ABS" -le 1 ]; then
        log_success "[$jail] IPv4: F2B=$F4, nft=$N4 (±1 range merge)"
      else
        log_warn    "[$jail] IPv4: F2B=$F4, nft=$N4 (MISMATCH)"
        ALLSYNCED=false
      fi

      # IPv6 časť
      if [ "$F6" -eq "$N6" ]; then
        log_info    "[$jail] IPv6: F2B=$F6, nft=$N6 (OK)"
      elif [ "$DIFF6ABS" -le 1 ]; then
        log_success "[$jail] IPv6: F2B=$F6, nft=$N6 (±1 range merge)"
      else
        log_warn    "[$jail] IPv6: F2B=$F6, nft=$N6 (MISMATCH)"
        ALLSYNCED=false
      fi
    fi
  done

  echo ""
  if $ALLSYNCED; then
    log_success "[OK] All jails synchronized (IPv4 + IPv6)!"
  else
    log_warn "Some jails out of sync - run 'f2b sync force'"
  fi
  echo ""
}


# f2b_sync_enhanced – dvojstranný sync s reportom
f2b_sync_enhanced() {
  log_header "F2B SYNC ENHANCED (bidirectional)"
  local removed=0
  local added=0

  log_header "Phase 1 – Remove orphaned IPs"
  for jail in "${JAILS[@]}"; do
    local nft_set="${SETMAP[${jail}]}"
    [ -z "${nft_set}" ] && continue

    local f2b_ips nft_ips ip
    f2b_ips=$(get_f2b_ips "${jail}")
    nft_ips=$(get_nft_ips "${nft_set}")

    local f2b_count nft_count
    f2b_count=$(count_ips "${f2b_ips}")
    nft_count=$(count_ips "${nft_ips}")
    log_info "${jail} F2B=${f2b_count}, NFT=${nft_count}"

    if [ -z "${f2b_ips}" ]; then
      while read -r ip; do
        [ -z "${ip}" ] && continue
        sudo nft delete element "${F2BTABLE}" "${nft_set}" "{ ${ip} }" 2>/dev/null && removed=$((removed + 1))
      done <<<"${nft_ips}"
    else
      while read -r ip; do
        [ -z "${ip}" ] && continue
        if ! echo "${f2b_ips}" | grep -Fxq "${ip}"; then
          sudo nft delete element "${F2BTABLE}" "${nft_set}" "{ ${ip} }" 2>/dev/null && removed=$((removed + 1))
        fi
      done <<<"${nft_ips}"
    fi
  done

  echo
  log_header "Phase 2 – Add missing IPs"
  for jail in "${JAILS[@]}"; do
    local nft_set="${SETMAP[${jail}]}"
    [ -z "${nft_set}" ] && continue

    local f2b_ips nft_ips ip
    f2b_ips=$(get_f2b_ips "${jail}")
    nft_ips=$(get_nft_ips "${nft_set}")

    while read -r ip; do
      [ -z "${ip}" ] && continue
      if ! echo "${f2b_ips}" | grep -Fxq "${ip}"; then
        sudo nft add element "${F2BTABLE}" "${nft_set}" "{ ${ip} }" 2>/dev/null && added=$((added + 1))
      fi
    done <<<"${f2b_ips}"
  done

  echo
  log_header "SYNC REPORT"
  log_success "Removed orphaned : ${removed}"
  log_success "Added missing    : ${added}"
  if [ "${removed}" -gt 0 ] || [ "${added}" -gt 0 ]; then
    log_success "Synchronization completed!"
  else
    log_warn "No changes needed"
  fi
  echo
}

# f2b_sync_force – alias na enhanced + check
f2b_sync_force() {
  f2b_sync_enhanced
  f2b_sync_check
}

# sync_silent – tichá F2B → nft sync pre cron
sync_silent() {
  local LOGFILE="/var/log/f2b-sync.log"
  local CHANGES=0

  echo "$(date '+%Y-%m-%d %H:%M:%S') Starting silent sync..." >>"$LOGFILE"

  for jail in "${JAILS[@]}"; do
    local nft_set="${SETMAP[${jail}]}"
    [ -z "${nft_set}" ] && continue

    local f2b_ips nft_ips ip

    f2b_ips=$(get_f2b_ips "${jail}")
    nft_ips=$(get_nft_ips "${nft_set}")

    # Remove orphaned IPs z nft setu
    if [ -z "${f2b_ips}" ]; then
      while read -r ip; do
        [ -z "${ip}" ] && continue
        sudo nft delete element "${F2BTABLE}" "${nft_set}" "{ ${ip} }" 2>/dev/null && CHANGES=$((CHANGES + 1)) \
          && echo "$(date '+%Y-%m-%d %H:%M:%S') Removed orphan ${ip} from ${jail}" >>"$LOGFILE"
      done <<<"${nft_ips}"
    else
      while read -r ip; do
        [ -z "${ip}" ] && continue
        if ! echo "${f2b_ips}" | grep -Fxq "${ip}"; then
          sudo nft delete element "${F2BTABLE}" "${nft_set}" "{ ${ip} }" 2>/dev/null && CHANGES=$((CHANGES + 1)) \
            && echo "$(date '+%Y-%m-%d %H:%M:%S') Removed orphan ${ip} from ${jail}" >>"$LOGFILE"
        fi
      done <<<"${nft_ips}"
    fi

    # Add missing IPs do nft setu
    while read -r ip; do
      [ -z "${ip}" ] && continue
      if ! echo "${nft_ips}" | grep -Fxq "${ip}"; then
        sudo nft add element "${F2BTABLE}" "${nft_set}" "{ ${ip} }" 2>/dev/null && CHANGES=$((CHANGES + 1)) \
          && echo "$(date '+%Y-%m-%d %H:%M:%S') Added ${ip} to ${jail}" >>"$LOGFILE"
      fi
    done <<<"${f2b_ips}"
  done

  if [ "${CHANGES}" -eq 0 ]; then
    echo "$(date '+%Y-%m-%d %H:%M:%S') Sync OK - no changes" >>"$LOGFILE"
  else
    echo "$(date '+%Y-%m-%d %H:%M:%S') Sync completed - ${CHANGES} changes" >>"$LOGFILE"
  fi
}

################################################################################
# F2B DOCKER VERIFY – deep sync check (IPv4)
################################################################################

f2b_docker_verify() {
  log_header "F2B Docker-Block Deep Verify (IPv4 union)"

  # 1) JAILY ↔ F2B NFT SETY
  log_info "STEP 1: F2B jails vs F2B nft sets (IPv4 union)"

  local ALL_JAILS ALL_SETS
  local jail set

  ALL_JAILS=$(
    for jail in "${JAILS[@]}"; do
      get_f2b_ips "$jail" 2>/dev/null \
        | grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}$' || true
    done | sort -u
  )

  ALL_SETS=$(
    for set in \
      f2b-sshd \
      f2b-sshd-slowattack \
      f2b-exploit-critical \
      f2b-dos-high \
      f2b-web-medium \
      f2b-nginx-recon-bonus \
      f2b-recidive \
      f2b-manualblock \
      f2b-fuzzing-payloads \
      f2b-botnet-signatures \
      f2b-anomaly-detection; do
      sudo nft list set inet fail2ban-filter "$set" 2>/dev/null \
        | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' || true
    done | sort -u
  )

  local JAIL_NOT_IN_SET SET_NOT_IN_JAIL
  JAIL_NOT_IN_SET=$(comm -23 <(echo "$ALL_JAILS") <(echo "$ALL_SETS") || true)
  SET_NOT_IN_JAIL=$(comm -13 <(echo "$ALL_JAILS") <(echo "$ALL_SETS") || true)

  if [[ -z "$JAIL_NOT_IN_SET" && -z "$SET_NOT_IN_JAIL" ]]; then
    log_success "Jaily a F2B nft sety sú 1:1 (IPv4 union)."
  else
    log_warn "Rozdiely medzi jailmi a F2B setmi (IPv4):"
    [[ -n "$JAIL_NOT_IN_SET" ]] && {
      echo "  - V jailoch, nie v F2B setoch:"
      echo "$JAIL_NOT_IN_SET"
    }
    [[ -n "$SET_NOT_IN_JAIL" ]] && {
      echo "  - Vo F2B setoch, nie v jailoch:"
      echo "$SET_NOT_IN_JAIL"
    }
  fi

  echo
  log_info "STEP 2: Membership check: ALL F2B nft IPs are contained in docker-block (IPv4 union)"

  if ! sudo nft list table inet docker-block >/dev/null 2>&1; then
    log_error "docker-block table NOT FOUND (install docker-block v0.4 first)."
    return 1
  fi

  local miss_count=0
  local max_sample=20

  while read -r ip; do
    sudo nft get element inet docker-block docker-banned-ipv4 "{ $ip }" >/dev/null 2>&1 \
      || {
        miss_count=$((miss_count+1))
        if [ "$miss_count" -le "$max_sample" ]; then
          log_warn "MISS $ip"
        fi
      }
  done < <(echo "$ALL_SETS")

  if [ "$miss_count" -eq 0 ]; then
    log_success "docker-block obsahuje všetky IP z F2B setov (0 misses)."
  else
    log_warn "docker-block NEobsahuje všetky IP z F2B setov: misses=$miss_count (vypísané prvé $max_sample)."
    return 2
  fi

  echo
  log_info "STEP 3: Súhrn počtov (IPv4)"

  local JAIL_UNIQUE SET_UNIQUE
  JAIL_UNIQUE=$(echo "$ALL_JAILS" | wc -l | tr -d '[:space:]')
  SET_UNIQUE=$(echo "$ALL_SETS"  | wc -l | tr -d '[:space:]')

  echo "  Jaily IPv4 unique:       $JAIL_UNIQUE"
  echo "  F2B sety IPv4 unique:    $SET_UNIQUE"
  echo
  log_info "Poznámka: reálna konzistencia F2B → docker-block sa rieši v STEP 2 (nftables interval/auto-merge robí plain count porovnania nepresné)."
}

################################################################################
# F2B DOCKER SYNC (NEW v0.23)
################################################################################

# f2b_sync_docker_full – bidirectional union sync F2B ↔ docker-block (IPv4 + IPv6)
f2b_sync_docker_full() {
  log_header "F2B Docker-Block Bidirectional Sync"
  echo

  # Pre-sync: najprv zosynchronizuj F2B ↔ nft fail2ban-filter
  log_info "Pre-sync: synchronizing Fail2Ban nftables..."
  sync_silent
  echo

  if ! sudo nft list table inet docker-block >/dev/null 2>&1; then
    log_error "docker-block table NOT FOUND"
    log_info "Install with: bash 03-install-docker-block-v04.sh"
    echo
    return 1
  fi

  local LOGFILE="/var/log/f2b-docker-sync.log"
  sudo touch "$LOGFILE" 2>/dev/null || true
  log_info "Starting docker-block sync (union of all F2B sets)..."
  echo

  # Jails/sety, ktoré vstupujú do unionu
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

  ##############################################################################
  # IPv4 SYNC – UNION F2B setov ↔ docker-banned-ipv4
  ##############################################################################

  # 1. UNION všetkých IPv4 z F2B setov
  local F2BIPS
  F2BIPS=$(
    for SET in "${SETS[@]}"; do
      sudo nft list set inet fail2ban-filter "${SET}" 2>/dev/null \
        | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' || true
    done | sort -u
  )

  # 2. Pridaj IP, ktoré sú vo F2B a nie sú v docker-block
    while IFS= read -r IP; do
      [ -z "$IP" ] && continue

      # membership check (správna nft syntax)
      # shellcheck disable=SC1083  
      if ! sudo nft get element inet docker-block docker-banned-ipv4 { "$IP" } >/dev/null 2>&1; then
        # ADD: bez explicitného timeoutu -> použije sa default timeout setu (u teba 7d)
        sudo nft add element inet docker-block docker-banned-ipv4 { "$IP" } 2>/dev/null || true
        echo "$(date '+%Y-%m-%d %H:%M:%S') ADDED IPv4 $IP" | sudo tee -a "$LOGFILE" >/dev/null
      fi
    done <<<"$F2BIPS"

  # 3. Odstráň IP, ktoré sú v docker-block, ale už nie sú v žiadnom F2B sete
  local DOCKERIPS
  DOCKERIPS=$(
    sudo nft list set inet docker-block docker-banned-ipv4 2>/dev/null \
      | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' \
      | sort -u || true
  )

  while IFS= read -r IP; do
    [ -z "$IP" ] && continue
    if ! echo "$F2BIPS" | grep -qx "$IP"; then
      sudo nft delete element inet docker-block docker-banned-ipv4 "{ $IP }" 2>/dev/null || true
      echo "$(date '+%Y-%m-%d %H:%M:%S') REMOVED IPv4 $IP (no longer in Fail2Ban)" \
        | sudo tee -a "$LOGFILE" >/dev/null
    fi
  done <<<"$DOCKERIPS"

  ##############################################################################
  # IPv6 SYNC – UNION F2B setov ↔ docker-banned-ipv6
  ##############################################################################

  local F2BIPS6
  F2BIPS6=$(
    for SET in "${SETS[@]}"; do
      sudo nft list set inet fail2ban-filter "${SET}-v6" 2>/dev/null \
        | grep -oE '[0-9a-fA-F: ]+' \
        | grep -F ':' || true
    done | sort -u
  )

  # 2. Pridaj IPv6 vo F2B, ktoré nie sú v docker-block
  while IFS= read -r IP; do
    [ -z "$IP" ] && continue
    if ! sudo nft get element inet docker-block docker-banned-ipv6 "{ $IP }" >/dev/null 2>&1; then
      sudo nft add element inet docker-block docker-banned-ipv6 "{ $IP }" 2>/dev/null || true

      echo "$(date '+%Y-%m-%d %H:%M:%S') ADDED IPv6 $IP" | sudo tee -a "$LOGFILE" >/dev/null
    fi
  done <<<"$F2BIPS6"

  # 3. Odstráň IPv6, ktoré sú v docker-block, ale už nie vo F2B
  local DOCKERIPS6
  DOCKERIPS6=$(
    sudo nft list set inet docker-block docker-banned-ipv6 2>/dev/null \
      | grep -oE '[0-9a-fA-F: ]+' \
      | grep -F ':' \
      | sort -u || true
  )

  while IFS= read -r IP; do
    [ -z "$IP" ] && continue
    if ! echo "$F2BIPS6" | grep -qx "$IP"; then
      sudo nft delete element inet docker-block docker-banned-ipv6 "{ $IP }" 2>/dev/null || true
      echo "$(date '+%Y-%m-%d %H:%M:%S') REMOVED IPv6 $IP (no longer in Fail2Ban)" \
        | sudo tee -a "$LOGFILE" >/dev/null
    fi
  done <<<"$DOCKERIPS6"

  ##############################################################################
  # METRIKY – porovnanie počtov (jaily vs docker-block)
  ##############################################################################

  # F2B: spočítaj všetky IP naprieč jailmi (v4)
  local TOTAL_JAIL_IPS=0
  local ALL_JAIL_IPS
  ALL_JAIL_IPS=$(
    for jail in "${JAILS[@]}"; do
      sudo fail2ban-client status "$jail" 2>/dev/null \
        | grep "Banned IP list" \
        | sed 's/.*Banned IP list:\s*//' \
        | tr ' ,' '\n' \
        | grep -E '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' || true
    done
  )

  if [ -n "$ALL_JAIL_IPS" ]; then
    TOTAL_JAIL_IPS=$(echo "$ALL_JAIL_IPS" | wc -l | tr -d ' ')
  fi

  local UNIQUE_IPS=0
  local UNIQUE_LIST
  UNIQUE_LIST=$(echo "$ALL_JAIL_IPS" | sort -u)
  if [ -n "$UNIQUE_LIST" ]; then
    UNIQUE_IPS=$(echo "$UNIQUE_LIST" | wc -l | tr -d ' ')
  fi

  local DUPLICATES=0
  if [ "$TOTAL_JAIL_IPS" -gt "$UNIQUE_IPS" ]; then
    DUPLICATES=$((TOTAL_JAIL_IPS - UNIQUE_IPS))
  fi

  # docker-block: presný count cez jq (IPv4)
  local DOCKER_IP_COUNT=0
  if jq_check_installed; then
    DOCKER_IP_COUNT=$(
      sudo nft -j list set inet docker-block docker-banned-ipv4 2>/dev/null \
        | jq -r '.nftables[] | select(.set.elem != null) | .set.elem | length' 2>/dev/null \
        | head -1
    )
    DOCKER_IP_COUNT=${DOCKER_IP_COUNT:-0}
  else
    DOCKER_IP_COUNT=$(
      sudo nft list set inet docker-block docker-banned-ipv4 2>/dev/null \
        | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' \
        | wc -l | tr -d ' '
    )
  fi

  log_header "SYNC METRICS"
# --- F2B totals (IPv4 + IPv6) across all jails (duplicates across jails are expected) ---
local ALL4 ALL6
ALL4="$(
  for jail in "${JAILS[@]}"; do
    get_f2b_ips "$jail" | grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}$' || true
  done
)"
ALL6="$(
  for jail in "${JAILS[@]}"; do
    get_f2b_ips "$jail" | grep -F ':' || true
  done
)"

local TOTAL4 TOTAL6 UNIQUE4 UNIQUE6 DUP4 DUP6
TOTAL4=0; TOTAL6=0; UNIQUE4=0; UNIQUE6=0; DUP4=0; DUP6=0

if [ -n "$ALL4" ]; then
  TOTAL4="$(echo "$ALL4" | wc -l | tr -d '[:space:]')"
  UNIQUE4="$(echo "$ALL4" | sort -u | wc -l | tr -d '[:space:]')"
  [ "$TOTAL4" -gt "$UNIQUE4" ] && DUP4=$((TOTAL4 - UNIQUE4))
fi

if [ -n "$ALL6" ]; then
  TOTAL6="$(echo "$ALL6" | wc -l | tr -d '[:space:]')"
  UNIQUE6="$(echo "$ALL6" | sort -u | wc -l | tr -d '[:space:]')"
  [ "$TOTAL6" -gt "$UNIQUE6" ] && DUP6=$((TOTAL6 - UNIQUE6))
fi

# --- docker-block element counts (note: interval/auto-merge can make counts differ) ---
local DOCKER4 DOCKER6
DOCKER4=0
DOCKER6=0

if jq_check_installed; then
  DOCKER4="$(sudo nft -j list set inet docker-block docker-banned-ipv4 2>/dev/null \
    | jq -r '.nftables[] | select(.set.elem) | .set.elem | length' 2>/dev/null | head -1)"
  DOCKER6="$(sudo nft -j list set inet docker-block docker-banned-ipv6 2>/dev/null \
    | jq -r '.nftables[] | select(.set.elem) | .set.elem | length' 2>/dev/null | head -1)"
else
  DOCKER4="$(sudo nft list set inet docker-block docker-banned-ipv4 2>/dev/null \
    | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | wc -l | tr -d '[:space:]')"
  DOCKER6="$(sudo nft list set inet docker-block docker-banned-ipv6 2>/dev/null \
    | grep -oE '([0-9a-fA-F:]+)' | grep -F ':' | wc -l | tr -d '[:space:]')"
fi

DOCKER4="${DOCKER4:-0}"
DOCKER6="${DOCKER6:-0}"

loginfo "Jails IPv4: total=$TOTAL4 (dup=$DUP4, unique=$UNIQUE4)"
loginfo "Jails IPv6: total=$TOTAL6 (dup=$DUP6, unique=$UNIQUE6)"
loginfo "Docker-block IPv4 elements: $DOCKER4 (auto-merge may differ from unique IPs)"
loginfo "Docker-block IPv6 elements: $DOCKER6 (auto-merge may differ from unique IPs)"

# diff check (keep your ±5 tolerance)
local DIFF4 DIFF6 DIFF4ABS DIFF6ABS
DIFF4=$((UNIQUE4 - DOCKER4)); DIFF4ABS=${DIFF4#-}
DIFF6=$((UNIQUE6 - DOCKER6)); DIFF6ABS=${DIFF6#-}

if [ "$DOCKER4" -eq "$UNIQUE4" ]; then
  logsuccess "✅ IPv4 perfect sync: $UNIQUE4 == $DOCKER4"
elif [ "$DIFF4ABS" -le 5 ]; then
  loginfo "ℹ️ IPv4 minor difference (±$DIFF4ABS) - normal due to nftables auto-merge"
else
  logwarn "⚠️ IPv4 significant difference: unique_jails=$UNIQUE4, docker-block=$DOCKER4"
fi

if [ "$DOCKER6" -eq "$UNIQUE6" ]; then
  logsuccess "✅ IPv6 perfect sync: $UNIQUE6 == $DOCKER6"
elif [ "$DIFF6ABS" -le 5 ]; then
  loginfo "ℹ️ IPv6 minor difference (±$DIFF6ABS) - normal due to nftables auto-merge"
else
  logwarn "⚠️ IPv6 significant difference: unique_jails=$UNIQUE6, docker-block=$DOCKER6"
fi
}

################################################################################
# F2B DOCKER SYNC (VALIDATION-ONLY) v0.31
# Purpose: Check & fix inconsistencies; immediate bans handled by docker-sync-hook
################################################################################

f2b_sync_docker() {
  log_header "F2B Docker-Block Validation Sync (Consistency Check)"
  echo ""

  # Pre-sync: synchronizuj F2B ↔ nft fail2ban-filter
  log_info "Pre-sync: synchronizing Fail2Ban nftables..."
  sync_silent
  echo ""

  if ! sudo nft list table inet docker-block >/dev/null 2>&1; then
    log_error "docker-block table NOT FOUND"
    log_info "Install with: bash 03-install-docker-block-v04.sh"
    echo ""
    return 1
  fi

  local LOGFILE="/var/log/f2b-docker-sync.log"
  sudo touch "$LOGFILE" 2>/dev/null || true
  log_info "Starting docker-block validation sync (union of all F2B sets)..."
  log_info "NOTE: Immediate bans are handled by fail2ban hook (docker-sync-hook action)"
  echo ""

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

  ##############################################################################
  # IPv4 VALIDATION – Remove orphaned IPs (docker-block IPs no longer in F2B)
  ##############################################################################

  # 1. Gather all IPv4 from F2B sets
  local F2BIPS
  F2BIPS=$(
    for SET in "${SETS[@]}"; do
      sudo nft list set inet fail2ban-filter "${SET}" 2>/dev/null \
        | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' || true
    done | sort -u
  )

  # 2. REMOVE orphaned IPs from docker-block (in docker-block but NOT in F2B)
  local REMOVED=0
  local DOCKERIPS
  DOCKERIPS=$(
    sudo nft list set inet docker-block docker-banned-ipv4 2>/dev/null \
      | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' \
      | sort -u || true
  )

  while IFS= read -r IP; do
    [ -z "$IP" ] && continue
    if ! echo "$F2BIPS" | grep -qx "$IP"; then
      sudo nft delete element inet docker-block docker-banned-ipv4 "{ $IP }" 2>/dev/null || true
      echo "$(date '+%Y-%m-%d %H:%M:%S') [SYNC] REMOVED IPv4 $IP (no longer in Fail2Ban)" \
        | sudo tee -a "$LOGFILE" >/dev/null
      REMOVED=$((REMOVED + 1))
    fi
  done <<<"$DOCKERIPS"

  ##############################################################################
  # IPv6 VALIDATION – Remove orphaned IPv6 addresses
  ##############################################################################

  local F2BIPS6
  F2BIPS6=$(
    for SET in "${SETS[@]}"; do
      sudo nft list set inet fail2ban-filter "${SET}-v6" 2>/dev/null \
        | grep -oE '[0-9a-fA-F:]+' \
        | grep -F ':' || true
    done | sort -u
  )

  local REMOVED6=0
  local DOCKERIPS6
  DOCKERIPS6=$(
    sudo nft list set inet docker-block docker-banned-ipv6 2>/dev/null \
      | grep -oE '[0-9a-fA-F:]+' \
      | grep -F ':' \
      | sort -u || true
  )

  while IFS= read -r IP; do
    [ -z "$IP" ] && continue
    if ! echo "$F2BIPS6" | grep -qx "$IP"; then
      sudo nft delete element inet docker-block docker-banned-ipv6 "{ $IP }" 2>/dev/null || true
      echo "$(date '+%Y-%m-%d %H:%M:%S') [SYNC] REMOVED IPv6 $IP (no longer in Fail2Ban)" \
        | sudo tee -a "$LOGFILE" >/dev/null
      REMOVED6=$((REMOVED6 + 1))
    fi
  done <<<"$DOCKERIPS6"

  ##############################################################################
  # METRICS – Compare counts
  ##############################################################################

  local ALL4 ALL6
  ALL4="$(
    for jail in "${JAILS[@]}"; do
      get_f2b_ips "$jail" | grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}$' || true
    done
  )"
  ALL6="$(
    for jail in "${JAILS[@]}"; do
      get_f2b_ips "$jail" | grep -F ':' || true
    done
  )"

  local TOTAL4 TOTAL6 UNIQUE4 UNIQUE6 DUP4 DUP6
  TOTAL4=0; TOTAL6=0; UNIQUE4=0; UNIQUE6=0; DUP4=0; DUP6=0

  if [ -n "$ALL4" ]; then
    TOTAL4="$(echo "$ALL4" | wc -l | tr -d '[:space:]')"
    UNIQUE4="$(echo "$ALL4" | sort -u | wc -l | tr -d '[:space:]')"
    [ "$TOTAL4" -gt "$UNIQUE4" ] && DUP4=$((TOTAL4 - UNIQUE4))
  fi

  if [ -n "$ALL6" ]; then
    TOTAL6="$(echo "$ALL6" | wc -l | tr -d '[:space:]')"
    UNIQUE6="$(echo "$ALL6" | sort -u | wc -l | tr -d '[:space:]')"
    [ "$TOTAL6" -gt "$UNIQUE6" ] && DUP6=$((TOTAL6 - UNIQUE6))
  fi

  local DOCKER4 DOCKER6
  DOCKER4=0
  DOCKER6=0

  if jq_check_installed; then
    DOCKER4="$(sudo nft -j list set inet docker-block docker-banned-ipv4 2>/dev/null \
      | jq -r '.nftables[] | select(.set.elem) | .set.elem | length' 2>/dev/null | head -1)"
    DOCKER6="$(sudo nft -j list set inet docker-block docker-banned-ipv6 2>/dev/null \
      | jq -r '.nftables[] | select(.set.elem) | .set.elem | length' 2>/dev/null | head -1)"
  else
    DOCKER4="$(sudo nft list set inet docker-block docker-banned-ipv4 2>/dev/null \
      | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | wc -l | tr -d '[:space:]')"
    DOCKER6="$(sudo nft list set inet docker-block docker-banned-ipv6 2>/dev/null \
      | grep -oE '([0-9a-fA-F:]+)' | grep -F ':' | wc -l | tr -d '[:space:]')"
  fi

  DOCKER4="${DOCKER4:-0}"
  DOCKER6="${DOCKER6:-0}"

  log_header "SYNC METRICS & VALIDATION REPORT"
  loginfo "Jails IPv4: total=$TOTAL4 (dup=$DUP4, unique=$UNIQUE4)"
  loginfo "Jails IPv6: total=$TOTAL6 (dup=$DUP6, unique=$UNIQUE6)"
  loginfo "Docker-block IPv4 elements: $DOCKER4 (auto-merge may differ from unique IPs)"
  loginfo "Docker-block IPv6 elements: $DOCKER6 (auto-merge may differ from unique IPs)"
  loginfo "Removed (orphaned): IPv4=$REMOVED, IPv6=$REMOVED6"
  echo ""

  # Diff check
  local DIFF4 DIFF6 DIFF4ABS DIFF6ABS
  DIFF4=$((UNIQUE4 - DOCKER4)); DIFF4ABS=${DIFF4#-}
  DIFF6=$((UNIQUE6 - DOCKER6)); DIFF6ABS=${DIFF6#-}

  if [ "$DOCKER4" -eq "$UNIQUE4" ]; then
    logsuccess "✅ IPv4 perfect sync: $UNIQUE4 == $DOCKER4"
  elif [ "$DIFF4ABS" -le 5 ]; then
    loginfo "ℹ️ IPv4 minor difference (±$DIFF4ABS) - normal due to nftables auto-merge"
  else
    logwarn "⚠️ IPv4 significant difference: unique_jails=$UNIQUE4, docker-block=$DOCKER4"
  fi

  if [ "$DOCKER6" -eq "$UNIQUE6" ]; then
    logsuccess "✅ IPv6 perfect sync: $UNIQUE6 == $DOCKER6"
  elif [ "$DIFF6ABS" -le 5 ]; then
    loginfo "ℹ️ IPv6 minor difference (±$DIFF6ABS) - normal due to nftables auto-merge"
  else
    logwarn "⚠️ IPv6 significant difference: unique_jails=$UNIQUE6, docker-block=$DOCKER6"
  fi

  echo ""
  logsuccess "Validation sync completed. Hook handles immediate bans."
}


################################################################################
# F2B DOCKER DASHBOARD (NEW v0.23)
################################################################################

# f2b_docker_dashboard – real-time dashboard pre docker-block + Fail2Ban
f2b_docker_dashboard() {
  while true; do
    clear
    log_header "F2B DOCKER-BLOCK REAL-TIME DASHBOARD v${VERSION}"
    date "+%Y-%m-%d %H:%M:%S"
    echo

    echo "DOCKER-BLOCK STATUS"
    if sudo nft list table inet docker-block >/dev/null 2>&1; then
      log_success "Table ACTIVE"

      local ipv4count ipv6count blockedports
      if jq_check_installed; then
        ipv4count=$(
          sudo nft -j list set inet docker-block docker-banned-ipv4 2>/dev/null \
            | jq -r '.nftables[] | select(.set.elem) | .set.elem | length' 2>/dev/null \
            | head -1
        )
        ipv6count=$(
          sudo nft -j list set inet docker-block docker-banned-ipv6 2>/dev/null \
            | jq -r '.nftables[] | select(.set.elem) | .set.elem | length' 2>/dev/null \
            | head -1
        )
      else
        ipv4count=$(
          sudo nft list set inet docker-block docker-banned-ipv4 2>/dev/null \
            | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' \
            | wc -l | tr -d '[:space:]'
        )
        ipv6count=$(
          sudo nft list set inet docker-block docker-banned-ipv6 2>/dev/null \
            | grep -oE '([0-9a-fA-F:]+)' \
            | grep -F ':' \
            | wc -l | tr -d '[:space:]'
        )
      fi

      ipv4count=${ipv4count:-0}
      ipv6count=${ipv6count:-0}

      blockedports=$(
        sudo nft list set inet docker-block docker-blocked-ports 2>/dev/null \
          | grep -oE '[0-9]+' \
          | sort -un \
          | tr '\n' ' '
      )

      echo "  IPv4 banned : ${ipv4count} IPs"
      echo "  IPv6 banned : ${ipv6count} IPs"
      if [ -n "${blockedports}" ]; then
        echo "  Blocked ports: ${blockedports}"
      fi
    else
      log_error "Table NOT FOUND"
    fi

    echo
    echo "FAIL2BAN STATUS"

    local active_jails=0
    local tmp_all total_unique_v4
    tmp_all=$(mktemp)
    : > "$tmp_all"

    for jail in "${JAILS[@]}"; do
      local count
      count=$(get_f2b_count "${jail}" all | tr -d ' ')
      count=${count:-0}

      if [ "${count}" -gt 0 ]; then
        printf " %-30s %s IPs\n" "${jail}" "${count}"
        active_jails=$((active_jails + 1))

        # Spoľahlivý zdroj IP – rovnaké ako sync/verify
        get_f2b_ips "$jail" 2>/dev/null \
          | grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}$' \
          >> "$tmp_all"
      fi
    done

    if [ "${active_jails}" -eq 0 ]; then
      log_success "All jails clean"
      total_unique_v4=0
    else
      total_unique_v4=$(sort -u "$tmp_all" | wc -l | tr -d ' ')
      echo
      echo "  Active jails : ${active_jails}"
      echo "  Total IPs    : ${total_unique_v4} (unique IPv4)"
    fi

    rm -f "$tmp_all"

    echo
    echo "RECENT ATTACKS (last hour)"
    if [ -f /var/log/fail2ban.log ]; then
      local lasthour since1
      since1="$(date --date='1 hour ago' '+%Y-%m-%d %H:%M:%S')"
      lasthour=$(
        zcat --force /var/log/fail2ban.log /var/log/fail2ban.log.1 2>/dev/null \
          | awk -v since="$since1" '
              substr($0,1,19) >= since && $0 ~ /(BanFound| Found | Ban )/ { c++ }
              END { print c+0 }
            '
      )
      lasthour=${lasthour:-0}
      echo "  Ban/Found events: ${lasthour}"
    else
      echo "  No fail2ban log available"
    fi

    echo
    echo "TOP 5 ATTACKERS"
    if [ -f /var/log/fail2ban.log ]; then
      if ! grep -h "Ban" /var/log/fail2ban.log 2>/dev/null \
          | tail -500 \
          | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' \
          | sort | uniq -c | sort -rn | head -5; then
        echo "  No attack data available"
      fi
    else
      log_error "Fail2Ban log not found"
    fi

    echo
    echo "SYNC STATUS"

    if sudo nft list table inet docker-block >/dev/null 2>&1; then
      local tmpfile f2b_unique ipv4count2 diff diff_abs
      tmpfile=$(mktemp)
      : > "$tmpfile"

      # F2B union unikátnych IPv4 naprieč všetkými jailmi (rovnako ako sync)
      for jail in "${JAILS[@]}"; do
        get_f2b_ips "$jail" 2>/dev/null \
          | grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}$' \
          >> "$tmpfile"
      done
      f2b_unique=$(sort -u "$tmpfile" | wc -l | tr -d ' ')
      rm -f "$tmpfile"

      if jq_check_installed; then
        ipv4count2=$(
          sudo nft -j list set inet docker-block docker-banned-ipv4 2>/dev/null \
            | jq -r '.nftables[] | select(.set.elem) | .set.elem | length' 2>/dev/null \
            | head -1
        )
      else
        ipv4count2=$(
          sudo nft list set inet docker-block docker-banned-ipv4 2>/dev/null \
            | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' \
            | wc -l | tr -d '[:space:]'
        )
      fi
      ipv4count2=${ipv4count2:-0}

      diff=$((f2b_unique - ipv4count2))
      diff_abs=${diff#-}

      echo "  F2B unique IPv4 : ${f2b_unique}"
      echo "  docker-block IPv4: ${ipv4count2}"

      if [ "$f2b_unique" -eq "$ipv4count2" ]; then
        log_success "Fail2Ban ↔ docker-block PERFECT SYNC"
      elif [ "$diff_abs" -le 5 ]; then
        log_success "Minor diff (±5) due to nftables auto-merge (DIFF=${diff})"
      else
        log_warn "Significant DIFF=${diff} – run: sudo f2b docker verify"
      fi
    else
      log_warn "docker-block table not configured"
    fi

    echo
    if sudo crontab -l 2>/dev/null | grep -q "/usr/local/bin/f2b docker sync"; then
      log_success "Auto-sync ACTIVE (cron)"
    else
      log_error "Auto-sync NOT CONFIGURED"
    fi

    echo
    echo "Press Ctrl+C to exit - refresh in 5 seconds..."
    sleep 5
  done
}

f2b_docker_commands() {
  case "${2}" in
    dashboard)
      f2b_docker_dashboard
      ;;
    info)
      f2b_docker_info
      ;;
    sync)
      case "${3:-validate}" in
        full)
          f2b_sync_docker_full
          ;;
        validate|*)
          f2b_sync_docker
          ;;
      esac
      ;;
    verify)
      f2b_docker_verify
      ;;
    *)
      cat << 'EOF'
Usage: f2b docker COMMAND

COMMANDS:
  dashboard              Real-time monitoring dashboard
  info                   Show docker-block configuration
  sync [full|validate]   Synchronize fail2ban ↔ docker-block
                         - full:     Heavy bidirectional sync (ADD+REMOVE)
                         - validate: Light consistency check (REMOVE only)
                         - default:  validate
  verify                 Deep verify of F2B ↔ docker-block sync (IPv4 union)

Examples:
  sudo f2b docker dashboard
  sudo f2b docker sync                    # Default: validate
  sudo f2b docker sync validate           # Explicit validate mode
  sudo f2b docker sync full               # Full reconciliation
  sudo f2b docker verify
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

    local NFT_DOCKER_CONF="/etc/nftables.d/docker-block.nft"

    if [ ! -f "$NFT_DOCKER_CONF" ]; then
        log_error "Config file not found: $NFT_DOCKER_CONF"
        return 1
    fi

    local CURRENT_PORTS
    CURRENT_PORTS=$(sudo nft list set inet docker-block docker-blocked-ports 2>/dev/null \
        | grep -oE '[0-9]+' | sort -un | tr '\n' ',' | sed 's/,$//')

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

    local NFT_DOCKER_CONF="/etc/nftables.d/docker-block.nft"

    if [ ! -f "$NFT_DOCKER_CONF" ]; then
        log_error "Config file not found: $NFT_DOCKER_CONF"
        return 1
    fi

    local CURRENT_PORTS
    CURRENT_PORTS=$(sudo nft list set inet docker-block docker-blocked-ports 2>/dev/null \
        | grep -oE '[0-9]+' | sort -un | tr '\n' ',' | sed 's/,$//')

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
    sudo nft list set inet docker-block docker-blocked-ports 2>/dev/null \
        || log_warn "No blocked ports or docker-block table missing"

    echo ""
}

manage_manual_ban() {
  local ip="$1"
  local timeout="${2:-7d}"

  if [ -z "$ip" ]; then
    logerror "Usage: manage manual-ban IP [timeout]"
    return 1
  fi

  # Validácia IP (wrapper už má validate_ip())
  if ! validate_ip "$ip"; then
    return 1
  fi

  logheader "Banning $ip ($timeout)"

  # 1) Fail2Ban jail: manualblock
  if sudo fail2ban-client set manualblock banip "$ip" >/dev/null 2>&1; then
    logsuccess "Fail2Ban: added to jail 'manualblock'"
  else
    logwarn "Fail2Ban: failed to add IP to jail 'manualblock' (maybe already banned?)"
  fi

  # 2) nftables set: f2b-manualblock
  if sudo nft add element inet fail2ban-filter f2b-manualblock "{ $ip timeout $timeout }" >/dev/null 2>&1; then
    logsuccess "nftables: added to set f2b-manualblock"
  else
    logwarn "nftables: could not add IP to set f2b-manualblock (already present or nft error)"
  fi

  echo
}

manage_manual_unban() {
    local ip
    ip="$1"

    if [ -z "$ip" ]; then
        logerror "Usage: manage manual-unban IP"
        return 1
    fi

    if ! validate_ip "$ip"; then
        return 1
    fi

    logheader "Unbanning $ip"

    local changed=0

    # 1) Fail2Ban jail manualblock
    if sudo fail2ban-client status manualblock 2>/dev/null | grep -Fq "$ip"; then
        if sudo fail2ban-client set manualblock unbanip "$ip" >/dev/null 2>&1; then
            logsuccess "Fail2Ban: removed from jail 'manualblock'"
            changed=1
        else
            logwarn "Fail2Ban: failed to unban IP from jail 'manualblock'"
        fi
    else
        loginfo "Fail2Ban: IP not present in jail 'manualblock'"
    fi

    # 2) nftables set f2b-manualblock
    if sudo nft list set inet fail2ban-filter f2b-manualblock 2>/dev/null | grep -Fq "$ip"; then
        if sudo nft delete element inet fail2ban-filter f2b-manualblock "{ $ip }" >/dev/null 2>&1; then
            logsuccess "nftables: removed from set f2b-manualblock"
            changed=1
        else
            logwarn "nftables: failed to remove IP from set f2b-manualblock"
        fi
    else
        loginfo "nftables: IP not present in set f2b-manualblock"
    fi

    if [ "$changed" -eq 0 ]; then
        logwarn "IP $ip not found in manualblock (Fail2Ban ani nftables)"
    fi

    echo
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

    local found=0
    local unbanned=0

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

    local removed=0

    for jail in "${JAILS[@]}"; do
        local nftset
        nftset="${SETMAP[$jail]}"
        [ -z "$nftset" ] && continue

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
    log_header "docker-block v${DOCKER_BLOCK_VERSION} - Status"
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
        sudo nft list set inet docker-block docker-blocked-ports 2>/dev/null \
            | grep "elements" || echo " (none)"
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
    local active=0
    for jail in "${JAILS[@]}"; do
        local count
        count=$(get_f2b_count "$jail" all | tr -d '[:space:]')
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
            count=$(get_f2b_count "$j" all | tr -d '[:space:]')
            count=${count:-0}

            if [ "$count" -gt 0 ]; then
                echo -e "${YELLOW}$j${NC} ($count IPs):"

                # Zobraz IPs s metadata ak je jq dostupné
                if jq_check_installed; then
                    local nftset
                    nftset="${SETMAP[$j]}"
                    sudo nft --json list set inet fail2ban-filter "$nftset" 2>/dev/null \
                        | jq -r '.nftables[] | select(.set.elem) | .set.elem[] | select(.elem)
                            | "  \(.elem.val), timeout: \(.elem.timeout // "permanent"), expires: \(.elem.expires // "never")"' 2>/dev/null \
                        || get_f2b_ips "$j" | while read -r ip; do echo "  $ip"; done
                else
                    # Fallback bez metadata
                    get_f2b_ips "$j" | while read -r ip; do echo "  $ip"; done
                fi
                echo ""
            fi
        done
    else
        local count
        count=$(get_f2b_count "$jail" all | tr -d '[:space:]')
        count=${count:-0}

        if [ "$count" -gt 0 ]; then
            echo -e "${YELLOW}$jail${NC} ($count IPs):"

            if jq_check_installed; then
                local nftset
                nftset="${SETMAP[$jail]}"
                sudo nft --json list set inet fail2ban-filter "$nftset" 2>/dev/null \
                    | jq -r '.nftables[] | select(.set.elem) | .set.elem[] | select(.elem)
                        | "  \(.elem.val), timeout: \(.elem.timeout // "permanent"), expires: \(.elem.expires // "never")"' 2>/dev/null \
                    || get_f2b_ips "$jail" | while read -r ip; do echo "  $ip"; done
            else
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

    grep -h "Ban" /var/log/fail2ban.log 2>/dev/null \
        | tail -1000 \
        | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' \
        | sort | uniq -c | sort -rn | head -10 > "$temp_file" 2>/dev/null || true

    if [ ! -s "$temp_file" ]; then
        log_info "No attack data available"
        rm -f "$temp_file"
        return 0
    fi

    echo ""

    local rank=1
    while IFS= read -r line; do
        local count
        count=$(echo "$line" | awk '{print $1}')
        local ip
        ip=$(echo "$line" | awk '{print $2}')
        echo -e "${YELLOW}${rank}.${NC} $ip ${RED}(${count} bans)${NC}"
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

        local total=0
        for jail in "${JAILS[@]}"; do
            local count
            count=$(get_f2b_count "$jail" all | tr -d '[:space:]')
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

    grep "\[$jail\]" /var/log/fail2ban.log 2>/dev/null | tail -n "$lines" \
        || log_warn "No logs found for $jail"

    echo ""
}

monitor_trends() {
    log_header "ATTACK TREND ANALYSIS"

    echo ""

    local since1 since6 since24
    local last_hour last_6h last_24h

    since1="$(date --date='1 hour ago'  '+%Y-%m-%d %H:%M:%S')"
    since6="$(date --date='6 hours ago' '+%Y-%m-%d %H:%M:%S')"
    since24="$(date --date='24 hours ago' '+%Y-%m-%d %H:%M:%S')"

    last_hour="$(
        zcat --force /var/log/fail2ban.log /var/log/fail2ban.log.1 2>/dev/null \
          | awk -v since="$since1" '
              substr($0,1,19) >= since && $0 ~ /(Ban|Found|Failed|Invalid)/ {c++}
              END{print c+0}
            '
    )"

    last_6h="$(
        zcat --force /var/log/fail2ban.log /var/log/fail2ban.log.1 2>/dev/null \
          | awk -v since="$since6" '
              substr($0,1,19) >= since && $0 ~ /(Ban|Found|Failed|Invalid)/ {c++}
              END{print c+0}
            '
    )"

    last_24h="$(
        zcat --force /var/log/fail2ban.log /var/log/fail2ban.log.1 2>/dev/null \
          | awk -v since="$since24" '
              substr($0,1,19) >= since && $0 ~ /(Ban|Found|Failed|Invalid)/ {c++}
              END{print c+0}
            '
    )"

    # Sanitize numeric values
    last_hour="$(clean_number "$last_hour")"; [ -z "$last_hour" ] && last_hour=0
    last_6h="$(clean_number "$last_6h")";     [ -z "$last_6h" ] && last_6h=0
    last_24h="$(clean_number "$last_24h")";   [ -z "$last_24h" ] && last_24h=0

    echo -e "Last hour: ${YELLOW}$last_hour${NC} attempts"
    echo -e "Last 6h:   ${YELLOW}$last_6h${NC} attempts"
    echo -e "Last 24h:  ${YELLOW}$last_24h${NC} attempts"
    echo ""

    if [ "$last_hour" -gt 50 ] || [ "$last_6h" -gt 1500 ] || [ "$last_24h" -gt 3000 ]; then
        log_alert "CRITICAL: HIGH ATTACK INTENSITY!"
        echo ""
        log_info "Recommended actions:"
        log_info " • Review logs: f2b monitor jail-log <jail>"
        log_info " • Check top attackers: f2b monitor top-attackers"
        log_info " • Consider enabling stricter rules"
    elif [ "$last_hour" -gt 20 ] || [ "$last_6h" -gt 600 ] || [ "$last_24h" -gt 1500 ]; then
        log_warn "WARNING: Elevated attack activity"
    else
        log_success "Attack levels normal"
    fi

    echo ""
}


################################################################################
# REPORT FUNCTIONS
################################################################################

report_json() {
    log_header "JSON EXPORT"
    local total_bans=0
    local jail_stats=""

    for jail in "${JAILS[@]}"; do
        local count
        count=$(get_f2b_count "$jail" all | tr -d '[:space:]')
        count=${count:-0}
        total_bans=$((total_bans + count))
        jail_stats="${jail_stats} \"${jail}\": ${count},\n"
    done

    jail_stats=$(echo -e "$jail_stats" | sed '$ s/,$//')

    cat << EOF
{
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "version": "${VERSION}",
  "services": {
    "nftables": "$(systemctl is-active nftables 2>/dev/null || echo "unknown")",
    "fail2ban": "$(systemctl is-active fail2ban 2>/dev/null || echo "unknown")",
    "docker_block": "$(sudo nft list table inet docker-block &>/dev/null && echo "active" || echo "inactive")"
  },
  "statistics": {
    "total_bans": ${total_bans},
    "jails": {
$(echo -e "$jail_stats")
    }
  },
  "generated_by": "F2B Wrapper v${VERSION}"
}
EOF

    echo ""
}

report_csv() {
    log_header "CSV EXPORT"
    echo "Timestamp,Jail,Banned_IPs,Status"

    for jail in "${JAILS[@]}"; do
        local count
        count=$(get_f2b_count "$jail" all | tr -d '[:space:]')
        count=${count:-0}
        local status="active"
        [ "$count" -eq 0 ] && status="clean"
        echo "$(date +%Y-%m-%d\ %H:%M:%S),${jail},${count},${status}"
    done

    echo ""
}

report_daily() {
    log_header "DAILY REPORT"
    echo "Generated: $(date '+%Y-%m-%d %H:%M:%S')"
    echo ""

    echo "Services:"
    echo " nftables: $(systemctl is-active nftables 2>/dev/null || echo "unknown")"
    echo " fail2ban: $(systemctl is-active fail2ban 2>/dev/null || echo "unknown")"
    echo ""

    echo "Jail Statistics:"
    local total=0
    for jail in "${JAILS[@]}"; do
        local count
        count=$(get_f2b_count "$jail" all | tr -d '[:space:]')
        count=${count:-0}
        [ "$count" -gt 0 ] && echo " ${jail}: ${count}"
        total=$((total + count))
    done

    echo ""
    echo "Total banned IPs: ${total}"
    echo ""

    echo "Top 5 Attackers:"
    if [ -f /var/log/fail2ban.log ]; then
        grep -h "Ban" /var/log/fail2ban.log 2>/dev/null \
            | tail -500 \
            | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' \
            | sort | uniq -c | sort -rn | head -5 \
            | awk '{print " " $2 " (" $1 " bans)"}'
    else
        echo " (log not available)"
    fi

    echo ""
}

audit_silent() {
    local LOGFILE="/var/log/f2b-audit.log"
    local TOTAL=0

    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Audit started" >> "$LOGFILE"
    for jail in "${JAILS[@]}"; do
        local count
        count=$(get_f2b_count "$jail" all | tr -d '[:space:]')
        count=${count:-0}
        TOTAL=$((TOTAL + count))
        [ "$count" -gt 0 ] && echo " ${jail}: ${count} IPs" >> "$LOGFILE"
    done

    if [ "$TOTAL" -eq 0 ]; then
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] Status: ALL CLEAN" >> "$LOGFILE"
    else
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] Total banned: ${TOTAL}" >> "$LOGFILE"
    fi
}

stats_quick() {
    local total=0
    for jail in "${JAILS[@]}"; do
        local count
        count=$(get_f2b_count "$jail" all | tr -d '[:space:]')
        count=${count:-0}
        total=$((total + count))
    done

    echo "Total: ${total} | nftables: $(systemctl is-active nftables 2>/dev/null) | fail2ban: $(systemctl is-active fail2ban 2>/dev/null)"
}

################################################################################
# ATTACK ANALYSIS FUNCTIONS
################################################################################

analyze_npm_http_status() {
    log_header "NPM HTTP Status Analysis"
    echo ""

    if ! sudo test -f "$NPM_LOG_DIR/proxy-host-1_access.log"; then
        log_warn "No NPM logs found at $NPM_LOG_DIR"
        return 1
    fi

    local ACCESS_LOGS=( "$NPM_LOG_DIR"/*_access.log )

    if [ ! -e "${ACCESS_LOGS[0]}" ]; then
        log_warn "No access logs matched: $NPM_LOG_DIR/*_access.log"
        return 1
    fi

    local _RECENT_LOGS
    _RECENT_LOGS=$(sudo cat "${ACCESS_LOGS[@]}" 2>/dev/null | tail -5000)

    if [ -z "$_RECENT_LOGS" ]; then
        log_warn "No log lines available for analysis"
        return 0
    fi

    local STATUS_400 STATUS_403 STATUS_404 STATUS_444 STATUS_499 STATUS_500
    STATUS_400=$(clean_number "$(echo "$_RECENT_LOGS" | grep -c ' 400 ' 2>/dev/null)")
    STATUS_403=$(clean_number "$(echo "$_RECENT_LOGS" | grep -c ' 403 ' 2>/dev/null)")
    STATUS_404=$(clean_number "$(echo "$_RECENT_LOGS" | grep -c ' 404 ' 2>/dev/null)")
    STATUS_444=$(clean_number "$(echo "$_RECENT_LOGS" | grep -c ' 444 ' 2>/dev/null)")
    STATUS_499=$(clean_number "$(echo "$_RECENT_LOGS" | grep -c ' 499 ' 2>/dev/null)")
    STATUS_500=$(clean_number "$(echo "$_RECENT_LOGS" | grep -c ' 500 ' 2>/dev/null)")

    local TOTAL_ERRORS=$((STATUS_400 + STATUS_403 + STATUS_404 + STATUS_444 + STATUS_499 + STATUS_500))

    local TOTAL_REQUESTS
    TOTAL_REQUESTS=$(echo "$_RECENT_LOGS" | wc -l | tr -d ' ')

    echo " 400 Bad Request:       $STATUS_400 (malformed requests)"
    echo " 403 Forbidden:         $STATUS_403 (blocked by rules)"
    echo " 404 Not Found:         $STATUS_404 (scanner probes)"
    echo " 444 Connection Closed: $STATUS_444 (NPM rejected)"
    echo " 499 Client Closed:     $STATUS_499 (timeout)"
    echo " 500 Internal Error:    $STATUS_500"
    echo " ────────────────────────"
    echo " Total Error Responses: $TOTAL_ERRORS / $TOTAL_REQUESTS requests"
    echo ""

    if [ "$TOTAL_ERRORS" -gt 1000 ]; then
        log_alert "HIGH ERROR RATE - Active attack in progress!"
    elif [ "$TOTAL_ERRORS" -gt 200 ]; then
        log_warn "Elevated error rate - Scanning activity"
    else
        log_success "Normal error rate"
    fi

    echo ""

    # Globálna premenná pre analyze_probed_paths() v tom istom behu (bez exportu!)
    RECENT_LOGS="$_RECENT_LOGS"

    # Export len malé metriky (OK)
    export NPM_TOTAL_ERRORS="$TOTAL_ERRORS"
    export NPM_TOTAL_REQUESTS="$TOTAL_REQUESTS"
    export NPM_STATUS_400="$STATUS_400"
    export NPM_STATUS_403="$STATUS_403"
    export NPM_STATUS_404="$STATUS_404"
    export NPM_STATUS_444="$STATUS_444"
    export NPM_STATUS_499="$STATUS_499"
    export NPM_STATUS_500="$STATUS_500"
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
    # Pozn.: používam [[:space:]] namiesto \s (grep -E). [file:1]
    SQL_INJ=$(clean_number "$(echo "$ALL_LOGS" | grep -iEc 'union|select.*from|sqlmap|%27|%3[dD]|drop[[:space:]]+table|sleep\(|benchmark' 2>/dev/null)")
    PATH_TRAV=$(clean_number "$(echo "$ALL_LOGS" | grep -iEc '\.\./|\.\.\\|%2e%2e|\.\.%2[fF]|%5[cC]|%2fetc|etc/passwd' 2>/dev/null)")
    PHP_EXPLOIT=$(clean_number "$(echo "$ALL_LOGS" | grep -iEc 'wp-login|wp-admin|xmlrpc|phpmyadmin|shell\.php|upload\.php|/admin/' 2>/dev/null)")
    SHELL_RCE=$(clean_number "$(echo "$ALL_LOGS" | grep -iEc 'wget|curl|bash -i|nc -|/dev/tcp|`.*`|\$\([^)]*\)' 2>/dev/null)")
    SCANNER=$(clean_number "$(echo "$ALL_LOGS" | grep -iEc 'nikto|nmap|masscan|nessus|sqlmap|dirbuster|burp|zap|metasploit' 2>/dev/null)")
    GIT_EXPOSE=$(clean_number "$(echo "$ALL_LOGS" | grep -Ec '\.git/|\.git$|\.env|\.config|\.htaccess|\.htpasswd|web\.config' 2>/dev/null)")

    echo " SQL Injection:         $SQL_INJ attempts"
    echo " Path Traversal:        $PATH_TRAV attempts"
    echo " PHP Exploits:          $PHP_EXPLOIT attempts"
    echo " Shell/RCE:             $SHELL_RCE attempts"
    echo " Scanner/Bot:           $SCANNER attempts"
    echo " Git/Config Exposure:   $GIT_EXPOSE attempts"

    TOTAL_NPM_ATTACKS=$((SQL_INJ + PATH_TRAV + PHP_EXPLOIT + SHELL_RCE + SCANNER + GIT_EXPOSE))
    echo " ────────────────────────"
    echo " Total NPM Attacks:     $TOTAL_NPM_ATTACKS"
    echo ""

    export TOTAL_NPM_ATTACKS
}

analyze_probed_paths() {
    log_header "Top 10 Most Probed Paths (404)"
    echo ""

    if [ -z "$RECENT_LOGS" ]; then
        echo "  None"
        echo ""
        return 0
    fi

    echo "$RECENT_LOGS" \
        | awk '($4==404 || $5==404)' \
        | awk -F\" 'NF>=2 {print $2}' \
        | sort | uniq -c | sort -rn | head -10 \
        | awk '{printf "  %5d x %s\n", $1, $2}'

    echo ""
}

# Pomocná: vráti 1 ak je line 404 alebo 444 (tvoj log má status v $4 alebo $5)
_is_404_or_444_line() {
    awk '($4==404 || $5==404 || $4==444 || $5==444){exit 0} {exit 1}'
}

analyze_top_source_ips_444() {
    log_header "Top 10 Source IPs (444, recent ~5k requests)"
    echo ""

    if [ -z "$RECENT_LOGS" ]; then
        echo "  None (no RECENT_LOGS)"
        echo ""
        return 0
    fi

    local out
      out=$(
      echo "$RECENT_LOGS" \
        | awk '($4==444 || $5==444)' \
        | grep -oE '\[Client [0-9]{1,3}(\.[0-9]{1,3}){3}\]' \
        | sed 's/^\[Client //; s/\]$//' \
        | sort | uniq -c | sort -rn | head -10 \
        | awk '{printf "  %5d x %s\n", $1, $2}'
    )


    if [ -n "$out" ]; then
        echo "$out"
    else
        echo "  None"
    fi

    echo ""
}

analyze_top_user_agents_444() {
    log_header "Top 10 User-Agents (444 only, recent logs)"
    echo ""

    if [ -z "$RECENT_LOGS" ]; then
        echo "  None (no RECENT_LOGS)"
        echo ""
        return 0
    fi

    # UA je u teba zvyčajne quoted segment tesne pred posledným quoted "-"
    # Príklad: ...] "cypex.ai/scanning Mozilla/5.0 ... Safari/537.36" "-"
    local out
    out=$(echo "$RECENT_LOGS" \
        | awk '($4==444 || $5==444)' \
        | awk -F\" 'NF>=4 {print $(NF-3)}' \
        | sed 's/^[[:space:]]*//; s/[[:space:]]*$//' \
        | grep -vE '^(|-)$' \
        | awk '{ if (length($0)>120) print substr($0,1,120) "..."; else print }' \
        | sort | uniq -c | sort -rn | head -10 \
        | awk '{printf "  %5d x %s\n", $1, substr($0, index($0,$2))}'
    )

    if [ -n "$out" ]; then
        echo "$out"
    else
        echo "  None"
    fi

    echo ""
}

analyze_top_source_ips_404() {
    log_header "Top 10 Source IPs (404, recent logs)"
    echo ""

    if [ -z "$RECENT_LOGS" ]; then
        echo "  None (no RECENT_LOGS)"
        echo ""
        return 0
    fi

    out=$(
      echo "$RECENT_LOGS" \
        | awk '($4==404 || $5==404)' \
        | grep -oE '\[Client [0-9]{1,3}(\.[0-9]{1,3}){3}\]' \
        | sed 's/^\[Client //; s/\]$//' \
        | sort | uniq -c | sort -rn | head -10 \
        | awk '{printf "  %5d x %s\n", $1, $2}'
    )

    [ -n "$out" ] && echo "$out" || echo "  None"
    echo ""
}

analyze_top_user_agents_suspicious() {
    log_header "Top 10 Scanners by User-Agent (404/444, recent logs)"
    echo ""

    if [ -z "$RECENT_LOGS" ]; then
        echo "  None (no RECENT_LOGS)"
        echo ""
        return 0
    fi

    local out
    out=$(echo "$RECENT_LOGS" \
        | awk '($4==404 || $5==404 || $4==444 || $5==444)' \
        | awk -F\" 'NF>=4 {print $(NF-3)}' \
        | sed 's/^[[:space:]]*//; s/[[:space:]]*$//' \
        | grep -vE '^(|-)$' \
        | awk '{ if (length($0)>120) print substr($0,1,120) "..."; else print }' \
        | sort | uniq -c | sort -rn | head -10 \
        | awk '{printf "  %5d x %s\n", $1, substr($0, index($0,$2))}'
    )

    if [ -n "$out" ]; then
        echo "$out"
    else
        echo "  None"
    fi

    echo ""
}

################################################################################
# SSH ATTACK ANALYSIS FUNCTIONS
################################################################################

analyze_ssh_attacks() {
    log_header "SSH Attack Analysis (Last 24h)"
    echo ""

    if [ ! -f /var/log/fail2ban.log ]; then
        log_warn "fail2ban.log not found"
        return 1
    fi

    local CUTOFF TMP_F2B
    CUTOFF="$(date -d '24 hours ago' '+%Y-%m-%d %H:%M:%S')"
    TMP_F2B="$(mktemp)" || { log_error "mktemp failed"; return 1; }
    zcat --force /var/log/fail2ban.log /var/log/fail2ban.log.1 2>/dev/null \
    | awk -v c="$CUTOFF" 'substr($0,1,19) >= c {print}' > "$TMP_F2B"

    local SSHD_NEW SSHD_EXT SSHD_EVENTS
    local SLOW_NEW SLOW_EXT SLOW_EVENTS

    SSHD_NEW=$(clean_number "$(grep '\[sshd\]' "$TMP_F2B" 2>/dev/null \
        | grep ' Ban ' | grep -vc 'Increase Ban')")
    SSHD_EXT=$(clean_number "$(grep '\[sshd\]' "$TMP_F2B" 2>/dev/null \
        | grep -c 'Increase Ban' || echo 0)")
    SSHD_EVENTS=$((SSHD_NEW + SSHD_EXT))

    SLOW_NEW=$(clean_number "$(grep '\[sshd-slowattack\]' "$TMP_F2B" 2>/dev/null \
        | grep ' Ban ' | grep -vc 'Increase Ban')")
    SLOW_EXT=$(clean_number "$(grep '\[sshd-slowattack\]' "$TMP_F2B" 2>/dev/null \
        | grep -c 'Increase Ban' || echo 0)")
    SLOW_EVENTS=$((SLOW_NEW + SLOW_EXT))

    local TOTAL_SSH_BAN_EVENTS=$((SSHD_EVENTS + SLOW_EVENTS))

    local SSH_ATTEMPTS
    if grep -Eq '\[(sshd|sshd-slowattack)\].*(BanFound| Found )' "$TMP_F2B" 2>/dev/null; then
        SSH_ATTEMPTS=$(clean_number "$(
            grep -E '\[(sshd|sshd-slowattack)\]' "$TMP_F2B" 2>/dev/null \
                | grep -Ec 'BanFound| Found '
        )")
    else
        SSH_ATTEMPTS=$(clean_number "$(
            grep -E '\[(sshd|sshd-slowattack)\]' "$TMP_F2B" 2>/dev/null \
                | grep ' Ban ' | grep -vc 'Increase Ban'
        )")
    fi

    local FAILED_PASS=0 INVALID_USER=0 CONN_ATTEMPTS=0 PREAUTH_FAIL=0
    if [ -f /var/log/auth.log ]; then
      local AUTH_TODAY AUTH_YESTERDAY AUTH_LINES
      AUTH_TODAY=$(date '+%b %d')
      AUTH_YESTERDAY=$(date -d '1 day ago' '+%b %d')

      AUTH_LINES=$(grep -E "^($AUTH_TODAY|$AUTH_YESTERDAY)" /var/log/auth.log 2>/dev/null || echo "")

      FAILED_PASS=$(clean_number "$(echo "$AUTH_LINES" | grep -c "Failed password" || echo 0)")
      INVALID_USER=$(clean_number "$(echo "$AUTH_LINES" | grep -c "Invalid user" || echo 0)")
      CONN_ATTEMPTS=$(clean_number "$(echo "$AUTH_LINES" | grep -c "Connection from" || echo 0)")
      PREAUTH_FAIL=$(clean_number "$(echo "$AUTH_LINES" | grep -c "Disconnected from authenticating user" || echo 0)")
    fi

    printf " %-20s %d attempts\n" "Failed Passwords:" "$FAILED_PASS"
    printf " %-20s %d attempts\n" "Invalid Users:"    "$INVALID_USER"
    printf " %-20s %d\n"           "Connection Attempts:" "$CONN_ATTEMPTS"
    printf " %-20s %d\n"           "Preauth Failures:"   "$PREAUTH_FAIL"
    echo " ────────────────────────"

    printf " %-20s %d\n" "SSH Attempts (24h):" "$SSH_ATTEMPTS"
    printf " %-20s %d (new: %d, extensions: %d)\n" "SSHD Ban events:" "$SSHD_EVENTS" "$SSHD_NEW" "$SSHD_EXT"
    printf " %-20s %d (new: %d, extensions: %d)\n" "Slow Ban events:" "$SLOW_EVENTS" "$SLOW_NEW" "$SLOW_EXT"
    printf " %-20s %d\n" "Total Ban events:" "$TOTAL_SSH_BAN_EVENTS"
    echo ""

    if [ "$TOTAL_SSH_BAN_EVENTS" -gt 0 ]; then
        echo " Recent SSH ban activity:"
        grep -E '\[(sshd|sshd-slowattack)\]' "$TMP_F2B" 2>/dev/null \
            | grep ' Ban ' | grep -v 'Increase Ban' | tail -5 \
            | while IFS= read -r line; do
                local timestamp ip
                timestamp=$(echo "$line" | awk '{print $1, $2}' | cut -d',' -f1)
                ip=$(echo "$line" \
                | awk '{for(i=1;i<=NF;i++) if($i=="Ban"){ip=$(i+1); sub(/[.,]$/,"",ip); print ip; break}}')
                [ -n "$ip" ] && printf "  %s → %s\n" "$timestamp" "$ip"
            done
        echo ""
    fi

    cleanup_tmp "$TMP_F2B"

    export TOTAL_SSH_ATTACKS="$SSH_ATTEMPTS"
    export SSH_BAN_EVENTS="$TOTAL_SSH_BAN_EVENTS"
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
    TMP_F2B="$(mktemp)" || { log_error "mktemp failed"; return 1; }

    # 24h window, rotácia-safe
    zcat --force /var/log/fail2ban.log /var/log/fail2ban.log.1 2>/dev/null \
      | awk -v c="$CUTOFF" 'substr($0,1,19) >= c {print}' > "$TMP_F2B"

    # Vyber len SSH jaily (sshd + sshd-slowattack) a vytiahni IP (IPv4 alebo IPv6)
# Prefer attempt markers; fallback to Ban (new only)
local IP_STREAM
if grep -Eq '\[(sshd|sshd-slowattack)\].*(BanFound| Found )' "$TMP_F2B" 2>/dev/null; then
    IP_STREAM="$(
        grep -E '\[(sshd|sshd-slowattack)\]' "$TMP_F2B" 2>/dev/null \
          | grep -E 'BanFound| Found ' \
          | awk '
              {
                for (i=1; i<=NF; i++) {
                  if ($i=="BanFound" || $i=="Found") {
                    ip=$(i+1)
                    sub(/[.,]$/, "", ip)   # fail2ban log často dáva bodku za IP
                    print ip
                    break
                  }
                }
              }'
    )"
else
    IP_STREAM="$(
        grep -E '\[(sshd|sshd-slowattack)\]' "$TMP_F2B" 2>/dev/null \
          | grep ' Ban ' | grep -v 'Increase Ban' \
          | awk '
              {
                for (i=1; i<=NF; i++) {
                  if ($i=="Ban") {
                    ip=$(i+1)
                    sub(/[.,]$/, "", ip)
                    print ip
                    break
                  }
                }
              }'
    )"
fi

    if [ -z "$IP_STREAM" ]; then
        echo "  No attacks detected"
        cleanup_tmp "$TMP_F2B"
        echo ""
        return 0
    fi
    # dočasný debug – TERAZ VYHODIŤ
    # echo "$IP_STREAM" | head -20 >&2
    echo "$IP_STREAM" | sort | uniq -c | sort -rn | head -10 | \
    while read -r count ip; do
        local BANNED="(unbanned)"

        # Fail2Ban (sshd, sshd-slowattack) – get banned <IP> → 1/0
        if sudo fail2ban-client get sshd banned "$ip" 2>/dev/null | grep -qx "1" \
           || sudo fail2ban-client get sshd-slowattack banned "$ip" 2>/dev/null | grep -qx "1"; then
            BANNED="F2B-BANNED"
        fi

        # nftables fail2ban-filter (v4 + v6)
        if sudo nft get element inet fail2ban-filter f2b-sshd "{ $ip }" &>/dev/null 2>&1 \
           || sudo nft get element inet fail2ban-filter f2b-sshd-v6 "{ $ip }" &>/dev/null 2>&1; then
            BANNED="NFT-BLOCKED"
        fi

        # docker-block (v4 + v6)
        if sudo nft get element inet docker-block docker-banned-ipv4 "{ $ip }" &>/dev/null 2>&1 \
           || sudo nft get element inet docker-block docker-banned-ipv6 "{ $ip }" &>/dev/null 2>&1; then
            BANNED="DOCKER-BLOCKED"
        fi

        printf "  %-39s %6d attempts  %s\n" "$ip" "$count" "$BANNED"
    done

    cleanup_tmp "$TMP_F2B"
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

    # Get Fail2Ban banned count
    local TOTAL_BANNED=0
    local count
    for jail in $(sudo fail2ban-client status 2>/dev/null | grep "Jail list" | sed 's/.*://;s/,//g'); do
        count=$(sudo fail2ban-client status "$jail" 2>/dev/null | grep "Currently banned" | awk '{print $4}')
        if [ -n "$count" ]; then
            TOTAL_BANNED=$((TOTAL_BANNED + count))
        fi
    done
    TOTAL_BANNED="$(clean_number "$TOTAL_BANNED")"

    # Get Docker-block count
    local DOCKER_BLOCKED
    if jq_check_installed; then
        DOCKER_BLOCKED="$(clean_number "$(
            sudo nft -j list set inet docker-block docker-banned-ipv4 2>/dev/null \
                | jq -r '.nftables[] | select(.set.elem) | .set.elem | length' 2>/dev/null \
                | head -1
        )")"
    else
        DOCKER_BLOCKED="$(
            sudo nft list set inet docker-block docker-banned-ipv4 2>/dev/null \
                | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' \
                | wc -l
        )"
        DOCKER_BLOCKED="$(clean_number "$DOCKER_BLOCKED")"
    fi

    # Get attack detections (fallback if export failed)
    local NPM_DETECTED="${TOTAL_NPM_ATTACKS:-0}"
    local SSH_DETECTED="${TOTAL_SSH_ATTACKS:-0}"

    # Get total attempts from fail2ban logs (real last-24h window, incl. rotated)
    local since
    local TOTAL_ATTEMPTS_RAW
    local TOTAL_ATTEMPTS

    since="$(date --date='24 hours ago' '+%Y-%m-%d %H:%M:%S')"

    TOTAL_ATTEMPTS_RAW="$(
        zcat --force /var/log/fail2ban.log /var/log/fail2ban.log.1 2>/dev/null \
            | awk -v since="$since" '
                substr($0,1,19) >= since && $0 ~ /(Ban|Found|Failed|Invalid)/ { c++ }
                END { print c+0 }
            '
    )"

    TOTAL_ATTEMPTS="$(clean_number "$TOTAL_ATTEMPTS_RAW")"
    [ -z "$TOTAL_ATTEMPTS" ] && TOTAL_ATTEMPTS=0


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

    # Risk assessment (aligned more with timeline)
    if [ "$TOTAL_ATTEMPTS" -gt 3000 ]; then
        log_alert "⚠️  CRITICAL - Very high attack activity"
        echo ""
        echo "Recommendations:"
        echo "  • Monitor: sudo f2b monitor watch"
        echo "  • Review: sudo f2b monitor top-attackers"
        echo "  • Check: sudo f2b docker dashboard"
    elif [ "$TOTAL_ATTEMPTS" -gt 1500 ]; then
        log_warn "⚠️  WARNING - Elevated attack activity"
        echo ""
        echo "Recommendations:"
        echo "  • Review: sudo f2b monitor trends"
        echo "  • Check: sudo f2b monitor top-attackers"
    elif [ "$TOTAL_ATTEMPTS" -gt 500 ]; then
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
    > "$TEMP_DATA"  # Clear/create file

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
        analyze_top_user_agents_suspicious
        analyze_top_source_ips_404
        analyze_top_source_ips_444
        analyze_top_user_agents_444
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
  echo

  if [ ! -f /var/log/fail2ban.log ]; then
    log_warn "Fail2Ban log not found"
    return 1
  fi

  echo "Metric: fail2ban.filter ' Found ' events (all attack attempts, including non-banned)"
  echo

  local -a hours
  local -a counts
  local max_count=0
  local total_count=0

  local TMP_F2B since24
  TMP_F2B="$(mktemp)" || { log_error "mktemp failed"; return 1; }
  since24="$(date --date='24 hours ago' '+%Y-%m-%d %H:%M:%S')"

  # Vyrež posledných 24h (rotácia-safe)
  zcat --force /var/log/fail2ban.log /var/log/fail2ban.log.1 2>/dev/null \
    | awk -v s="$since24" 'substr($0,1,19) >= s {print}' > "$TMP_F2B"

  # Nazbieraj po hodinách (23h ago .. 0h ago)
  for i in {23..0}; do
    local hour_start hour_end attempts_count
    hour_start="$(date -d "$i hours ago" '+%Y-%m-%d %H:00:00')"
    hour_end="$(date -d "$i hours ago" '+%Y-%m-%d %H:59:59')"

    attempts_count="$(
      awk -v s="$hour_start" -v e="$hour_end" '
        substr($0,1,19) >= s &&
        substr($0,1,19) <= e &&
        $0 ~ /fail2ban.filter/ &&
        $0 ~ / Found / { c++ }
        END { print c+0 }
      ' "$TMP_F2B"
    )"
    attempts_count="$(clean_number "${attempts_count:-0}")"

    hours+=( "$(date -d "$i hours ago" '+%H:00')" )
    counts+=( "$attempts_count" )

    total_count=$((total_count + attempts_count))
    [ "$attempts_count" -gt "$max_count" ] && max_count=$attempts_count
  done

  cleanup_tmp "$TMP_F2B"

  local avg_count=$((total_count / 24))
  local bar_width=30

  # --- DISPLAY: 2-hodinové bloky (12 riadkov), stále pokrýva 24h ---
  # max pre 2h bloky (škálovanie barov)
  local max_block=0
  local i idx block_count
  for i in $(seq 23 -2 1); do
    idx=$((23 - i))
    block_count=$(( ${counts[$idx]:-0} + ${counts[$((idx+1))]:-0} ))
    block_count="$(clean_number "${block_count:-0}")"
    [ "$block_count" -gt "$max_block" ] && max_block="$block_count"
  done

  for i in $(seq 23 -2 1); do
    idx=$((23 - i))

    # Label pre 2h okno
    local h_start h_end hour_range
    h_start="$(date -d "$i hours ago" '+%H:00')"
    h_end="$(date -d "$((i-1)) hours ago" '+%H:59')"
    hour_range="${h_start}-${h_end}"

    # 2h suma + avg/h (pre level prahy)
    local count2h count_avg
    count2h=$(( ${counts[$idx]:-0} + ${counts[$((idx+1))]:-0} ))
    count2h="$(clean_number "${count2h:-0}")"
    count_avg=$((count2h / 2))

    local bar_length=0
    if [ "$max_block" -gt 0 ]; then
      bar_length=$((count2h * bar_width / max_block))
    fi

    local bar=""
    local j
    for ((j=0; j<bar_width; j++)); do
      if [ "$j" -lt "$bar_length" ]; then
        bar+="█"
      else
        bar+="░"
      fi
    done

    local level="LOW"
    if [ "$count_avg" -gt 200 ]; then
      level="CRITICAL"
    elif [ "$count_avg" -gt 100 ]; then
      level="HIGH"
    elif [ "$count_avg" -gt 20 ]; then
      level="MODERATE"
    fi

    printf "%s  │ %s  %4s events/2h (%3s/h)  %-10s\n" "$hour_range" "$bar" "$count2h" "$count_avg" "$level"
  done

  echo
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  printf "Total 24h: %s attempts  |  Average: %s/h  |  Peak: %s/h\n" "$total_count" "$avg_count" "$max_count"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo

  if [ "$max_count" -gt 200 ]; then
    log_alert "⚠️  CRITICAL WAVE - Peak attack intensity detected!"
  elif [ "$max_count" -gt 100 ]; then
    log_warn "HIGH ACTIVITY - Significant attack waves detected"
  elif [ "$total_count" -gt 1000 ]; then
    log_info "SUSTAINED ACTIVITY - Continuous attack pattern"
  else
    log_success "NORMAL ACTIVITY - Low attack volume"
  fi

  echo
  echo "Recommendations:"
  echo "  • Monitor in real-time: sudo f2b monitor watch"
  echo "  • Review attackers: sudo f2b monitor top-attackers"
  echo "  • Check dashboard: sudo f2b docker dashboard"
}

################################################################################
# HELP
################################################################################

show_help() {
    cat << 'EOF'

═══════════════════════════════════════════════════════════════════
F2B UNIFIED WRAPPER v0.31
Fail2Ban + nftables Complete Management
═══════════════════════════════════════════════════════════════════

USAGE: f2b [args]

CORE:
  status                      Show comprehensive status
  audit                       Audit all jails
  find <IP>                   Find IP in jails
  version [--json|--short]    Show version info
  version --json              Machine-readable JSON
  version --short             Short version string
  alert-now <min> #optional   number of bans in last X minutes (default 5)

SYNC:
  sync check                  Verify F2B ↔ nftables sync
  sync enhanced               Enhanced bidirectional sync
  sync force                  Force sync + verify
  sync silent                 Silent sync (for cron)
  sync docker                 Docker-block sync full # Full reconciliation

DOCKER:
  docker COMMAND              Docker only related commands
  docker dashboard            Real-time monitoring dashboard
  docker info                 Show docker-block configuration
  docker sync                    # Default: validate
  docker sync validate           # Explicit validate mode
  docker sync full               # Full reconciliation
  docker verify               Deep verify of F2B ↔ docker-block sync (IPv4 union)

MANAGE - PORT BLOCKING:
  manage block-port <port>           Block Docker port
  manage unblock-port <port>         Unblock port
  manage list-blocked-ports          List blocked ports

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
  report timeline                    Attack wave timeline (24h)
  report attack-analysis [--npm-only|--ssh-only]
                                     Complete attack analysis

SILENT (for cron):
  audit-silent                       Silent audit
  stats-quick                        Quick stats

EXAMPLES:
  sudo f2b status
  sudo f2b audit
  sudo f2b find 1.2.3.4
  sudo f2b sync force
  sudo f2b docker dashboard
  sudo f2b docker sync
  sudo f2b manage block-port 8081
  sudo f2b manage manual-ban 192.0.2.1 30d
  sudo f2b monitor trends
  sudo f2b monitor jail-log sshd 50
  sudo f2b report json > /tmp/f2b-report.json
  sudo f2b monitor watch
  sudo f2b report attack-analysis
  sudo f2b report timeline

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
        alert-now)
            # optional: minutes param
            f2b_alert_now "${2:-5}"
            ;;

        # Sync commands
        sync)
            case "$2" in
                check)    f2b_sync_check ;;
                enhanced) f2b_sync_enhanced ;;
                force)    f2b_sync_force ;;
                silent)   sync_silent ;;
                docker)   f2b_sync_docker_full ;;
                *)        show_help ;;
            esac
            ;;

        # Docker commands (rozšírené)
        docker)
            f2b_docker_commands "$@"
            ;;

        # Manage commands
        manage)
            case "$2" in
                block-port)        manage_block_port "$3" ;;
                unblock-port)      manage_unblock_port "$3" ;;
                list-blocked-ports) manage_list_blocked_ports ;;
                docker-info)       f2b_docker_info ;;
                manual-ban)        manage_manual_ban "$3" "$4" ;;
                manual-unban)      manage_manual_unban "$3" ;;
                unban-all)         manage_unban_all "$3" ;;
                reload)            manage_reload ;;
                backup)            manage_backup ;;
                *)                 show_help ;;
            esac
            ;;

        # Monitor commands
        monitor)
            case "$2" in
                status)        monitor_status ;;
                show-bans)     monitor_show_bans "$3" ;;
                top-attackers) monitor_top_attackers ;;
                watch)         monitor_watch ;;
                jail-log)      monitor_jail_log "$3" "$4" ;;
                trends)        monitor_trends ;;
                *)             show_help ;;
            esac
            ;;

        # Report commands
    report)
        acquire_lock  # lock aj pre reporty
        case "$2" in
            json)            report_json ;;
            csv)             report_csv ;;
            daily)           report_daily ;;
            attack-analysis)
                case "$3" in
                    --npm-only) report_attack_analysis "npm-only" ;;
                    --ssh-only) report_attack_analysis "ssh-only" ;;
                    *)          report_attack_analysis "all" ;;
                esac
                ;;
            timeline)
                report_attack_timeline
                ;;
            *)
                release_lock
                show_help
                return 1
                ;;
        esac
        release_lock
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


