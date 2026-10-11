#!/usr/bin/env bash
################################################################################
# Component: f2b-docker-hook.sh
# Part of: Fail2Ban Hybrid Nftables Manager
#
# Release:  v0.34-dev
# Version:  v0.34-dev
# Date:     2026-10-08
#
# Fail2Ban → docker-block immediate ban/unban helper
# Called from: /etc/fail2ban/action.d/docker-sync-hook.conf
#   actionban   = /usr/local/sbin/f2b-docker-hook ban <ip> <name> <bantime>
#   actionunban = /usr/local/sbin/f2b-docker-hook unban <ip> <name> <bantime>
#
# Function:
#   - On ban:   add IP to inet docker-block docker-banned-ipv4/ipv6 with timeout == bantime
#   - On unban: remove IP from corresponding docker-banned-ipv4/ipv6 set
#   - Log each event to /var/log/f2b-docker-sync.log (JAIL, IP, set, timeout)
################################################################################

set -euo pipefail

MODE="${1:-}"
IP="${2:-}"
JAIL="${3:-unknown}"
BANTIME_RAW="${4:-3600}"

LOGFILE="/var/log/f2b-docker-sync.log"

# Fail2Ban zvyčajne posiela bantime už ako sekundy; ak nie je číslo, fallback
if [[ "$BANTIME_RAW" == -1 ]]; then
  TIMEOUT="permanent (renewable 30d lease)"
elif [[ "$BANTIME_RAW" =~ ^[0-9]+$ ]]; then
  TIMEOUT="${BANTIME_RAW}s"
else
  echo "Invalid bantime: $BANTIME_RAW" >&2
  exit 2
fi

# Detect IP family
if [[ "$IP" == *:* ]]; then
  SETNAME="docker-banned-ipv6"
else
  SETNAME="docker-banned-ipv4"
fi

ts() { date -Is; }  # bez % -> jednoduché, stabilné

log_line() {
  echo "$(ts) [$JAIL] $1 $IP ($SETNAME) timeout=$TIMEOUT" >> "$LOGFILE" || true
}

# Ensure logfile exists
touch "$LOGFILE" 2>/dev/null || true

case "$MODE" in
  ban)
    # Extend a shared ban to the longest expiry; -1 means permanent, maintained
    # as a renewable lease. Failures propagate to Fail2Ban instead of vanishing.
    /usr/bin/python3 /usr/local/sbin/f2b-ipv6-sync.py hook-ban "$IP" "$BANTIME_RAW"
    log_line "HOOK-BAN"
    ;;
  unban)
    # Keep a shared IPv6 ban until the runtime union has been checked.
    # Do not query Fail2Ban here: this hook runs inside its action worker.
    log_line "HOOK-UNBAN-DEFERRED"
    ;;
  *)
    echo "Usage: $0 {ban|unban} <ip> <jail> [bantime]" >&2
    exit 2
    ;;
esac
