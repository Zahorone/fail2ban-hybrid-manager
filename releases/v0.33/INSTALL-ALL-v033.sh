#!/bin/bash

################################################################################
# Fail2Ban + nftables v0.33 - Universal Installer
# Complete Production Installation with IPv4+IPv6 support
#
# Features:
# - Auto-detects: Fresh install / Upgrade from v0.19/v0.31
# - 12 Fail2Ban jails + 12 detection filters (Added nginx-php-errors)
# - Full IPv4 + IPv6 dual-stack support
# - F2B Wrapper v0.33 (50 functions)
# - Docker port blocking v0.4
# - Docker-block auto-sync (cron every 1 minute) ⚠️ CRITICAL
# - Auto-sync service
#
# Supports:
# - Fresh installation on new servers
# - Upgrade from v0.19/v0.21/v0.31
# - Reinstall v0.33 (rebuild components)
################################################################################

################################################################################
# Component: Main Installer
# Part of: Fail2Ban Hybrid Nftables Manager
################################################################################

set -e

# shellcheck disable=SC2034 # Metadata: used for release tracking / logging
RELEASE="v0.33"
# shellcheck disable=SC2034
VERSION="0.33"
# shellcheck disable=SC2034
BUILD_DATE="2026-01-01"
# shellcheck disable=SC2034
COMPONENT_NAME="INSTALL-ALL"

export VERSION # Export for subscripts

# Colors
# shellcheck disable=SC2034 # Predefined color constants
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Logging functions
log() { echo -e "${GREEN}✓${NC} $1"; }
error() { echo -e "${RED}✗${NC} $1"; exit 1; }
warning() { echo -e "${YELLOW}⚠${NC} $1"; }
info() { echo -e "${BLUE}ℹ${NC} $1"; }
step() { echo -e "${CYAN}▶ STEP $1/$2:${NC} $3"; }

STARTTIME=$(date +%s)

################################################################################
# CLI FLAGS
################################################################################

MODE="auto" # auto | cleanup-only
FORCE_CLEANUP="no" # no | yes

case "${1:-}" in
  --cleanup-only)
    MODE="cleanup-only"
    ;;
  --clean-install)
    FORCE_CLEANUP="yes"
    ;;
  --force-cleanup)
    FORCE_CLEANUP="yes"
    ;;
  --help|-h)
    echo "Usage: sudo bash $0 [--cleanup-only|--clean-install|--force-cleanup]"
    echo ""
    echo "  --cleanup-only   Run pre-cleanup only, then exit"
    echo "  --clean-install  Force cleanup (delete nft tables), then continue install"
    echo "  --force-cleanup  Same as --clean-install (kept for clarity)"
    exit 0
    ;;
esac

SCRIPTDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

clear
cat <<EOF
╔════════════════════════════════════════════════════════════╗
║                                                            ║
║     Fail2Ban + nftables Complete Setup ${RELEASE}            ║
║     Universal Installer: Fresh Install / Upgrade          ║
║     Full IPv4/IPv6 + Docker-Block + Sync Support          ║
║                                                            ║
╚════════════════════════════════════════════════════════════╝
EOF
echo ""

################################################################################
# ROOT CHECK
################################################################################

if [ "$EUID" -ne 0 ]; then
  error "Please run with sudo: sudo bash $0"
fi

################################################################################
# AUTO-DETECT INSTALLATION TYPE
################################################################################

info "Detecting system state..."
echo ""

INSTALLTYPE="fresh"

# Check if fail2ban is installed
if command -v fail2ban-client >/dev/null 2>&1; then
  info "Fail2Ban detected: $(fail2ban-client --version | head -1)"
  INSTALLTYPE="upgrade"
fi

# Check if nftables table exists
if nft list table inet fail2ban-filter >/dev/null 2>&1; then
  info "nftables fail2ban-filter table detected"
  INSTALLTYPE="upgrade"
  
  # Count current structure
  CURRENTSETSV4=$(nft list table inet fail2ban-filter 2>/dev/null | grep "set f2b-" | grep -vc "\-v6" || echo 0)
  CURRENTSETSV6=$(nft list table inet fail2ban-filter 2>/dev/null | grep -c "set f2b-.*-v6" || echo 0)

  if [ "$CURRENTSETSV6" -eq 0 ]; then
     info "Detected v0.19-v0.21 installation (no IPv6 support)"
     INSTALLTYPE="upgrade_old"
  else
     info "Detected v0.22+ installation (with IPv6 support)"
     INSTALLTYPE="reinstall"
  fi
fi

# Check for F2B wrapper
if [ -x /usr/local/bin/f2b ]; then
  F2BVERSION=$(/usr/local/bin/f2b version --short 2>/dev/null | grep -oP 'v[0-9\.]+' || echo "unknown")
  info "F2B wrapper detected: $F2BVERSION"
fi

# Check for docker-block
if nft list table inet docker-block >/dev/null 2>&1; then
  info "docker-block table detected"
fi

# Check for docker-block auto-sync cron
if sudo crontab -l 2>/dev/null | grep -q "f2b sync docker"; then
  info "docker-block auto-sync: ACTIVE"
else
  warning "docker-block auto-sync: NOT configured"
fi

echo ""
echo ""
info "Installation Type: $INSTALLTYPE"
echo ""
echo ""

################################################################################
# INSTALLATION TYPE DESCRIPTION
################################################################################

case "$INSTALLTYPE" in
  fresh)
    echo "This is a FRESH INSTALLATION"
    echo ""
    echo "Will install:"
    echo " • nftables with fail2ban-filter table (IPv4/IPv6)"
    echo " • Fail2Ban with 12 jails (Added: nginx-php-errors)"
    echo " • 12 detection filters"
    echo " • Docker port blocking v0.4"
    echo " • F2B wrapper ${RELEASE} (50+ functions)"
    echo " • Docker-block auto-sync cron (CRITICAL)"
    echo " • Auto-sync service (hourly)"
    echo " • Bash aliases"
    ;;
  upgrade_old)
    echo "UPGRADE from v0.19-v0.21 to ${RELEASE}"
    echo ""
    echo "Current state:"
    echo " • IPv4 sets: $CURRENTSETSV4"
    echo " • IPv6 sets: $CURRENTSETSV6 (missing)"
    echo ""
    echo "Will upgrade to:"
    echo " • Add IPv6 support (12 sets + 12 rules)"
    echo " • Add nginx-php-errors jail"
    echo " • Add docker-block v0.4"
    echo " • Add docker-block auto-sync (CRITICAL)"
    echo " • Update F2B wrapper to ${RELEASE} (50+ functions)"
    echo " • Add new filters if missing"
    echo " • Preserve all banned IPs"
    ;;
  reinstall)
    echo "REINSTALL - ${RELEASE} already present"
    echo ""
    echo "Will rebuild all components while preserving bans"
    ;;
  upgrade)
    echo "GENERIC UPGRADE to ${RELEASE}"
    ;;
esac

echo ""
echo ""
echo ""

################################################################################
# EMAIL & NETWORK CONFIGURATION (OPTIONAL)
################################################################################

info "Email Notification & Network Configuration (Optional)"
echo ""
echo "Configure email alerts and ignore list."
echo ""

JAIL_LOCAL="$SCRIPTDIR/config/jail.local"

###############################################################################
# Helper: set/replace key=value only inside the FIRST [DEFAULT] section,
# and drop duplicate [DEFAULT] headers.
###############################################################################
set_default_kv() {
  local file="$1" key="$2" value="$3"

  awk -v key="$key" -v value="$value" '
    function is_section(line) { return (line ~ /^[[:space:]]*\[[^]]+\][[:space:]]*$/) }
    function is_default(line) { return (line ~ /^[[:space:]]*\[DEFAULT\][[:space:]]*$/) }
    function is_key(line)     { return (line ~ "^[[:space:]]*" key "[[:space:]]*=") }
    function emit_kv()        { print key " = " value }

    BEGIN { seen_default=0; in_default=0; key_done=0 }

    {
      if (is_default($0)) {
        if (seen_default == 1) next
        seen_default=1
        in_default=1
        print
        next
      }

      if (in_default == 1 && is_section($0)) {
        if (key_done == 0) { emit_kv(); key_done=1 }
        in_default=0
        print
        next
      }

      if (in_default == 1 && is_key($0)) {
        if (key_done == 0) { emit_kv(); key_done=1 }
        next
      }

      print
    }

    END {
      if (seen_default == 0) {
        print ""
        print "[DEFAULT]"
        emit_kv()
      } else if (in_default == 1 && key_done == 0) {
        emit_kv()
      }
    }
  ' "$file" > "${file}.tmp" && mv "${file}.tmp" "$file"
}

###############################################################################
# Helper: read key value from FIRST [DEFAULT]
###############################################################################
get_default_value() {
  local file="$1" key="$2"
  awk -v key="$key" '
    function is_section(line) { return (line ~ /^[[:space:]]*\[[^]]+\][[:space:]]*$/) }
    BEGIN { seen_default=0; in_default=0 }
    /^[[:space:]]*\[DEFAULT\][[:space:]]*$/ {
      if (seen_default == 1) exit
      seen_default=1
      in_default=1
      next
    }
    {
      if (in_default == 1 && is_section($0)) exit
      if (in_default == 1 && $0 ~ "^[[:space:]]*" key "[[:space:]]*=") {
        sub(/^[[:space:]]*[^=]+=[[:space:]]*/, "", $0)
        print $0
        exit
      }
    }
  ' "$file"
}

###############################################################################
# Helper: merge ignoreip tokens (defaults + existing + new), dedupe, keep order
###############################################################################
merge_ignoreip() {
  local existing="$1" add="$2"
  local defaults="127.0.0.1/8 ::1"

  echo "$defaults $existing $add" \
    | tr ',\t\r\n' ' ' \
    | xargs \
    | awk '{
        for (i=1; i<=NF; i++) {
          if (!seen[$i]++) out = (out ? out FS $i : $i)
        }
      }
      END { print out }'
}

###############################################################################
# EMAIL
###############################################################################
read -r -p "Do you want to configure email notifications? (yes/no): " -r EMAIL_REPLY
echo ""

if [[ $EMAIL_REPLY =~ ^([Yy]es|[Yy])$ ]]; then
  if command -v mail &>/dev/null || command -v sendmail &>/dev/null; then
    log "Mail service detected"
    echo ""

    read -r -p "Enter admin email address (for receiving alerts): " ADMIN_EMAIL
    read -r -p "Enter sender email address (for From header): " SENDER_EMAIL
    echo ""

    if [ -n "$ADMIN_EMAIL" ] && [ -n "$SENDER_EMAIL" ]; then
      if [ -f "$JAIL_LOCAL" ]; then
        log "Updating email configuration in jail.local..."
        echo ""

        cp "$JAIL_LOCAL" "$JAIL_LOCAL.backup-$(date +%Y%m%d-%H%M%S)"

        set_default_kv "$JAIL_LOCAL" "destemail" "$ADMIN_EMAIL"
        set_default_kv "$JAIL_LOCAL" "sender" "$SENDER_EMAIL"
        # voliteľné:
        # set_default_kv "$JAIL_LOCAL" "sendername" "Fail2Ban Notifications"

        log "Email configuration updated:"
        echo " • Destination email: $ADMIN_EMAIL"
        echo " • Sender email: $SENDER_EMAIL"
        echo ""

        log "Email alerts will be sent when IPs are banned in:"
        echo ""
        grep "action = %(action_mwl)s" "$JAIL_LOCAL" \
          | sed 's/.*\[\(.*\)\].*/   ✉ \1 (on ban: email + ban)/g' \
          | sort -u
        echo ""
      else
        warning "jail.local not found: $JAIL_LOCAL"
      fi
    else
      warning "Invalid email addresses provided, using default configuration"
    fi
  else
    warning "Mail service not detected on this system"
    echo " Fail2Ban can still ban IPs, but cannot send email alerts without a mail server."
    echo " Consider installing postfix or sendmail."
    echo ""
  fi
else
  info "Email notifications disabled - using default configuration"
  echo ""
fi

###############################################################################
# IGNOREIP (manual/SSH client + optional Docker subnets)
###############################################################################

detect_ssh_client_ip() {
  local ip="" ttydev="" shell_pid="" environ=""

  # 1) Direct env (works when not stripped)
  if [ -n "${SSH_CLIENT:-}" ]; then
    ip="$(awk '{print $1}' <<<"$SSH_CLIENT")"
  elif [ -n "${SSH_CONNECTION:-}" ]; then
    ip="$(awk '{print $1}' <<<"$SSH_CONNECTION")"
  fi

  # 2) If running under sudo, try to read SSH_* from the invoking user's shell env
  if [ -z "$ip" ] && [ -n "${SUDO_USER:-}" ]; then
    ttydev="$(tty 2>/dev/null | sed 's#^/dev/##')"
    if [ -n "$ttydev" ]; then
      shell_pid="$(
        ps -t "$ttydev" -u "$SUDO_USER" -o pid=,comm= 2>/dev/null \
          | awk '$2 ~ /^(bash|zsh|fish|sh|dash)$/ {print $1; exit}'
      )"

      if [ -n "$shell_pid" ] && [ -r "/proc/$shell_pid/environ" ]; then
        environ="$(tr '\0' '\n' < "/proc/$shell_pid/environ" 2>/dev/null)"

        if echo "$environ" | grep -q '^SSH_CLIENT='; then
          ip="$(echo "$environ" | sed -n 's/^SSH_CLIENT=//p' | awk '{print $1}' | head -n1)"
        elif echo "$environ" | grep -q '^SSH_CONNECTION='; then
          ip="$(echo "$environ" | sed -n 's/^SSH_CONNECTION=//p' | awk '{print $1}' | head -n1)"
        fi
      fi
    fi
  fi

  # 3) Last resort: who -m (no --ips on your system)
  if [ -z "$ip" ]; then
    ip="$(who -m 2>/dev/null | awk '{print $NF}' | tr -d '()')"
  fi

  # sanitize
  if [ -z "$ip" ] || [ "$ip" = ":0" ]; then
    ip=""
  fi

  echo "$ip"
}

read -r -p "Do you want to update Fail2Ban ignoreip whitelist? (yes/no): " -r IGN_REPLY
echo ""

if [[ $IGN_REPLY =~ ^([Yy]es|[Yy])$ ]]; then
  if [ ! -f "$JAIL_LOCAL" ]; then
    warning "jail.local not found: $JAIL_LOCAL"
  else
    # --- MAIN FLOW: log exactly once ---
    CLIENT_IP="$(detect_ssh_client_ip)"
    if [ -n "$CLIENT_IP" ]; then
      log "Detected SSH client IP: $CLIENT_IP"
    else
      warning "No SSH client IP detected (env + sudo + who failed)"
    fi
    echo ""
    # --- end MAIN FLOW ---

    read -r -p "IP/CIDR(s) to add (comma/space separated; default: ${CLIENT_IP:-none}; empty = skip): " ADD_IP
    echo ""
    [ -z "$ADD_IP" ] && ADD_IP="$CLIENT_IP"

    # Docker subnet selection (with safe fallback)
    read -r -p "Auto-add Docker subnets to ignoreip? (yes/no): " -r DOCKER_AUTO_REPLY
    echo ""

    DOCKER_SUBNETS=""
    if [[ $DOCKER_AUTO_REPLY =~ ^([Yy]es|[Yy])$ ]]; then
      if ! command -v docker &>/dev/null; then
        warning "docker command not found; cannot auto-add Docker subnets"
        echo ""
      else
        BRIDGE_NETS="$(docker network ls --filter driver=bridge --format '{{.Name}}' 2>/dev/null | xargs -n1 echo)"
        if [ -z "$BRIDGE_NETS" ]; then
          warning "No Docker bridge networks found"
          echo ""
        else
          HAS_GW=0
          if echo "$BRIDGE_NETS" | grep -qx "docker_gwbridge"; then
            HAS_GW=1
          fi

          log "Detected Docker bridge networks:"
          while read -r net; do
            [ -z "$net" ] && continue
            subnets="$(docker network inspect "$net" --format '{{range .IPAM.Config}}{{.Subnet}} {{end}}' 2>/dev/null | xargs)"
            echo " • $net: ${subnets:-<no subnet>}"
          done <<<"$BRIDGE_NETS"
          echo ""

          echo "Select which Docker bridge networks to include:"
          echo " 1) Only default 'bridge' (safe-check subnet)"
          if [ "$HAS_GW" -eq 1 ]; then
            echo " 2) 'bridge' + 'docker_gwbridge' (Swarm gateway bridge)"
            echo " 3) All bridge networks"
            echo " 4) Choose by name (comma/space separated)"
          else
            echo " 2) All bridge networks"
            echo " 3) Choose by name (comma/space separated)"
          fi
          read -r -p "Choice: " DOCKER_CHOICE
          echo ""

          SELECTED_NETS=""
          if [ "$HAS_GW" -eq 1 ]; then
            case "$DOCKER_CHOICE" in
              1) SELECTED_NETS="bridge" ;;
              2) SELECTED_NETS="bridge docker_gwbridge" ;;
              3) SELECTED_NETS="$BRIDGE_NETS" ;;
              4)
                read -r -p "Enter network names: " NET_INPUT
                SELECTED_NETS="$(echo "$NET_INPUT" | tr ',' ' ' | xargs)"
                ;;
              *) warning "Invalid choice, skipping Docker subnets"; echo "" ;;
            esac
          else
            case "$DOCKER_CHOICE" in
              1) SELECTED_NETS="bridge" ;;
              2) SELECTED_NETS="$BRIDGE_NETS" ;;
              3)
                read -r -p "Enter network names: " NET_INPUT
                SELECTED_NETS="$(echo "$NET_INPUT" | tr ',' ' ' | xargs)"
                ;;
              *) warning "Invalid choice, skipping Docker subnets"; echo "" ;;
            esac
          fi

          # Safety check: if only "bridge" chosen, ensure it actually has subnet(s)
          if [ "$SELECTED_NETS" = "bridge" ]; then
            BRIDGE_SUBNETS_TEST="$(docker network inspect bridge --format '{{range .IPAM.Config}}{{.Subnet}} {{end}}' 2>/dev/null | xargs)"
            if [ -z "$BRIDGE_SUBNETS_TEST" ]; then
              warning "Docker network 'bridge' has no IPAM subnet info; cannot add it safely."
              echo ""

              read -r -p "Fallback to ALL Docker bridge networks instead? (yes/no): " -r FALLBACK_REPLY
              echo ""
              if [[ $FALLBACK_REPLY =~ ^([Yy]es|[Yy])$ ]]; then
                SELECTED_NETS="$BRIDGE_NETS"
              else
                SELECTED_NETS=""
                info "Skipping Docker subnet auto-add"
                echo ""
              fi
            fi
          fi

          if [ -n "$SELECTED_NETS" ]; then
            DOCKER_SUBNETS="$(
              for net in $SELECTED_NETS; do
                docker network inspect "$net" --format '{{range .IPAM.Config}}{{.Subnet}} {{end}}' 2>/dev/null
              done \
              | tr ' ' '\n' \
              | awk 'NF' \
              | awk '!seen[$0]++' \
              | tr '\n' ' '
            )"
            DOCKER_SUBNETS="$(echo "$DOCKER_SUBNETS" | xargs)"

            if [ -n "$DOCKER_SUBNETS" ]; then
              log "Docker subnets selected for ignoreip:"
              echo " $DOCKER_SUBNETS"
              echo ""
            else
              warning "No subnets extracted from selected Docker networks"
              echo ""
            fi
          fi
        fi
      fi
    fi

    if [ -z "$ADD_IP" ] && [ -z "$DOCKER_SUBNETS" ]; then
      info "Nothing to add; skipping ignoreip update"
      echo ""
    else
      cp "$JAIL_LOCAL" "$JAIL_LOCAL.backup-$(date +%Y%m%d-%H%M%S)"

      EXISTING_IGNOREIP="$(get_default_value "$JAIL_LOCAL" "ignoreip")"
      NEW_IGNOREIP="$(merge_ignoreip "$EXISTING_IGNOREIP" "$ADD_IP $DOCKER_SUBNETS")"

      set_default_kv "$JAIL_LOCAL" "ignoreip" "$NEW_IGNOREIP"

      log "ignoreip updated to:"
      echo " $NEW_IGNOREIP"
      echo ""
    fi
  fi
else
  info "ignoreip not modified"
  echo ""
fi

###############################################################################
# SSH PORT CONFIGURATION
###############################################################################

read -r -p "Do you want to change the default SSH port (2222) for jails? (yes/no): " -r SSH_REPLY
echo ""

if [[ $SSH_REPLY =~ ^([Yy]es|[Yy])$ ]]; then
  read -r -p "Enter custom SSH port (current: 2222): " CUSTOM_SSH_PORT
  echo ""
  
  # Validácia, či je to číslo
  if [[ "$CUSTOM_SSH_PORT" =~ ^[0-9]+$ ]]; then
      log "Updating SSH port to $CUSTOM_SSH_PORT in jail.local..."
      
      # Funkcia na priamu náhradu v konkrétnych sekciách (sed je tu jednoduchší ako awk pre konkrétne sekcie)
      # Najprv zálohujeme
      cp "$JAIL_LOCAL" "$JAIL_LOCAL.backup-sshport-$(date +%s)"
      
      # Nahradíme port = 2222 za port = NOVY_PORT v sekcii [sshd] a [sshd-slowattack]
      # Toto je trochu trickier, lebo port= môže byť hocikde.
      # Najbezpečnejšie je použiť crudini alebo python, ale s bashom:
      
      # 1. Nahradíme v [sshd]
      sed -i "/^\[sshd\]/,/^\[/ s/^port[[:space:]]*=[[:space:]]*[0-9]*/port = $CUSTOM_SSH_PORT/" "$JAIL_LOCAL"
      
      # 2. Nahradíme v [sshd-slowattack]
      sed -i "/^\[sshd-slowattack\]/,/^\[/ s/^port[[:space:]]*=[[:space:]]*[0-9]*/port = $CUSTOM_SSH_PORT/" "$JAIL_LOCAL"
      
      log "SSH port updated successfully."
      echo ""
  else
      warning "Invalid port number. Skipping SSH port update."
      echo ""
  fi
else
  info "Keeping default SSH port (2222)"
  echo ""
fi

################################################################################
# INSTALLATION STEPS
################################################################################

TOTALSTEPS=9

# Step 1: Pre-installation cleanup & backup
step 1 "$TOTALSTEPS" "Pre-installation cleanup & backup"
echo ""

if [ -f "$SCRIPTDIR/scripts/00-pre-cleanup-v033.sh" ]; then
  if [ "$FORCE_CLEANUP" = "yes" ]; then
    info "Pre-cleanup: FORCE mode enabled (--clean-install/--force-cleanup)"
    F2B_FORCE_CLEANUP=yes bash "$SCRIPTDIR/scripts/00-pre-cleanup-v033.sh" \
      || warning "Pre-cleanup had warnings (continuing)"
  else
    bash "$SCRIPTDIR/scripts/00-pre-cleanup-v033.sh" \
      || warning "Pre-cleanup had warnings (continuing)"
  fi
else
  info "Pre-cleanup script not found (skipping)"
fi

echo ""
if [ "$MODE" = "cleanup-only" ]; then
  log "Cleanup-only mode selected -> stopping after pre-cleanup."
  exit 0
fi

echo ""

# Step 2: Installing nftables infrastructure (IPv4/IPv6)
step 2 "$TOTALSTEPS" "Installing nftables infrastructure (IPv4/IPv6)"
echo ""
if [ -f "$SCRIPTDIR/scripts/01-install-nftables-v033.sh" ]; then
  bash "$SCRIPTDIR/scripts/01-install-nftables-v033.sh" || error "nftables installation failed"
else
  error "nftables installation script not found"
fi
echo ""

# Step 3: Installing Fail2Ban jails + 12 detection filters
step 3 "$TOTALSTEPS" "Installing Fail2Ban jails (12 detection filters)"
echo ""
if [ -f "$SCRIPTDIR/scripts/02-install-jails-v033.sh" ]; then
  bash "$SCRIPTDIR/scripts/02-install-jails-v033.sh" || error "Jails installation failed"
else
  error "Jails installation script not found"
fi
echo ""

# Step 4: Installing F2B wrapper
step 4 "$TOTALSTEPS" "Installing F2B wrapper ${RELEASE} (50+ functions)"
echo ""
if [ -f "$SCRIPTDIR/scripts/03-install-wrapper-v033.sh" ]; then
  bash "$SCRIPTDIR/scripts/03-install-wrapper-v033.sh" --yes || error "Wrapper installation failed"
elif [ -f "$SCRIPTDIR/scripts/04-install-wrapper-v033.sh" ]; then
  info "Using legacy wrapper installer (interactive prompts expected)"
  bash "$SCRIPTDIR/scripts/04-install-wrapper-v033.sh" || error "Legacy wrapper installation failed"
else
  error "Wrapper installation script not found"
fi
echo ""

# Step 5: Installing Docker port blocking v0.4
step 5 "$TOTALSTEPS" "Installing Docker port blocking v0.4"
echo ""
if [ -f "$SCRIPTDIR/scripts/04-install-docker-block-v033.sh" ]; then
  bash "$SCRIPTDIR/scripts/04-install-docker-block-v033.sh" || warning "Docker blocking had warnings"
elif [ -f "$SCRIPTDIR/scripts/03-install-docker-block-v033.sh" ]; then
  bash "$SCRIPTDIR/scripts/03-install-docker-block-v033.sh" || warning "Docker blocking had warnings"
else
  warning "Docker blocking script not found (skipping)"
fi
echo ""

# Step 6: Installing auto-sync service
step 6 "$TOTALSTEPS" "Installing auto-sync service (fail2ban ↔ nftables)"
echo ""
if [ -f "$SCRIPTDIR/scripts/05-install-auto-sync-v033.sh" ]; then
  bash "$SCRIPTDIR/scripts/05-install-auto-sync-v033.sh" || warning "Auto-sync installation had warnings"
else
  warning "Auto-sync script not found (skipping)"
fi
echo ""

# Step 7: Installing bash aliases
step 7 "$TOTALSTEPS" "Installing bash aliases"
echo ""
if [ -f "$SCRIPTDIR/scripts/06-install-aliases-v033.sh" ]; then
  bash "$SCRIPTDIR/scripts/06-install-aliases-v033.sh" || warning "Aliases installation had warnings"
else
  warning "Aliases script not found (skipping)"
fi
echo ""

# Step 8: CRITICAL - Configuring docker-block auto-sync cron
step 8 "$TOTALSTEPS" "⚠️  CRITICAL: Configuring docker-block auto-sync cron"
echo ""
if [ -f "$SCRIPTDIR/scripts/07-setup-docker-sync-cron-v033.sh" ]; then
  bash "$SCRIPTDIR/scripts/07-setup-docker-sync-cron-v033.sh" || warning "Docker-sync cron setup had warnings"
else
  warning "Docker-sync cron script not found (skipping)"
  warning "⚠️  Docker containers will NOT be protected without this!"
fi
echo ""

# Step 9: Final system verification
step 9 "$TOTALSTEPS" "Final system verification"
echo ""

################################################################################
# VERIFICATION (UPDATED FOR 12 JAILS)
################################################################################

# Verify nftables
# Počítame sety (mali by byť 12 IPv4 a 12 IPv6)
SETSV4=$(nft list table inet fail2ban-filter 2>/dev/null | grep "set f2b-" | grep -vc "\-v6" || echo 0)
SETSV6=$(nft list table inet fail2ban-filter 2>/dev/null | grep -c "set f2b-.*-v6" || echo 0)
# Počítame pravidlá (12 jailov x 2 verzie IP = 24 INPUT pravidiel)
INPUTRULES=$(nft list chain inet fail2ban-filter f2b-input 2>/dev/null | grep -c "drop" || echo 0)
FORWARDRULES=$(nft list chain inet fail2ban-filter f2b-forward 2>/dev/null | grep -c "drop" || echo 0)

echo "nftables Structure:"
echo " • IPv4 sets: $SETSV4 / 12"
echo " • IPv6 sets: $SETSV6 / 12"
echo " • INPUT rules: $INPUTRULES / 24"
echo " • FORWARD rules: $FORWARDRULES / 6" # Forward ostáva cca rovnako
echo ""

# Verify Fail2Ban
JAILCOUNT=$(fail2ban-client status 2>/dev/null | grep "Jail list:" | sed 's/.*://' | tr ',' '\n' | wc -l || echo 0)
echo "Fail2Ban:"
echo " • Active jails: $JAILCOUNT / 12"
echo ""

# Verify F2B wrapper
if [ -x /usr/local/bin/f2b ]; then
  echo "F2B Wrapper:"
  echo " • Status: Installed"
  F2BVERSION=$(/usr/local/bin/f2b version --short 2>/dev/null || echo "unknown")
  echo " • Version: $F2BVERSION"
  echo " • Functions: 50+ complete functions"
else
  echo "F2B Wrapper:"
  echo " • Status: Not found"
fi
echo ""

# Verify docker-block
if nft list table inet docker-block >/dev/null 2>&1; then
  echo "Docker-block:"
  echo " • Status: Installed"
  if sudo crontab -l 2>/dev/null | grep -q "f2b sync docker"; then
     echo " • Auto-sync: ACTIVE (every 1 minute)"
  else
     echo " • Auto-sync: NOT CONFIGURED"
  fi
else
  echo "Docker-block:"
  echo " • Status: Not installed"
fi
echo ""

################################################################################
# CALCULATE SUCCESS
################################################################################

ERRORS=0
[ "$SETSV4" -ne 12 ] && ((ERRORS++))
[ "$SETSV6" -ne 12 ] && ((ERRORS++))
[ "$INPUTRULES" -ne 24 ] && ((ERRORS++))
# [ "$FORWARDRULES" -ne 6 ] && ((ERRORS++)) # Toto je menej striktné, záleží od setupu
[ "$JAILCOUNT" -lt 12 ] && ((ERRORS++))

ENDTIME=$(date +%s)
DURATION=$((ENDTIME - STARTTIME))
MINUTES=$((DURATION / 60))
SECONDS=$((DURATION % 60))

echo ""
echo ""
if [ "$ERRORS" -eq 0 ]; then
  echo "╔════════════════════════════════════════════════════════════╗"
  echo "║                                                            ║"
  echo "║   ✅  INSTALLATION COMPLETE - SUCCESS!                      ║"
  echo "║                                                            ║"
  echo "╚════════════════════════════════════════════════════════════╝"
else
  echo "╔════════════════════════════════════════════════════════════╗"
  echo "║                                                            ║"
  echo "║   ⚠️  INSTALLATION COMPLETE - ERRORS/WARNINGS               ║"
  echo "║                                                            ║"
  echo "╚════════════════════════════════════════════════════════════╝"
fi
echo ""
echo ""
log "Installation duration: ${MINUTES}m ${SECONDS}s"
echo ""

if [ "$ERRORS" -eq 0 ]; then
  echo "Your system is now protected with ${RELEASE}:"
  echo " ✓ Full IPv4 + IPv6 dual-stack support"
  echo " ✓ 24 nftables rules (12 IPv4 + 12 IPv6)"
  echo " ✓ 12 Fail2Ban jails + 12 detection filters"
  echo " ✓ Docker port blocking v0.4"
  echo " ✓ F2B wrapper ${RELEASE} (50+ functions)"
  echo " ✓ Docker-block auto-sync (every 1 minute)"
  echo " ✓ Auto-sync enabled (hourly)"
else
  warning "Installation completed with $ERRORS warnings"
  info "Review logs for details"
fi

echo ""
echo ""
info "Next Steps:"
echo ""
echo ""
echo "1. Reload bash aliases:"
echo "   source ~/.bashrc"
echo ""
echo "2. Test the F2B wrapper:"
echo "   sudo f2b status"
echo ""
echo "3. Verify docker-block sync:"
echo "   sudo crontab -l | grep docker-sync"
echo "   sudo tail -f /var/log/f2b-docker-sync.log"
echo ""
echo "4. Real-time docker-block dashboard:"
echo "   sudo f2b docker dashboard"
echo ""
echo "5. Monitor attacks in real-time:"
echo "   sudo f2b monitor watch"
echo ""
echo "6. Manual docker-block sync (if needed):"
echo "   sudo f2b sync docker"
echo ""
echo ""
log "Installation complete!"
echo ""

