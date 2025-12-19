#!/bin/bash

################################################################################
# Fail2Ban + nftables v0.23 - Universal Installer
# Complete Production Installation with IPv4+IPv6 support
#
# Features:
# - Auto-detects: Fresh install / Upgrade from v0.19/v0.21
# - 11 Fail2Ban jails + 11 detection filters
# - Full IPv4 + IPv6 dual-stack support
# - F2B Wrapper v0.24 (50 functions)
# - Docker port blocking v0.4
# - Docker-block auto-sync (cron every 1 minute) ⚠️ CRITICAL
# - Auto-sync service
#
# Supports:
# - Fresh installation on new servers
# - Upgrade from v0.19/v0.21/v0.22 (adds IPv6 + docker-block sync)
# - Reinstall v0.2š (rebuild components)
################################################################################

################################################################################
# Component: Main Installer
# Part of: Fail2Ban Hybrid Nftables Manager
################################################################################

set -e
# shellcheck disable=SC2034  # Metadata: used for release tracking / logging
RELEASE="v0.30"
# shellcheck disable=SC2034 
VERSION="0.30"
# shellcheck disable=SC2034
BUILD_DATE="2025-12-19"
# shellcheck disable=SC2034
COMPONENT_NAME="INSTALL-ALL"

export VERSION  # Export for subscripts

# Colors
# shellcheck disable=SC2034  # Predefined color constants (may be unused in some scripts)
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

################################################################################
# CLI FLAGS
################################################################################

MODE="auto"          # auto | cleanup-only
FORCE_CLEANUP="no"   # no | yes

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
# GET SCRIPT DIRECTORY
################################################################################
SCRIPTDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPTDIR"

################################################################################
# DETECT INSTALLATION TYPE
################################################################################
info "Detecting installation type..."
echo ""

INSTALLTYPE="fresh"

# Check if fail2ban is installed
if command -v fail2ban-client &>/dev/null; then
    info "Fail2Ban detected: $(fail2ban-client --version | head -1)"
    INSTALLTYPE="upgrade"
fi

# Check if nftables table exists
if nft list table inet fail2ban-filter &>/dev/null 2>&1; then
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
if nft list table inet docker-block &>/dev/null 2>&1; then
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
        echo "  • nftables with fail2ban-filter table (IPv4/IPv6)"
        echo "  • Fail2Ban with 11 jails"
        echo "  • 11 detection filters"
        echo "  • Docker port blocking v0.4"
        echo "  • F2B wrapper ${RELEASE} (50+ functions)"
        echo "  • Docker-block auto-sync cron (CRITICAL)"
        echo "  • Auto-sync service (hourly)"
        echo "  • Bash aliases"
        ;;
    upgrade_old)
        echo "UPGRADE from v0.19-v0.21 to ${RELEASE}"
        echo ""
        echo "Current state:"
        echo "  • IPv4 sets: $CURRENTSETSV4"
        echo "  • IPv6 sets: $CURRENTSETSV6 (missing)"
        echo ""
        echo "Will upgrade to:"
        echo "  • Add IPv6 support (11 sets + 11 rules)"
        echo "  • Add docker-block v0.4"
        echo "  • Add docker-block auto-sync (CRITICAL)"
        echo "  • Update F2B wrapper to ${RELEASE} (50+ functions)"
        echo "  • Add new filters if missing"
        echo "  • Preserve all banned IPs"
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
echo "Configure email alerts and WAN/Server IP ignore list."
echo ""

read -p "Do you want to configure email notifications? (yes/no): " -r
echo ""

if [[ $REPLY =~ ^[Yy]es$ ]]; then
    # Check if mail service is available
    if command -v mail &>/dev/null || command -v sendmail &>/dev/null; then
        log "Mail service detected"
        echo ""
        
        read -p "Enter admin email address (for receiving alerts): " ADMIN_EMAIL
        read -p "Enter sender email address (for From header): " SENDER_EMAIL
        
        if [ -n "$ADMIN_EMAIL" ] && [ -n "$SENDER_EMAIL" ]; then
            # Update jail.local before installation
            if [ -f "$SCRIPTDIR/config/jail.local" ]; then
                log "Updating email configuration in jail.local..."
                
                # Backup original
                cp "$SCRIPTDIR/config/jail.local" "$SCRIPTDIR/config/jail.local.backup-$(date +%Y%m%d-%H%M%S)"
                
                # Update destemail and sender (global)
                sed -i "s|^destemail = .*|destemail = $ADMIN_EMAIL|g" "$SCRIPTDIR/config/jail.local"
                sed -i "s|^sender = .*|sender = $SENDER_EMAIL|g" "$SCRIPTDIR/config/jail.local"
                
                log "Email configuration updated:"
                echo " • Destination email: $ADMIN_EMAIL"
                echo " • Sender email: $SENDER_EMAIL"
                echo ""
                
                # Show which jails will send emails
                log "Email alerts will be sent when IPs are banned in:"
                echo ""
                grep "action = %(action_mwl)s" "$SCRIPTDIR/config/jail.local" | sed 's/.*\[\(.*\)\].*/   ✉ \1 (on ban: email + ban)/g' | sort -u
                echo ""
                
            else
                warning "jail.local not found in config/ directory"
            fi
        else
            warning "Invalid email addresses provided, using default configuration"
        fi
        
        echo ""
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

################################################################################
# AUTO-DETECT WAN/SERVER IP & IGNORE LIST
################################################################################

info "Auto-Detecting WAN/Server IP Address"
echo ""
echo "Adding your server's WAN/LAN IP to the ignore list ensures you won't"
echo "accidentally block yourself if SSH or web services trigger Fail2Ban."
echo ""

# Try to detect primary WAN/LAN IP
WAN_IP=""

# Method 1: Get IP from hostname -I
if command -v hostname &>/dev/null; then
    IPS=$(hostname -I 2>/dev/null | awk '{print $1}')
    if [ -n "$IPS" ]; then
        WAN_IP="$IPS"
    fi
fi

# Method 2: Get from ip addr (if hostname fails)
if [ -z "$WAN_IP" ] && command -v ip &>/dev/null; then
    WAN_IP=$(ip addr show | grep "inet " | grep -v "127.0.0.1" | head -1 | awk '{print $2}' | cut -d/ -f1)
fi

# Method 3: Try ifconfig (fallback for older systems)
if [ -z "$WAN_IP" ] && command -v ifconfig &>/dev/null; then
    WAN_IP=$(ifconfig | grep "inet " | grep -v "127.0.0.1" | head -1 | awk '{print $2}')
fi

if [ -n "$WAN_IP" ]; then
    log "Detected WAN/Server IP: $WAN_IP"
    
    read -p "Add this IP to Fail2Ban ignore list? (yes/no): " -r
    echo ""
    
    if [[ $REPLY =~ ^[Yy]es$ ]]; then
        # Update ignoreip in jail.local
        if [ -f "$SCRIPTDIR/config/jail.local" ]; then
            log "Adding $WAN_IP to ignoreip list in jail.local..."
            
            # Check if ignoreip line exists
            if grep -q "^ignoreip" "$SCRIPTDIR/config/jail.local"; then
                # Append to existing ignoreip (preserving loopback)
                sed -i "s|^ignoreip = .*|ignoreip = 127.0.0.1/8 ::1 $WAN_IP|g" "$SCRIPTDIR/config/jail.local"
            else
                # Add new ignoreip line after [DEFAULT]
                sed -i "/\[DEFAULT\]/a ignoreip = 127.0.0.1/8 ::1 $WAN_IP" "$SCRIPTDIR/config/jail.local"
            fi
            
            log "Ignore list updated:"
            echo " • 127.0.0.1/8 (localhost IPv4)"
            echo " • ::1 (localhost IPv6)"
            echo " • $WAN_IP (your server WAN/LAN IP)"
            echo ""
        fi
    else
        info "WAN IP not added to ignore list"
        echo ""
    fi
else
    warning "Could not auto-detect server WAN/LAN IP"
    echo " Manually add your server IP to ignoreip in config/jail.local before installation:"
    echo " ignoreip = 127.0.0.1/8 ::1 <YOUR_WAN_OR_LAN_IP>"
    echo ""
fi

echo ""


if [ "$MODE" != "cleanup-only" ]; then
  read -p "Continue with installation? (yes/no): " -r
  echo ""

  if [[ ! $REPLY =~ ^[Yy]es$ ]]; then
    warning "Installation cancelled by user"
    exit 0
  fi
else
  info "Mode: cleanup-only (will run pre-cleanup and exit)"
  echo ""
fi

STARTTIME=$(date +%s)

################################################################################
# INSTALLATION STEPS
################################################################################
TOTALSTEPS=9

# Step 1: Pre-installation cleanup & backup
step 1 "$TOTALSTEPS" "Pre-installation cleanup & backup"
echo ""
if [ -f "$SCRIPTDIR/scripts/00-pre-cleanup-v030.sh" ]; then
  if [ "$FORCE_CLEANUP" = "yes" ]; then
    info "Pre-cleanup: FORCE mode enabled (--clean-install/--force-cleanup)"
    F2B_FORCE_CLEANUP=yes bash "$SCRIPTDIR/scripts/00-pre-cleanup-v030.sh" \
      || warning "Pre-cleanup had warnings (continuing)"
  else
    bash "$SCRIPTDIR/scripts/00-pre-cleanup-v030.sh" \
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
if [ -f "$SCRIPTDIR/scripts/01-install-nftables-v030.sh" ]; then
    bash "$SCRIPTDIR/scripts/01-install-nftables-v030.sh" || error "nftables installation failed"
else
    error "nftables installation script not found"
fi
echo ""

# Step 3: Installing Fail2Ban jails + 11 detection filters
step 3 "$TOTALSTEPS" "Installing Fail2Ban jails (11 detection filters)"
echo ""
if [ -f "$SCRIPTDIR/scripts/02-install-jails-v030.sh" ]; then
    bash "$SCRIPTDIR/scripts/02-install-jails-v030.sh" || error "Jails installation failed"
else
    error "Jails installation script not found"
fi
echo ""

# Step 4: Installing Docker port blocking v0.4
step 4 "$TOTALSTEPS" "Installing Docker port blocking v0.4"
echo ""
if [ -f "$SCRIPTDIR/scripts/03-install-docker-block-v030.sh" ]; then
    bash "$SCRIPTDIR/scripts/03-install-docker-block-v030.sh" || warning "Docker blocking had warnings (may be optional)"
else
    warning "Docker blocking script not found (skipping)"
fi
echo ""

# Step 5: Installing F2B wrapper v0.30 (50+ functions)
step 5 "$TOTALSTEPS" "Installing F2B wrapper ${RELEASE} (50+ functions)"
echo ""

# Try direct wrapper installation first
if [ -f "$SCRIPTDIR/scripts/f2b-wrapper-v030.sh" ]; then
    sudo cp "$SCRIPTDIR/scripts/f2b-wrapper-v030.sh" /usr/local/bin/f2b
    sudo chmod +x /usr/local/bin/f2b
    log "✓ F2B wrapper installed at /usr/local/bin/f2b"
elif [ -f "$SCRIPTDIR/scripts/04-install-wrapper-v030.sh" ]; then
    bash "$SCRIPTDIR/scripts/04-install-wrapper-v030.sh" || error "Wrapper installation failed"
else
    error "Wrapper installation script not found"
fi
echo ""

# Step 6: Installing auto-sync service (fail2ban ↔ nftables)
step 6 "$TOTALSTEPS" "Installing auto-sync service (fail2ban ↔ nftables)"
echo ""
if [ -f "$SCRIPTDIR/scripts/05-install-auto-sync-v030.sh" ]; then
    bash "$SCRIPTDIR/scripts/05-install-auto-sync-v030.sh" || warning "Auto-sync installation had warnings"
else
    warning "Auto-sync script not found (skipping)"
fi
echo ""

# Step 7: Installing bash aliases
step 7 "$TOTALSTEPS" "Installing bash aliases"
echo ""
if [ -f "$SCRIPTDIR/scripts/06-install-aliases-v030.sh" ]; then
    bash "$SCRIPTDIR/scripts/06-install-aliases-v030.sh" || warning "Aliases installation had warnings"
else
    warning "Aliases script not found (skipping)"
fi
echo ""

# Step 8: CRITICAL - Configuring docker-block auto-sync cron
step 8 "$TOTALSTEPS" "⚠️  CRITICAL: Configuring docker-block auto-sync cron"
echo ""
if [ -f "$SCRIPTDIR/scripts/07-setup-docker-sync-cron-v030.sh" ]; then
    bash "$SCRIPTDIR/scripts/07-setup-docker-sync-cron-v030.sh" || warning "Docker-sync cron setup had warnings"
else
    warning "Docker-sync cron script not found (skipping)"
    warning "⚠️  Docker containers will NOT be protected without this!"
    echo ""
    info "Manual setup required:"
    echo "  sudo crontab -e"
    echo ""
    echo "Add this line:"
    echo "  */1 * * * * /usr/local/bin/f2b sync docker >> /var/log/f2b-docker-sync.log 2>&1"
fi
echo ""

# Step 9: Final system verification
step 9 "$TOTALSTEPS" "Final system verification"
echo ""

################################################################################
# VERIFICATION
################################################################################

# Verify nftables
SETSV4=$(nft list table inet fail2ban-filter 2>/dev/null | grep "set f2b-" | grep -vc "\-v6" || echo 0)
SETSV6=$(nft list table inet fail2ban-filter 2>/dev/null | grep -c "set f2b-.*-v6" || echo 0)
INPUTRULES=$(nft list chain inet fail2ban-filter f2b-input 2>/dev/null | grep -c "drop" || echo 0)
FORWARDRULES=$(nft list chain inet fail2ban-filter f2b-forward 2>/dev/null | grep -c "drop" || echo 0)

echo "nftables Structure:"
echo "  • IPv4 sets: $SETSV4 / 11"
echo "  • IPv6 sets: $SETSV6 / 11"
echo "  • INPUT rules: $INPUTRULES / 22"
echo "  • FORWARD rules: $FORWARDRULES / 6"
echo ""

# Verify Fail2Ban
JAILCOUNT=$(fail2ban-client status 2>/dev/null | grep "Jail list:" | sed 's/.*://' | tr ',' '\n' | wc -l || echo 0)
echo "Fail2Ban:"
echo "  • Active jails: $JAILCOUNT / 11"
echo ""

# Verify F2B wrapper
if [ -x /usr/local/bin/f2b ]; then
    echo "F2B Wrapper:"
    echo "  • Status: Installed"
    F2BVERSION=$(/usr/local/bin/f2b version --short 2>/dev/null || echo "unknown")
    echo "  • Version: $F2BVERSION"
    echo "  • Functions: 50+ complete functions"
else
    echo "F2B Wrapper:"
    echo "  • Status: Not found"
fi
echo ""

# Verify docker-block
if nft list table inet docker-block &>/dev/null 2>&1; then
    echo "Docker-block:"
    echo "  • Status: Installed"
    
    # Check auto-sync cron
    if sudo crontab -l 2>/dev/null | grep -q "f2b sync docker"; then
        echo "  • Auto-sync: ACTIVE (every 1 minute)"
    else
        echo "  • Auto-sync: NOT CONFIGURED"
    fi
else
    echo "Docker-block:"
    echo "  • Status: Not installed"
fi
echo ""

################################################################################
# CALCULATE SUCCESS
################################################################################
ERRORS=0
[ "$SETSV4" -ne 11 ] && ((ERRORS++))
[ "$SETSV6" -ne 11 ] && ((ERRORS++))
[ "$INPUTRULES" -ne 22 ] && ((ERRORS++))
[ "$FORWARDRULES" -ne 6 ] && ((ERRORS++))
[ "$JAILCOUNT" -lt 11 ] && ((ERRORS++))

ENDTIME=$(date +%s)
DURATION=$((ENDTIME - STARTTIME))
MINUTES=$((DURATION / 60))
SECONDS=$((DURATION % 60))

echo ""
echo ""

if [ "$ERRORS" -eq 0 ]; then
    echo "╔════════════════════════════════════════════════════════════╗"
    echo "║                                                            ║"
    echo "║           ✅ INSTALLATION COMPLETE - SUCCESS!              ║"
    echo "║                                                            ║"
    echo "╚════════════════════════════════════════════════════════════╝"
else
    echo "╔════════════════════════════════════════════════════════════╗"
    echo "║                                                            ║"
    echo "║      ⚠️  INSTALLATION COMPLETE - ERRORS/WARNINGS           ║"
    echo "║                                                            ║"
    echo "╚════════════════════════════════════════════════════════════╝"
fi

echo ""
echo ""
log "Installation duration: ${MINUTES}m ${SECONDS}s"
echo ""

if [ "$ERRORS" -eq 0 ]; then
    echo "Your system is now protected with ${RELEASE}:"
    echo "  ✓ Full IPv4 + IPv6 dual-stack support"
    echo "  ✓ 22 nftables rules (11 IPv4 + 11 IPv6)"
    echo "  ✓ 11 Fail2Ban jails + 11 detection filters"
    echo "  ✓ Docker port blocking v0.4"
    echo "  ✓ F2B wrapper ${RELEASE} (50+ functions)"
    echo "  ✓ Docker-block auto-sync (every 1 minute)"
    echo "  ✓ Auto-sync enabled (hourly)"
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
