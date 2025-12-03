#!/bin/bash
################################################################################
# Install Fail2Ban Jail Configuration and Filters v0.19
# Copies jail.local and filter files to /etc/fail2ban
################################################################################

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Logging
log() { echo -e "${GREEN}[OK]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }
warning() { echo -e "${YELLOW}[WARN]${NC} $1"; }
info() { echo -e "${BLUE}[INFO]${NC} $1"; }

echo ""
echo "═══════════════════════════════════════════════════════"
echo "  Fail2Ban Jail Configuration Installation v0.19"
echo "═══════════════════════════════════════════════════════"
echo ""

# Root check
if [[ $EUID -ne 0 ]]; then
   error "Please run with sudo"
fi

# Get script directory
SCRIPTDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Check for jail.local
JAILLOCAL=""
if [[ -f "$SCRIPTDIR/jail.local" ]]; then
    JAILLOCAL="$SCRIPTDIR/jail.local"
elif [[ -f "$SCRIPTDIR/config/jail.local" ]]; then
    JAILLOCAL="$SCRIPTDIR/config/jail.local"
else
    error "jail.local not found in $SCRIPTDIR or $SCRIPTDIR/config"
fi

info "Found jail.local: $JAILLOCAL"
echo ""

# Check for filters directory
FILTERSDIR=""
if [[ -d "$SCRIPTDIR/filters" ]]; then
    FILTERSDIR="$SCRIPTDIR/filters"
elif [[ -d "$SCRIPTDIR/config/filters" ]]; then
    FILTERSDIR="$SCRIPTDIR/config/filters"
else
    warning "Filters directory not found (optional)"
fi

if [[ -n "$FILTERSDIR" ]]; then
    info "Found filters directory: $FILTERSDIR"
    FILTERCOUNT=$(find "$FILTERSDIR" -name "*.conf" 2>/dev/null | wc -l)
    info "Found $FILTERCOUNT filter files"
fi
echo ""

# Confirmation
echo ""
warning "This will:"
echo "  • Backup existing jail.local (if present)"
echo "  • Copy new jail.local to /etc/fail2ban/jail.local"
if [[ -n "$FILTERSDIR" && $FILTERCOUNT -gt 0 ]]; then
    echo "  • Copy $FILTERCOUNT filters to /etc/fail2ban/filter.d/"
fi
echo "  • Validate configuration"
echo "  • Restart fail2ban service"
echo ""
read -p "Continue? [yes/no]: " -r
if [[ ! $REPLY =~ ^[Yy]es$ ]]; then
    warning "Installation cancelled"
    exit 0
fi
echo ""

# Step 1: Backup existing jail.local
if [[ -f /etc/fail2ban/jail.local ]]; then
    BACKUPFILE="/etc/fail2ban/jail.local.backup-$(date +%Y%m%d-%H%M)"
    log "Step 1/7: Backing up existing jail.local..."
    cp /etc/fail2ban/jail.local "$BACKUPFILE"
    log "Backup created: $BACKUPFILE"
else
    info "Step 1/7: No existing jail.local to backup"
fi
echo ""

# Step 2: Copy jail.local
log "Step 2/7: Installing jail.local..."
cp "$JAILLOCAL" /etc/fail2ban/jail.local
chown root:root /etc/fail2ban/jail.local
chmod 644 /etc/fail2ban/jail.local
log "Installed: /etc/fail2ban/jail.local"
echo ""

# Step 3: Copy filters
if [[ -n "$FILTERSDIR" && $FILTERCOUNT -gt 0 ]]; then
    log "Step 3/7: Installing filters..."
    INSTALLEDFILTERS=0
    
    while IFS= read -r filterfile; do
        FILTERNAME=$(basename "$filterfile")
        
        # Backup existing filter
        if [[ -f "/etc/fail2ban/filter.d/$FILTERNAME" ]]; then
            FILTERBACKUP="/etc/fail2ban/filter.d/$FILTERNAME.backup-$(date +%Y%m%d-%H%M)"
            cp "/etc/fail2ban/filter.d/$FILTERNAME" "$FILTERBACKUP"
            info "  Backed up $FILTERNAME"
        fi
        
        # Copy new filter
        cp "$filterfile" /etc/fail2ban/filter.d/
        chown root:root "/etc/fail2ban/filter.d/$FILTERNAME"
        chmod 644 "/etc/fail2ban/filter.d/$FILTERNAME"
        log "  Installed: $FILTERNAME"
        ((INSTALLEDFILTERS++))
    done < <(find "$FILTERSDIR" -name "*.conf" 2>/dev/null)
    
    echo ""
    log "Installed $INSTALLEDFILTERS filters"
else
    info "Step 3/7: No filters to install (skipped)"
fi
echo ""

# Step 4: Create manualblock.log if needed
log "Step 4/7: Checking manualblock.log..."
if grep -q "logpath.*manualblock.log" /etc/fail2ban/jail.local 2>/dev/null; then
    if [[ ! -f /etc/fail2ban/manualblock.log ]]; then
        touch /etc/fail2ban/manualblock.log
        chmod 644 /etc/fail2ban/manualblock.log
        log "Created /etc/fail2ban/manualblock.log"
    else
        info "manualblock.log already exists"
    fi
else
    info "manualblock jail not configured (skip)"
fi
echo ""

# Step 5: Validate configuration
log "Step 5/7: Validating Fail2Ban configuration..."
if fail2ban-client -t &> /dev/null; then
    log "Configuration syntax OK"
else
    error "Configuration syntax error! Check /var/log/fail2ban.log"
fi
echo ""

# Step 6: Restart fail2ban
log "Step 6/7: Restarting Fail2Ban service..."
if systemctl restart fail2ban; then
    log "Fail2Ban restarted successfully"
else
    error "Failed to restart Fail2Ban"
fi

# Wait for fail2ban to start
sleep 3

# Verify service is active
if systemctl is-active --quiet fail2ban; then
    log "Fail2Ban is active"
else
    error "Fail2Ban failed to start"
fi
echo ""

# Step 7: Verify jails
log "Step 7/7: Verifying active jails..."
echo ""
JAILLIST=$(fail2ban-client status 2>/dev/null | grep "Jail list" | sed 's/.*://') 

if [[ -z "$JAILLIST" ]]; then
    error "No jails detected! Check configuration."
fi

echo "Active jails:"
echo "$JAILLIST" | tr ',' '\n' | sed 's/^/  - /'
echo ""

JAILCOUNT=$(echo "$JAILLIST" | tr ',' '\n' | wc -l)
log "Total active jails: $JAILCOUNT"
echo ""

# Step 8: Verify nftables banaction
log "Verifying nftables integration..."
echo ""
NFTABLESJAILS=$(grep -c "banaction.*nftables-multiport" /etc/fail2ban/jail.local 2>/dev/null || echo "0")
echo "Jails with nftables-multiport: $NFTABLESJAILS"

if [[ $NFTABLESJAILS -ge 8 ]]; then
    log "✓ Majority of jails using nftables-multiport!"
else
    warning "Some jails might use different banaction"
fi
echo ""

# Summary
echo ""
echo "═══════════════════════════════════════════════════════"
log "Installation Summary"
echo "═══════════════════════════════════════════════════════"
echo ""
log "• jail.local: Installed (/etc/fail2ban/jail.local)"
if [[ -n "$FILTERSDIR" && $INSTALLEDFILTERS -gt 0 ]]; then
    log "• Filters: $INSTALLEDFILTERS installed"
fi
log "• Active jails: $JAILCOUNT"
log "• Service: Running"
echo ""

# Expected jails
echo "Expected jails in v0.19:"
echo "  1. sshd"
echo "  2. f2b-exploit-critical"
echo "  3. f2b-dos-high"
echo "  4. f2b-web-medium"
echo "  5. nginx-recon-bonus"
echo "  6. recidive"
echo "  7. manualblock"
echo "  8. f2b-fuzzing-payloads"
echo "  9. f2b-botnet-signatures"
echo "  10. f2b-anomaly-detection"
echo ""

if [[ $JAILCOUNT -ne 10 ]]; then
    warning "Expected 10 jails, found $JAILCOUNT"
    warning "Check /var/log/fail2ban.log for errors"
    echo ""
    echo "Common issues:"
    echo "  - Missing filter file"
    echo "  - Wrong logpath"
    echo "  - Syntax error in jail definition"
else
    log "✓ All 10 expected jails are active!"
fi
echo ""

echo "═══════════════════════════════════════════════════════"
info "Next Steps:"
echo "═══════════════════════════════════════════════════════"
echo ""
echo "1. Check jail status:"
echo "   fail2ban-client status"
echo ""
echo "2. View specific jail:"
echo "   fail2ban-client status sshd"
echo ""
echo "3. Monitor logs:"
echo "   tail -f /var/log/fail2ban.log"
echo ""
echo "4. Continue with installation:"
echo "   sudo bash 03-install-docker-block-v03.sh"
echo ""
echo ""
log "Fail2Ban jails installed successfully!"
echo ""
