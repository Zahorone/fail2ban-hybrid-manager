#!/bin/bash

################################################################################
# Install Fail2Ban Jail Configuration and Filters v0.22
# Copies jail.local and filter files to /etc/fail2ban
# FIXED: Proper path resolution from parent directory
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
echo " Fail2Ban Jail Configuration Installation v0.22"
echo "═══════════════════════════════════════════════════════"
echo ""

# Root check
if [[ $EUID -ne 0 ]]; then
    error "Please run with sudo"
fi

################################################################################
# PRE-CHECKS
################################################################################

info "Pre-flight checks..."
echo ""

# Check if fail2ban is installed
if ! command -v fail2ban-client &>/dev/null; then
    error "fail2ban is not installed! Install it first: apt install fail2ban"
fi

log "fail2ban installed: $(fail2ban-client --version | head -1)"

# Check if fail2ban directories exist
if [[ ! -d /etc/fail2ban ]]; then
    error "/etc/fail2ban directory not found!"
fi

if [[ ! -d /etc/fail2ban/filter.d ]]; then
    error "/etc/fail2ban/filter.d directory not found!"
fi

if [[ ! -d /etc/fail2ban/jail.d ]]; then
    sudo mkdir -p /etc/fail2ban/jail.d
    log "Created /etc/fail2ban/jail.d"
fi

echo ""

################################################################################
# PATH RESOLUTION
################################################################################

info "Resolving paths..."
echo ""

# Get script directory (scripts/)
SCRIPTDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
info "Script directory: $SCRIPTDIR"

# Get parent directory (v0.22/)
PARENTDIR="$(cd "$SCRIPTDIR/.." && pwd)"
info "Parent directory: $PARENTDIR"

################################################################################
# LOCATE SOURCE FILES
################################################################################

info "Locating source files..."
echo ""

# Check for jail.local in parent/config/
JAILLOCAL=""
if [[ -f "$PARENTDIR/config/jail.local" ]]; then
    JAILLOCAL="$PARENTDIR/config/jail.local"
elif [[ -f "$SCRIPTDIR/jail.local" ]]; then
    # Fallback: directly in scripts/
    JAILLOCAL="$SCRIPTDIR/jail.local"
elif [[ -f "$SCRIPTDIR/config/jail.local" ]]; then
    # Fallback: scripts/config/
    JAILLOCAL="$SCRIPTDIR/config/jail.local"
else
    error "jail.local not found! Expected at: $PARENTDIR/config/jail.local"
fi

log "Found jail.local: $JAILLOCAL"

# Check for filters directory in parent/filters/
FILTERSDIR=""
if [[ -d "$PARENTDIR/filters" ]]; then
    FILTERSDIR="$PARENTDIR/filters"
elif [[ -d "$SCRIPTDIR/filters" ]]; then
    # Fallback: directly in scripts/
    FILTERSDIR="$SCRIPTDIR/filters"
elif [[ -d "$SCRIPTDIR/config/filters" ]]; then
    # Fallback: scripts/config/filters/
    FILTERSDIR="$SCRIPTDIR/config/filters"
else
    warning "Filters directory not found (will skip filter installation)"
    warning "Expected at: $PARENTDIR/filters/"
fi

if [[ -n "$FILTERSDIR" ]]; then
    log "Found filters directory: $FILTERSDIR"
    FILTERCOUNT=$(find "$FILTERSDIR" -maxdepth 1 -name "*.conf" 2>/dev/null | wc -l)
    log "Found $FILTERCOUNT filter files"
    
    # List filters for verification
    if [[ $FILTERCOUNT -gt 0 ]]; then
        echo ""
        info "Filter files:"
        find "$FILTERSDIR" -maxdepth 1 -name "*.conf" -exec basename {} \; | sort | sed 's/^/  • /'
    fi
fi

echo ""

################################################################################
# ADDITIONAL CONFIG FILES (nginx-recon, anomaly-detection)
################################################################################

info "Checking for additional config files..."
echo ""

# Check for nginx-recon-optimized.local
NGINXRECONLOCAL=""
if [[ -f "$PARENTDIR/config/nginx-recon-optimized.local" ]]; then
    NGINXRECONLOCAL="$PARENTDIR/config/nginx-recon-optimized.local"
    log "Found: nginx-recon-optimized.local"
else
    info "nginx-recon-optimized.local not found (optional)"
fi

# Check for f2b-anomaly-detection.local
ANOMALYLOCAL=""
if [[ -f "$PARENTDIR/config/f2b-anomaly-detection.local" ]]; then
    ANOMALYLOCAL="$PARENTDIR/config/f2b-anomaly-detection.local"
    log "Found: f2b-anomaly-detection.local"
else
    info "f2b-anomaly-detection.local not found (optional)"
fi

echo ""

################################################################################
# CONFIRMATION
################################################################################

echo ""
warning "This will:"
echo " • Backup existing jail.local (if present)"
echo " • Install new jail.local to /etc/fail2ban/jail.local"

if [[ -n "$FILTERSDIR" && $FILTERCOUNT -gt 0 ]]; then
    echo " • Install/update $FILTERCOUNT filter *.conf files to /etc/fail2ban/filter.d/"
    echo " • Backup existing filters before overwriting"
fi

if [[ -n "$NGINXRECONLOCAL" ]]; then
    echo " • Install nginx-recon-optimized.local to /etc/fail2ban/filter.d/ (extra filter config)"
fi

if [[ -n "$ANOMALYLOCAL" ]]; then
    echo " • Install f2b-anomaly-detection.local to /etc/fail2ban/filter.d/ (extra filter config)"
fi

echo " • Validate configuration"
echo " • Restart fail2ban service"
echo ""

read -p "Continue? [yes/no]: " -r
if [[ ! $REPLY =~ ^[Yy]es$ ]]; then
    warning "Installation cancelled"
    exit 0
fi

echo ""

################################################################################
# STEP 1: BACKUP EXISTING JAIL.LOCAL
################################################################################

if [[ -f /etc/fail2ban/jail.local ]]; then
    BACKUPFILE="/etc/fail2ban/jail.local.backup-$(date +%Y%m%d-%H%M%S)"
    log "Step 1/8: Backing up existing jail.local..."
    
    if sudo cp /etc/fail2ban/jail.local "$BACKUPFILE"; then
        log "Backup created: $BACKUPFILE"
    else
        error "Failed to backup jail.local"
    fi
else
    info "Step 1/8: No existing jail.local to backup"
fi

echo ""

################################################################################
# STEP 2: INSTALL JAIL.LOCAL
################################################################################

log "Step 2/8: Installing jail.local..."

if sudo cp "$JAILLOCAL" /etc/fail2ban/jail.local; then
    sudo chown root:root /etc/fail2ban/jail.local
    sudo chmod 644 /etc/fail2ban/jail.local
    log "Installed: /etc/fail2ban/jail.local"
else
    error "Failed to copy jail.local"
fi

echo ""

################################################################################
# STEP 3: INSTALL ADDITIONAL FILTER *.LOCAL CONFIGS
################################################################################

log "Step 3/8: Installing extra filter *.local configs..."

ADDITIONAL_INSTALLED=0

# Install nginx-recon-optimized.local -> /etc/fail2ban/filter.d/
if [[ -n "$NGINXRECONLOCAL" ]]; then
    TARGET="/etc/fail2ban/filter.d/nginx-recon-optimized.local"
    if sudo cp "$NGINXRECONLOCAL" "$TARGET"; then
        sudo chown root:root "$TARGET"
        sudo chmod 644 "$TARGET"
        log " ✓ Installed: nginx-recon-optimized.local → filter.d"
        ((ADDITIONAL_INSTALLED++))
    else
        warning " ✗ Failed to install nginx-recon-optimized.local"
    fi
fi

# Install f2b-anomaly-detection.local -> /etc/fail2ban/filter.d/
if [[ -n "$ANOMALYLOCAL" ]]; then
    TARGET="/etc/fail2ban/filter.d/f2b-anomaly-detection.local"
    if sudo cp "$ANOMALYLOCAL" "$TARGET"; then
        sudo chown root:root "$TARGET"
        sudo chmod 644 "$TARGET"
        log " ✓ Installed: f2b-anomaly-detection.local → filter.d"
        ((ADDITIONAL_INSTALLED++))
    else
        warning " ✗ Failed to install f2b-anomaly-detection.local"
    fi
fi

echo ""

################################################################################
# STEP 4: INSTALL FILTERS (IDEMPOTENT)
################################################################################

if [[ -n "$FILTERSDIR" && $FILTERCOUNT -gt 0 ]]; then
    log "Step 4/8: Installing filters (idempotent with backup)..."
    echo ""
    
    INSTALLEDFILTERS=0
    SKIPPEDFILTERS=0
    
    while IFS= read -r filterfile; do
        FILTERNAME=$(basename "$filterfile")
        
        # Skip if source is not readable
        if [[ ! -f "$filterfile" ]]; then
            warning " Skipping $FILTERNAME (source not found)"
            ((SKIPPEDFILTERS++))
            continue
        fi
        
        TARGET="/etc/fail2ban/filter.d/$FILTERNAME"
        
        # Backup existing filter if it exists
        if [[ -f "$TARGET" ]]; then
            BACKUP="/etc/fail2ban/filter.d/${FILTERNAME}.backup-$(date +%Y%m%d-%H%M%S)"
            if sudo cp "$TARGET" "$BACKUP" 2>/dev/null; then
                info " ↪ Backed up: $FILTERNAME"
            else
                warning " ↪ Backup failed for $FILTERNAME (continuing)"
            fi
        fi
        
        # Copy filter with sudo
        if sudo cp "$filterfile" "$TARGET" 2>/dev/null; then
            sudo chown root:root "$TARGET" 2>/dev/null || warning " ↪ chown failed for $FILTERNAME"
            sudo chmod 644 "$TARGET" 2>/dev/null || warning " ↪ chmod failed for $FILTERNAME"
            log " ✓ Installed: $FILTERNAME"
            ((INSTALLEDFILTERS++))
        else
            warning " ✗ Failed to install $FILTERNAME"
            ((SKIPPEDFILTERS++))
        fi
        
    done < <(find "$FILTERSDIR" -maxdepth 1 -type f -name "*.conf" 2>/dev/null)
    
    echo ""
    
    if [[ $INSTALLEDFILTERS -gt 0 ]]; then
        log "Installed/updated: $INSTALLEDFILTERS filters"
    fi
    
    if [[ $SKIPPEDFILTERS -gt 0 ]]; then
        warning "Skipped: $SKIPPEDFILTERS filters"
    fi
    
else
    info "Step 4/8: No filters to install (skipped)"
fi

echo ""

################################################################################
# STEP 5: CREATE MANUALBLOCK.LOG
################################################################################

log "Step 5/8: Checking manualblock.log..."

if grep -q "logpath.*manualblock.log" /etc/fail2ban/jail.local 2>/dev/null; then
    if [[ ! -f /etc/fail2ban/manualblock.log ]]; then
        sudo touch /etc/fail2ban/manualblock.log
        sudo chmod 644 /etc/fail2ban/manualblock.log
        log "Created /etc/fail2ban/manualblock.log"
    else
        info "manualblock.log already exists"
    fi
else
    info "manualblock jail not configured (skip)"
fi

echo ""

################################################################################
# STEP 6: VALIDATE CONFIGURATION
################################################################################

log "Step 6/8: Validating Fail2Ban configuration..."

# Check if fail2ban service exists
if ! systemctl list-unit-files | grep -q "fail2ban.service"; then
    warning "fail2ban service not found - validation skipped"
else
    # Try validation
    if sudo fail2ban-client -t &> /dev/null; then
        log "Configuration syntax OK ✓"
    else
        error "Configuration syntax error! Check /var/log/fail2ban.log"
    fi
fi

echo ""

################################################################################
# STEP 7: RESTART FAIL2BAN
################################################################################

log "Step 7/8: Restarting Fail2Ban service..."

# Check if fail2ban is running
if systemctl is-active --quiet fail2ban; then
    info "fail2ban is running - restarting..."
    if sudo systemctl restart fail2ban; then
        log "Fail2Ban restarted successfully"
    else
        error "Failed to restart Fail2Ban - check journalctl -xeu fail2ban"
    fi
else
    info "fail2ban is not running - starting..."
    if sudo systemctl start fail2ban; then
        log "Fail2Ban started successfully"
    else
        error "Failed to start Fail2Ban - check journalctl -xeu fail2ban"
    fi
fi

# Wait for fail2ban to start
sleep 3

# Verify service is active
if systemctl is-active --quiet fail2ban; then
    log "Fail2Ban is active ✓"
else
    error "Fail2Ban failed to start - check journalctl -xeu fail2ban"
fi

echo ""

################################################################################
# STEP 8: VERIFY JAILS
################################################################################

log "Step 8/8: Verifying active jails..."
echo ""

JAILLIST=$(sudo fail2ban-client status 2>/dev/null | grep "Jail list" | sed 's/.*://' || echo "")

if [[ -z "$JAILLIST" ]]; then
    warning "No jails detected! Check configuration."
    info "Run: sudo fail2ban-client -t"
    info "Check: sudo journalctl -xeu fail2ban"
else
    echo "Active jails:"
    echo "$JAILLIST" | tr ',' '\n' | sed 's/^/ ✓ /' | sed 's/^[ \t]*/   /'
    echo ""
    
    JAILCOUNT=$(echo "$JAILLIST" | tr ',' '\n' | wc -l)
    log "Total active jails: $JAILCOUNT"
fi

echo ""

################################################################################
# VERIFY NFTABLES INTEGRATION
################################################################################

log "Verifying nftables integration..."
echo ""

NFTABLESJAILS=$(grep -c "banaction.*nftables" /etc/fail2ban/jail.local 2>/dev/null || echo "0")

echo "Jails with nftables banaction: $NFTABLESJAILS"

if [[ $NFTABLESJAILS -ge 8 ]]; then
    log "✓ Majority of jails using nftables!"
else
    warning "Some jails might use different banaction"
fi

echo ""

################################################################################
# SUMMARY
################################################################################

echo ""
echo "═══════════════════════════════════════════════════════"
log "Installation Summary"
echo "═══════════════════════════════════════════════════════"
echo ""

log "• jail.local: Installed (/etc/fail2ban/jail.local)"

if [[ $ADDITIONAL_INSTALLED -gt 0 ]]; then
    log "• Additional configs: $ADDITIONAL_INSTALLED installed"
fi

if [[ -n "$FILTERSDIR" && $INSTALLEDFILTERS -gt 0 ]]; then
    log "• Filters: $INSTALLEDFILTERS installed/updated"
fi

if [[ -n "$JAILCOUNT" && $JAILCOUNT -gt 0 ]]; then
    log "• Active jails: $JAILCOUNT"
else
    warning "• Active jails: UNKNOWN (check logs)"
fi

log "• Service: Running"

echo ""

# Expected jails list
echo "Expected jails in v0.22:"
echo " 1. sshd"
echo " 2. sshd-slowattack"
echo " 3. f2b-exploit-critical"
echo " 4. f2b-dos-high"
echo " 5. f2b-web-medium"
echo " 6. nginx-recon-bonus"
echo " 7. recidive"
echo " 8. manualblock"
echo " 9. f2b-fuzzing-payloads"
echo " 10. f2b-botnet-signatures"
echo " 11. f2b-anomaly-detection"
echo ""

if [[ -n "$JAILCOUNT" && $JAILCOUNT -eq 11 ]]; then
    log "✓ All 11 expected jails are active!"
elif [[ -n "$JAILCOUNT" ]]; then
    warning "Expected 11 jails, found $JAILCOUNT"
    echo ""
    echo "Troubleshooting:"
    echo " • Check logs: sudo tail -f /var/log/fail2ban.log"
    echo " • Test config: sudo fail2ban-client -t"
    echo " • Check status: sudo fail2ban-client status"
fi

echo ""
echo "═══════════════════════════════════════════════════════"
info "Next Steps:"
echo "═══════════════════════════════════════════════════════"
echo ""

echo "1. Check jail status:"
echo "   sudo fail2ban-client status"
echo ""

echo "2. View specific jail:"
echo "   sudo fail2ban-client status sshd"
echo ""

echo "3. Monitor logs:"
echo "   sudo tail -f /var/log/fail2ban.log"
echo ""

echo "4. Continue with installation:"
echo "   sudo bash scripts/03-install-docker-block-v04.sh"
echo ""

log "Fail2Ban jails installed successfully!"
echo ""

