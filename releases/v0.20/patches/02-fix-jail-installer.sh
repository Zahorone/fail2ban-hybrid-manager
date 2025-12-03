#!/bin/bash
echo "Fixing 02-install-jails.sh..."

cat > ../02-install-jails.sh << 'EOFSCRIPT'
#!/bin/bash
set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log() { echo -e "${GREEN}[OK]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }
warning() { echo -e "${YELLOW}[WARN]${NC} $1"; }
info() { echo -e "${BLUE}[INFO]${NC} $1"; }

echo ""
echo "═══════════════════════════════════════════════════════"
echo "  Fail2Ban Jail Configuration Installation v0.19"
echo "═══════════════════════════════════════════════════════"
echo ""

[[ $EUID -ne 0 ]] && error "Please run with sudo"

SCRIPTDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Find jail.local
JAILLOCAL=""
if [[ -f "$SCRIPTDIR/jail.local" ]]; then
    JAILLOCAL="$SCRIPTDIR/jail.local"
elif [[ -f "$SCRIPTDIR/config/jail.local" ]]; then
    JAILLOCAL="$SCRIPTDIR/config/jail.local"
else
    error "jail.local not found"
fi

info "Found jail.local: $JAILLOCAL"

# Find filters
FILTERSDIR=""
if [[ -d "$SCRIPTDIR/filters" ]]; then
    FILTERSDIR="$SCRIPTDIR/filters"
elif [[ -d "$SCRIPTDIR/config/filters" ]]; then
    FILTERSDIR="$SCRIPTDIR/config/filters"
fi

if [[ -n "$FILTERSDIR" ]]; then
    FILTERCOUNT=$(find "$FILTERSDIR" -name "*.conf" 2>/dev/null | wc -l)
    info "Found $FILTERCOUNT filter files"
fi

echo ""
read -p "Continue? [yes/no]: " -r
[[ ! $REPLY =~ ^[Yy]es$ ]] && exit 0
echo ""

# Backup jail.local
if [[ -f /etc/fail2ban/jail.local ]]; then
    BACKUP="/etc/fail2ban/jail.local.backup-$(date +%Y%m%d-%H%M)"
    cp /etc/fail2ban/jail.local "$BACKUP"
    log "Backup: $BACKUP"
fi

# Copy jail.local
cp "$JAILLOCAL" /etc/fail2ban/jail.local
chown root:root /etc/fail2ban/jail.local
chmod 644 /etc/fail2ban/jail.local
log "Installed jail.local"

# Copy filters
if [[ -n "$FILTERSDIR" ]]; then
    while IFS= read -r filterfile; do
        FILTERNAME=$(basename "$filterfile")
        cp "$filterfile" /etc/fail2ban/filter.d/ 2>/dev/null || true
        chown root:root "/etc/fail2ban/filter.d/$FILTERNAME" 2>/dev/null || true
        chmod 644 "/etc/fail2ban/filter.d/$FILTERNAME" 2>/dev/null || true
        log "Installed: $FILTERNAME"
    done < <(find "$FILTERSDIR" -name "*.conf" 2>/dev/null)
fi

# Create manualblock log
if grep -q "fail2ban-blocked-ips.txt" "$JAILLOCAL" 2>/dev/null; then
    touch /var/log/fail2ban-blocked-ips.txt
    chmod 644 /var/log/fail2ban-blocked-ips.txt
    log "Created manualblock log"
fi

# Validate
fail2ban-client -t &>/dev/null || error "Configuration error!"
log "Configuration OK"

# Restart
systemctl restart fail2ban
sleep 3
systemctl is-active --quiet fail2ban || error "Fail2Ban failed to start"
log "Fail2Ban restarted"

# Verify jails
JAILCOUNT=$(fail2ban-client status 2>/dev/null | grep -oP '\d+(?= jail)' || echo 0)
log "Active jails: $JAILCOUNT"

[[ $JAILCOUNT -ne 10 ]] && warning "Expected 10 jails, got $JAILCOUNT"

log "Installation complete!"
EOFSCRIPT

chmod +x ../02-install-jails.sh
echo "✅ 02-install-jails.sh fixed"
