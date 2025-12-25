#!/bin/bash
set -e
################################################################################
# Auto-Sync Service Installer (Fail2Ban ↔ nftables)
# Component: INSTALL-AUTO-SYNC
# Part of: Fail2Ban Hybrid Nftables Manager
################################################################################

# shellcheck disable=SC2034  # Metadata used for release tracking
RELEASE="v0.31"
# shellcheck disable=SC2034
VERSION="0.31"
# shellcheck disable=SC2034
BUILD_DATE="2025-12-26"
# shellcheck disable=SC2034
COMPONENT_NAME="INSTALL-AUTO-SYNC"
# shellcheck disable=SC2034
RED='\033[0;31m'
# shellcheck disable=SC2034
GREEN='\033[0;32m'
# shellcheck disable=SC2034
YELLOW='\033[1;33m'
# shellcheck disable=SC2034
BLUE='\033[0;34m'
# shellcheck disable=SC2034 
NC='\033[0m'

log()      { echo -e "${GREEN}✓${NC} $1"; }
error()    { echo -e "${RED}✗${NC} $1"; exit 1; }
warning()  { echo -e "${YELLOW}⚠${NC} $1"; }
info()     { echo -e "${BLUE}ℹ${NC} $1"; }

echo ""
echo "╔════════════════════════════════════════════════════════════╗"
echo "║  Auto-Sync Service Installer (Fail2Ban ↔ nftables)         ║"
echo "║  Release ${RELEASE}                                        ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""


# Všetky jaily
JAILS=(
    "sshd"
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

# Mapping jail → nft set
declare -A SET_MAP=(
    [sshd]="f2b-sshd"
    [f2b-exploit-critical]="f2b-exploit-critical"
    [f2b-dos-high]="f2b-dos-high"
    [f2b-web-medium]="f2b-web-medium"
    [nginx-recon-bonus]="f2b-nginx-recon-bonus"
    [recidive]="f2b-recidive"
    [manualblock]="f2b-manualblock"
    [f2b-fuzzing-payloads]="f2b-fuzzing-payloads"
    [f2b-botnet-signatures]="f2b-botnet-signatures"
    [f2b-anomaly-detection]="f2b-anomaly-detection"
)

TOTAL_ADDED=0

info "Starting sync for ${#JAILS[@]} jails..."
echo ""

for jail in "${JAILS[@]}"; do
    SET="${SET_MAP[$jail]}"
    
    # Zoznam IP z Fail2Ban (robustnejší)
    IPS=$(sudo fail2ban-client get "$jail" banned 2>/dev/null || sudo fail2ban-client status "$jail" 2>/dev/null | grep "Banned IP list:" | sed 's/.*Banned IP list://' | tr ' ' '\n' | grep -E '^[0-9a-fA-F:.]')
    
    if [ -z "$IPS" ]; then
        info "$jail: žiadne IP (prázdny jail)"
        continue
    fi
    
    COUNT=$(echo "$IPS" | grep -c '^' 2>/dev/null || echo 0)
    info "$jail: $COUNT IP to sync"
    
    # Pridaj do nftables setu
    while read -r IP; do
        if [ -z "$IP" ]; then
            continue
        fi
        
        # Detect IPv4 vs IPv6
        if echo "$IP" | grep -q ':'; then
            # IPv6
            TARGET_SET="$SET-v6"
        else
            # IPv4
            TARGET_SET="$SET"
        fi
        
        # Overenie či už existuje
        if ! sudo nft list set inet fail2ban-filter "$TARGET_SET" 2>/dev/null | grep -q "{ $IP"; then
            if sudo nft add element inet fail2ban-filter "$TARGET_SET" "{ $IP }" 2>/dev/null; then
                ((TOTAL_ADDED++))
                echo "  ✓ $IP → $TARGET_SET"
            else
                echo "  ✗ $IP → $TARGET_SET (failed)"
            fi
        fi
    done <<< "$IPS"
done

echo ""
log "SYNC COMPLETE: Pridaných $TOTAL_ADDED IP do nftables"
echo ""

################################################################################
# VERIFIKÁCIA
################################################################################

info "Verifying sync..."
echo ""

MISMATCH=0

for jail in "${JAILS[@]}"; do
    # Fail2Ban count
    F2B_COUNT=$(sudo fail2ban-client status "$jail" 2>/dev/null | grep "Currently banned" | grep -oE "[0-9]+" | head -1)
    [ -z "$F2B_COUNT" ] && F2B_COUNT=0
    
    SET="${SET_MAP[$jail]}"
    
    # nftables count (IPv4) - FIXED: robustnejší counting
    NFT_COUNT_V4=$(sudo nft list set inet fail2ban-filter "$SET" 2>/dev/null | sed -n '/elements = {/,/}/p' | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | wc -l)
    
    # nftables count (IPv6) - FIXED: robustnejší counting
    NFT_COUNT_V6=$(sudo nft list set inet fail2ban-filter "$SET-v6" 2>/dev/null | sed -n '/elements = {/,/}/p' | grep -oE '([0-9a-fA-F:]*:[0-9a-fA-F:]+)' | wc -l)
    
    NFT_COUNT=$((NFT_COUNT_V4 + NFT_COUNT_V6))
    
    if [ "$F2B_COUNT" -eq "$NFT_COUNT" ]; then
        log "$jail: F2B=$F2B_COUNT, nft=$NFT_COUNT (v4:$NFT_COUNT_V4, v6:$NFT_COUNT_V6) ✓"
    else
        warn "$jail: F2B=$F2B_COUNT, nft=$NFT_COUNT (v4:$NFT_COUNT_V4, v6:$NFT_COUNT_V6) ⚠"
        ((MISMATCH++))
    fi
done

echo ""

if [ "$MISMATCH" -eq 0 ]; then
    log "✅ All jails synchronized perfectly!"
else
    warn "⚠️  $MISMATCH jail(s) have minor mismatches (may be timing issue)"
    info "Run: f2b sync force (from wrapper) to re-sync if needed"
fi

echo ""
echo "══════════════════════════════════════════════════════════"
log "Initial sync complete!"
echo "══════════════════════════════════════════════════════════"
echo ""
echo "For scheduled syncs, configure crontab:"
echo "  sudo nano /etc/cron.d/f2b-silent-tasks"
echo ""
echo "Example cron entries:"
echo " # Full Fail2Ban ↔ nftables resync (optional safety net)"
echo " */30 * * * * root /usr/local/bin/f2b sync force > /dev/null 2>&1"
echo " # Periodic audit report (optional)"
echo " 0 */6 * * * root /usr/local/bin/f2b audit-silent > /dev/null 2>&1"
echo ""

