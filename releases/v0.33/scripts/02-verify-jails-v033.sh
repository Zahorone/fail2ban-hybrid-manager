#!/bin/bash
set -e

################################################################################
# Component: VERIFY-JAILS
# Part of: Fail2Ban Hybrid Nftables Manager
################################################################################

# shellcheck disable=SC2034  # Metadata used for release tracking
RELEASE="v0.33"
# shellcheck disable=SC2034
VERSION="0.33"
# shellcheck disable=SC2034
BUILD_DATE="2026-01-01"
# shellcheck disable=SC2034
COMPONENT_NAME="VERIFY-JAILS"

# Colors
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

log_header()  { echo -e "${BLUE}$1${NC}"; }
log_success() { echo -e "${GREEN}✓${NC} $1"; }
log_error()   { echo -e "${RED}✗${NC} $1"; }
log_info()    { echo -e "${BLUE}ℹ${NC} $1"; }
log_warn()    { echo -e "${YELLOW}⚠${NC} $1"; }

echo ""
echo "╔════════════════════════════════════════════════════════════╗"
echo "║                                                            ║"
echo "║ Fail2Ban Configuration Verification ${RELEASE}             ║"
echo "║ jail.local + filters + actions + nftables integration      ║"
echo "║                                                            ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

################################################################################
# SECTION 1: CONFIGURATION FILES CHECK
################################################################################
log_header "═══════════════════════════════════════════════════════════"
log_header " SECTION 1: CONFIGURATION FILES CHECK"
log_header "═══════════════════════════════════════════════════════════"
echo ""

# 1.1 jail.local
log_info "1.1 Checking /etc/fail2ban/jail.local"
if [ -f /etc/fail2ban/jail.local ]; then
    log_success "jail.local exists"
    FILESIZE=$(stat -f%z /etc/fail2ban/jail.local 2>/dev/null || stat -c%s /etc/fail2ban/jail.local)
    log_info "  Size: $FILESIZE bytes"
else
    log_error "jail.local NOT FOUND!"
    exit 1
fi
echo ""

# 1.2 Filter files
log_info "1.2 Checking filter files in /etc/fail2ban/filter.d/"

# Expected filters (customize based on your jails)
EXPECTED_FILTERS=(
    "recidive.conf"
    "sshd.conf"
    "nginx-4xx.conf"
    "nginx-limit-req.conf"
)

MISSING_FILTERS=0
for filter in "${EXPECTED_FILTERS[@]}"; do
    if [ -f "/etc/fail2ban/filter.d/$filter" ]; then
        echo -n "  ✓ $filter ... "
        echo "exists"
    else
        echo -n "  ✗ $filter ... "
        echo "MISSING"
        ((MISSING_FILTERS++))
    fi
done

if [ "$MISSING_FILTERS" -eq 0 ]; then
    log_success "All expected filters present"
else
    log_warn "$MISSING_FILTERS filter(s) missing"
fi
echo ""

# 1.3 Action files
log_info "1.3 Checking action files in /etc/fail2ban/action.d/"

# Critical actions
CRITICAL_ACTIONS=(
"nftables-multiport.conf"
"nftables-recidive.conf"
"docker-sync-hook.conf"
)

MISSING_ACTIONS=0
for action in "${CRITICAL_ACTIONS[@]}"; do
    if [ -f "/etc/fail2ban/action.d/$action" ]; then
        echo -n "  ✓ $action ... "
        # Check timeout in action file
        if [ "$action" = "nftables-recidive.conf" ]; then
            if grep -q "2592000s" "/etc/fail2ban/action.d/$action" 2>/dev/null; then
                echo "exists (30d timeout ✓)"
            else
                echo "exists (⚠ timeout mismatch)"
            fi
        else
            if grep -q "604800s" "/etc/fail2ban/action.d/$action" 2>/dev/null; then
                echo "exists (7d timeout ✓)"
            else
                echo "exists (⚠ timeout mismatch)"
            fi
        fi
    else
        echo -n "  ✗ $action ... "
        echo "MISSING"
        ((MISSING_ACTIONS++))
    fi
done

if [ "$MISSING_ACTIONS" -eq 0 ]; then
    log_success "All critical actions present"
else
    log_error "$MISSING_ACTIONS action(s) missing!"
fi
echo ""

# 1.4 Docker-sync-hook integration
log_info "1.4 Checking docker-sync-hook integration:"

# Check action conf
if [ -f /etc/fail2ban/action.d/docker-sync-hook.conf ]; then
    log_success "docker-sync-hook.conf present"
else
    log_error "docker-sync-hook.conf NOT FOUND - docker sync will not work"
    ((MISSING_ACTIONS++))
fi

# Check helper script
if [ -f /usr/local/sbin/f2b-docker-hook ]; then
    echo -n " ✓ /usr/local/sbin/f2b-docker-hook ... "
    if [ -x /usr/local/sbin/f2b-docker-hook ]; then
        echo "executable ✓"
    else
        echo "NOT executable ✗"
        log_warn "Run: sudo chmod 0755 /usr/local/sbin/f2b-docker-hook"
    fi
else
    log_error "/usr/local/sbin/f2b-docker-hook NOT FOUND"
    log_info "Docker-sync-hook will not work without the helper script"
fi

# Check if conf references correct path
if [ -f /etc/fail2ban/action.d/docker-sync-hook.conf ]; then
    if grep -q "/usr/local/sbin/f2b-docker-hook" /etc/fail2ban/action.d/docker-sync-hook.conf 2>/dev/null; then
        log_success "docker-sync-hook.conf references correct helper path"
    else
        log_warn "docker-sync-hook.conf does not reference /usr/local/sbin/f2b-docker-hook"
    fi
fi

echo ""

################################################################################
# SECTION 2: JAIL.LOCAL CONFIGURATION ANALYSIS
################################################################################
log_header "═══════════════════════════════════════════════════════════"
log_header " SECTION 2: JAIL.LOCAL CONFIGURATION ANALYSIS"
log_header "═══════════════════════════════════════════════════════════"
echo ""

# 2.1 DEFAULT section
log_info "2.1 DEFAULT banaction/action:"
sudo grep -A 8 "^\[DEFAULT\]" /etc/fail2ban/jail.local | grep -E "chain|banaction|action" || log_warn "  (DEFAULT section not found or no banaction specified)"
echo ""

# 2.2 Critical jails configuration
log_info "2.2 Jail-specific banaction settings:"
echo ""

# List of all expected jails
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

MULTIPORT_COUNT=0
RECIDIVE_COUNT=0
MISSING_JAILS=0

for jail in "${JAILS[@]}"; do
    echo "  [$jail]"
    if sudo grep -q "^\[$jail\]" /etc/fail2ban/jail.local 2>/dev/null; then
        ENABLED=$(sudo grep -A 3 "^\[$jail\]" /etc/fail2ban/jail.local | grep "enabled" | awk '{print $3}')
        BANACTION=$(sudo grep -A 10 "^\[$jail\]" /etc/fail2ban/jail.local | grep "^banaction" | awk '{print $3}')
        
        echo -n "    enabled: $ENABLED"
        if [ "$ENABLED" = "true" ]; then
            echo " ✓"
        else
            echo " (disabled)"
        fi
        
        if [ -n "$BANACTION" ]; then
            echo -n "    banaction: $BANACTION"
            
            # Check expected banaction
            if [ "$jail" = "recidive" ]; then
                # Recidive should use nftables-recidive
                if echo "$BANACTION" | grep -q "nftables-recidive"; then
                    echo " ✓ (correct - 30d)"
                    ((RECIDIVE_COUNT++))
                else
                    echo " ✗ (expected nftables-recidive)"
                fi
            else
                # Other jails should use nftables-multiport
                if echo "$BANACTION" | grep -q "nftables-multiport"; then
                    echo " ✓ (correct - 7d)"
                    ((MULTIPORT_COUNT++))
                else
                    echo " ⚠ (expected nftables-multiport)"
                fi
            fi
        else
            echo "    banaction: (not specified, using DEFAULT)"
            if [ "$jail" != "recidive" ]; then
                ((MULTIPORT_COUNT++))
            fi
        fi
    else
        log_warn "    Jail not found in jail.local"
        ((MISSING_JAILS++))
    fi
    echo ""
done

# Summary
echo ""
log_info "Banaction Statistics:"
echo "  - nftables-multiport (7d): $MULTIPORT_COUNT jails"
echo "  - nftables-recidive (30d): $RECIDIVE_COUNT jail (expected: 1)"
echo "  - Missing jails: $MISSING_JAILS"
echo ""

if [ "$RECIDIVE_COUNT" -eq 1 ] && [ "$MULTIPORT_COUNT" -gt 0 ]; then
    log_success "Banaction configuration is CORRECT"
    log_info "  ✓ Recidive uses nftables-recidive (30d timeout)"
    log_info "  ✓ Other jails use nftables-multiport (7d timeout)"
else
    log_warn "Banaction configuration needs review"
    if [ "$RECIDIVE_COUNT" -ne 1 ]; then
        log_error "  ✗ Recidive jail: expected 1, found $RECIDIVE_COUNT"
    fi
fi
echo ""

################################################################################
# SECTION 3: FAIL2BAN RUNTIME STATUS
################################################################################
log_header "═══════════════════════════════════════════════════════════"
log_header " SECTION 3: FAIL2BAN RUNTIME STATUS"
log_header "═══════════════════════════════════════════════════════════"
echo ""

log_info "3.1 Fail2Ban service status:"
if systemctl is-active --quiet fail2ban; then
    log_success "Fail2Ban is RUNNING"
else
    log_error "Fail2Ban is NOT RUNNING!"
fi
echo ""

log_info "3.2 Active jails:"
if sudo fail2ban-client status &>/dev/null; then
    sudo fail2ban-client status | grep "Jail list:" || log_warn "  (no jails loaded)"
    echo ""
    
    TOTAL_JAILS=$(sudo fail2ban-client status 2>/dev/null | grep -oP 'Number of jail:\s+\K\d+' || echo 0)
    log_info "Total active jails: $TOTAL_JAILS"
else
    log_error "fail2ban-client status failed"
fi
echo ""

log_info "3.3 Sample jail details:"
echo ""

# Check recidive jail specifically
if sudo fail2ban-client status recidive &>/dev/null; then
    echo "  [recidive] - 30d ban jail"
    sudo fail2ban-client status recidive | head -8 | sed 's/^/    /'
else
    log_warn "  Recidive jail not active"
fi
echo ""

# Check another sample jail
if sudo fail2ban-client status f2b-dos-high &>/dev/null; then
    echo "  [f2b-dos-high] - 7d ban jail"
    sudo fail2ban-client status f2b-dos-high | head -8 | sed 's/^/    /'
elif sudo fail2ban-client status sshd &>/dev/null; then
    echo "  [sshd] - 7d ban jail"
    sudo fail2ban-client status sshd | head -8 | sed 's/^/    /'
fi
echo ""

################################################################################
# SECTION 4: NFTABLES INTEGRATION
################################################################################
log_header "═══════════════════════════════════════════════════════════"
log_header " SECTION 4: NFTABLES INTEGRATION"
log_header "═══════════════════════════════════════════════════════════"
echo ""

log_info "4.1 nftables tables:"
sudo nft list tables 2>/dev/null | grep fail2ban || log_warn "  (no fail2ban-related nftables tables found)"
echo ""

log_info "4.2 fail2ban-filter table structure:"
if sudo nft list table inet fail2ban-filter &>/dev/null; then
    log_success "Table inet fail2ban-filter exists"
    
    # Count sets
    SETS_COUNT=$(sudo nft list sets inet fail2ban-filter 2>/dev/null | grep -c "name" || echo 0)
    echo "  Sets found: $SETS_COUNT / 24 expected (12 IPv4 + 12 IPv6)"
    
    # Check INPUT chain
    INPUT_RULES=$(sudo nft list chain inet fail2ban-filter f2b-input 2>/dev/null | grep -c "drop" || echo 0)
    echo "  INPUT rules: $INPUT_RULES / 24 expected"
    
    # Check FORWARD chain
    FORWARD_RULES=$(sudo nft list chain inet fail2ban-filter f2b-forward 2>/dev/null | grep -c "drop" || echo 0)
    echo "  FORWARD rules: $FORWARD_RULES / 8 expected (4 critical jails × 2 protocols)"
else
    log_error "Table inet fail2ban-filter NOT FOUND!"
fi
echo ""

log_info "4.3 Recidive set verification (30d timeout):"
if sudo nft list set inet fail2ban-filter f2b-recidive &>/dev/null; then
    TIMEOUT=$(sudo nft list set inet fail2ban-filter f2b-recidive 2>/dev/null | grep "timeout" | sed 's/.*timeout //')
    echo "  f2b-recidive timeout: $TIMEOUT"
    if echo "$TIMEOUT" | grep -q "30d"; then
        log_success "Correct timeout (30d)"
    else
        log_warn "Expected 30d, found: $TIMEOUT"
    fi
    
    ELEMENTS=$(sudo nft list set inet fail2ban-filter f2b-recidive 2>/dev/null | grep -c "elements")

    if [ "$ELEMENTS" -gt 0 ]; then
        BANNED_COUNT=$(sudo nft list set inet fail2ban-filter f2b-recidive 2>/dev/null | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | wc -l)
        echo "  Banned IPs: $BANNED_COUNT"
    else
        echo "  Banned IPs: 0 (clean)"
    fi
else
    log_error "f2b-recidive set NOT FOUND!"
fi
echo ""

log_info "4.4 Sample multiport set verification (7d timeout):"
if sudo nft list set inet fail2ban-filter f2b-sshd &>/dev/null; then
    TIMEOUT=$(sudo nft list set inet fail2ban-filter f2b-sshd 2>/dev/null | grep "timeout" | sed 's/.*timeout //')
    echo "  f2b-sshd timeout: $TIMEOUT"
    if echo "$TIMEOUT" | grep -q "7d"; then
        log_success "Correct timeout (7d)"
    else
        log_warn "Expected 7d, found: $TIMEOUT"
    fi
else
    log_warn "f2b-sshd set not found"
fi

loginfo "4.5 Checking for legacy addr-set-* sets (must be ZERO)"
if sudo nft list table inet fail2ban-filter 2>/dev/null | grep -q "addr-set-"; then
    logwarn "Found legacy addr-set-* sets -> split brain risk"
else
    logsuccess "No addr-set-* sets found"
fi

echo ""

################################################################################
# SECTION 5: FORWARD CHAIN VERIFICATION (Backend Protection)
################################################################################
log_header "═══════════════════════════════════════════════════════════"
log_header " SECTION 5: FORWARD CHAIN (Backend Protection)"
log_header "═══════════════════════════════════════════════════════════"
echo ""

log_info "5.1 FORWARD chain rules (protecting Apache2, MariaDB):"
if sudo nft list chain inet fail2ban-filter f2b-forward &>/dev/null; then
    # Check for critical sets in FORWARD
    FORWARD_CRITICAL_SETS=("f2b-exploit-critical" "f2b-dos-high" "f2b-manualblock" "f2b-recidive")
    
    for set in "${FORWARD_CRITICAL_SETS[@]}"; do
        if sudo nft list chain inet fail2ban-filter f2b-forward 2>/dev/null | grep -q "@$set"; then
            echo "  ✓ $set in FORWARD chain"
        else
            echo "  ✗ $set NOT in FORWARD chain"
        fi
    done
    
    echo ""
    if sudo nft list chain inet fail2ban-filter f2b-forward 2>/dev/null | grep -q "@f2b-recidive"; then
        log_success "Recidive is protected in FORWARD chain ✓"
        log_info "  Backend services (Apache2, MariaDB) are protected from recidivists"
    else
        log_warn "Recidive is NOT in FORWARD chain"
    fi
else
    log_error "FORWARD chain NOT FOUND!"
fi
echo ""

################################################################################
# SECTION 6: CONFIGURATION CONSISTENCY CHECK
################################################################################
log_header "═══════════════════════════════════════════════════════════"
log_header " SECTION 6: CONFIGURATION CONSISTENCY CHECK"
log_header "═══════════════════════════════════════════════════════════"
echo ""

# Summary check
ISSUES=0

echo "Checking configuration consistency..."
echo ""

# Check 1: All jails in jail.local are active
if [ "$TOTAL_JAILS" -lt 11 ]; then
    log_warn "Only $TOTAL_JAILS jails active (expected: 11-12 for full profile)"
    ((ISSUES++))
else
    log_success "$TOTAL_JAILS jails active"
fi

# Check 2: Banaction consistency
if [ "$RECIDIVE_COUNT" -eq 1 ] && [ "$MULTIPORT_COUNT" -ge 9 ]; then
    log_success "Banaction configuration consistent"
else
    log_warn "Banaction configuration inconsistent"
    ((ISSUES++))
fi

# Check 3: nftables sets match jails
if [ "$SETS_COUNT" -eq 24 ]; then
    log_success "All nftables sets present (24/24)"
else
    log_warn "nftables sets incomplete ($SETS_COUNT/24)"
    ((ISSUES++))
fi

# Check 4: FORWARD chain protection
if [ "$FORWARD_RULES" -eq 8 ]; then
    log_success "FORWARD chain fully configured (8/8)"
else
    log_warn "FORWARD chain incomplete ($FORWARD_RULES/8)"
    ((ISSUES++))
fi

echo ""

################################################################################
# FINAL SUMMARY
################################################################################
log_header "═══════════════════════════════════════════════════════════"
log_header " FINAL SUMMARY"
log_header "═══════════════════════════════════════════════════════════"
echo ""

if [ "$ISSUES" -eq 0 ] && [ "$MISSING_ACTIONS" -eq 0 ] && [ "$MISSING_FILTERS" -eq 0 ]; then
    log_success "✅ CONFIGURATION IS HEALTHY"
    echo ""
    echo "  ✓ All configuration files present"
    echo "  ✓ Banaction correctly configured (multiport + recidive)"
    echo "  ✓ nftables integration working"
    echo "  ✓ FORWARD chain protecting backend services"
    echo "  ✓ Recidive jail active (30d ban)"
    echo "  ✓ 12 jails (vrátane nginx-php-errors) nakonfigurovaných"
    echo "  ✓ 24 nftables setov (IPv4+IPv6) prítomných"
else
    log_warn "⚠️ CONFIGURATION HAS ISSUES"
    echo ""
    echo "  Issues found: $ISSUES"
    echo "  Missing actions: $MISSING_ACTIONS"
    echo "  Missing filters: $MISSING_FILTERS"
    echo ""
    echo "RECOMMENDATIONS:"
    echo "  1. Review jail.local configuration"
    echo "  2. Ensure nftables-multiport.conf exists (7d timeout)"
    echo "  3. Ensure nftables-recidive.conf exists (30d timeout)"
    echo "  4. Verify FORWARD chain rules for backend protection"
    echo "  5. Check fail2ban log: sudo tail -f /var/log/fail2ban.log"
fi

echo ""
echo "For deeper investigation:"
echo "  - Jail details: sudo fail2ban-client status <jail_name>"
echo "  - nftables dump: sudo nft list table inet fail2ban-filter"
echo "  - Live log: sudo tail -f /var/log/fail2ban.log"
echo ""

