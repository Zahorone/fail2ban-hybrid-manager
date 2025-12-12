#!/bin/bash

# Verify jail.local + jails + nftables integration (v0.22)

echo "==============================================================="
echo " JAIL.LOCAL CONFIGURATION CHECK"
echo "==============================================================="
echo ""

echo "1. DEFAULT banaction / action:"
sudo grep -A 8 "^\[DEFAULT\]" /etc/fail2ban/jail.local | grep -E "chain|banaction|action" || echo "  (DEFAULT section not found)"
echo ""

echo "2. Jail-specific settings (critical jails):"
echo ""

echo " [sshd]"
sudo grep -A 8 "^\[sshd\]" /etc/fail2ban/jail.local | grep -E "enabled|filter|logpath|banaction" || echo "  (sshd jail not found in jail.local)"
echo ""

echo " [sshd-slowattack]"
sudo grep -A 8 "^\[sshd-slowattack\]" /etc/fail2ban/jail.local | grep -E "enabled|filter|logpath|banaction" || echo "  (sshd-slowattack jail not found in jail.local)"
echo ""

echo " [f2b-dos-high]"
sudo grep -A 8 "^\[f2b-dos-high\]" /etc/fail2ban/jail.local | grep -E "enabled|filter|logpath|banaction" || echo "  (f2b-dos-high jail not found in jail.local)"
echo ""

echo " [f2b-exploit-critical]"
sudo grep -A 8 "^\[f2b-exploit-critical\]" /etc/fail2ban/jail.local | grep -E "enabled|filter|logpath|banaction" || echo "  (f2b-exploit-critical jail not found in jail.local)"
echo ""

echo " [f2b-anomaly-detection]"
sudo grep -A 8 "^\[f2b-anomaly-detection\]" /etc/fail2ban/jail.local | grep -E "enabled|filter|logpath|banaction" || echo "  (f2b-anomaly-detection jail not found in jail.local)"
echo ""

echo "==============================================================="
echo " FAIL2BAN RUNTIME STATUS"
echo "==============================================================="
echo ""

echo "3. Fail2Ban jail list (active):"
if sudo fail2ban-client status &>/dev/null; then
    sudo fail2ban-client status | grep "Jail list" || echo "  (no jails loaded)"
else
    echo "  fail2ban-client status failed (service not running?)"
fi
echo ""

echo "4. Number of active jails:"
TOTAL_JAILS=$(sudo fail2ban-client status 2>/dev/null | grep -oP 'Number of jail:\s+\K\d+' || echo 0)
echo "  Total active jails: $TOTAL_JAILS"
echo ""

echo "5. Sample jail detail (f2b-dos-high):"
if sudo fail2ban-client status f2b-dos-high &>/dev/null; then
    sudo fail2ban-client status f2b-dos-high | head -10
else
    echo "  Jail f2b-dos-high not found or not loaded (might be config error)"
fi
echo ""

echo "==============================================================="
echo " NFTABLES INTEGRATION"
echo "==============================================================="
echo ""

echo "6. nftables table verification:"
sudo nft list tables 2>/dev/null | grep fail2ban || echo "  (no fail2ban-related nftables table found)"
echo ""

echo "7. fail2ban-filter table structure (first 20 lines):"
sudo nft list table inet fail2ban-filter 2>/dev/null | head -20 || echo "  (inet fail2ban-filter table not found)"
echo ""

echo "==============================================================="
echo " CONFIGURATION ANALYSIS"
echo "==============================================================="
echo ""

# Count jails using nftables-multiport in jail.local
NFTABLES_JAILS=$(sudo grep -E "banaction\s*=\s*nftables-multiport" /etc/fail2ban/jail.local 2>/dev/null | wc -l || echo 0)

echo "Jails with banaction = nftables-multiport (from jail.local): $NFTABLES_JAILS"
echo "Total active jails (from fail2ban-client):                  $TOTAL_JAILS"
echo ""

if [ "$TOTAL_JAILS" -gt 0 ] && [ "$NFTABLES_JAILS" -eq "$TOTAL_JAILS" ]; then
    echo "✅ ALL ACTIVE JAILS use nftables-multiport"
    echo "✅ chain = INPUT in [DEFAULT] is effectively ignored"
    echo "✅ Configuration looks consistent"
else
    echo "⚠️ Not all active jails use nftables-multiport"
    echo "⚠️ Some jails may still rely on DEFAULT banaction"
fi

echo ""
echo "RECOMMENDATION:"
echo " - Ensure all production jails use:  banaction = nftables-multiport"
echo " - Check suspicious jails via:      sudo fail2ban-client status <jail>"
echo " - For deeper debug:                sudo tail -f /var/log/fail2ban.log"
echo ""

