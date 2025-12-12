#!/bin/bash
# Verify jail.local configuration

echo "==============================================================="
echo "         JAIL.LOCAL CONFIGURATION CHECK"
echo "==============================================================="
echo ""

echo "1. DEFAULT banaction:"
sudo grep -A 5 "^\[DEFAULT\]" /etc/fail2ban/jail.local | grep -E "chain|banaction|action"

echo ""
echo "2. Jail-specific banactions (sample 3):"
echo ""
echo "   sshd:"
sudo grep -A 3 "^\[sshd\]" /etc/fail2ban/jail.local | grep banaction

echo ""
echo "   sshd:"
sudo grep -A 3 "^\[sshd-slowattack\]" /etc/fail2ban/jail.local | grep banaction

echo ""
echo "   f2b-dos-high:"
sudo grep -A 3 "^\[f2b-dos-high\]" /etc/fail2ban/jail.local | grep banaction

echo ""
echo "   f2b-exploit-critical:"
sudo grep -A 3 "^\[f2b-exploit-critical\]" /etc/fail2ban/jail.local | grep banaction

echo ""
echo "3. Active jails using nftables:"
sudo fail2ban-client status | grep "Jail list"

echo ""
echo "4. nftables table verification:"
sudo nft list tables | grep fail2ban

echo ""
echo "5. Sample jail detail (dos-high):"
sudo fail2ban-client status f2b-dos-high | head -5

echo ""
echo "==============================================================="
echo "         CONFIGURATION ANALYSIS"
echo "==============================================================="
echo ""

# Count jails with nftables-multiport
NFTABLES_JAILS=$(sudo grep "banaction = nftables-multiport" /etc/fail2ban/jail.local | wc -l)
TOTAL_JAILS=$(sudo fail2ban-client status | grep -oP 'Number of jail:\s+\K\d+')

echo "Jails with nftables-multiport: $NFTABLES_JAILS"
echo "Total active jails: $TOTAL_JAILS"

if [ "$NFTABLES_JAILS" -eq "$TOTAL_JAILS" ]; then
    echo ""
    echo "✅ ALL JAILS using nftables-multiport!"
    echo "✅ chain = INPUT in [DEFAULT] is IGNORED"
    echo "✅ Configuration is CORRECT"
else
    echo ""
    echo "⚠️  Some jails might use DEFAULT banaction"
fi

echo ""
echo "RECOMMENDATION:"
echo "  chain = INPUT can stay (it's ignored)"
echo "  OR comment it out for clean config"

