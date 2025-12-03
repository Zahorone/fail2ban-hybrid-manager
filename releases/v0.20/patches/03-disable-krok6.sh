#!/bin/bash
echo "Disabling KROK 6 in 01-install-nftables.sh..."

# Backup
cp ../01-install-nftables.sh ../01-install-nftables.sh.backup-patch

# Disable KROK 6
sed -i.bak '/^# KROK 6: MIGRÁCIA IP/,/^echo ""$/ {
    /^# KROK 6: MIGRÁCIA IP/i\
# DISABLED - Import will be done by 05-install-auto-sync.sh\
# Reason: Python list parsing issues\
: << '\''DISABLED_KROK6'\''
    /^echo ""$/a\
DISABLED_KROK6
}' ../01-install-nftables.sh

echo "✅ KROK 6 disabled"
