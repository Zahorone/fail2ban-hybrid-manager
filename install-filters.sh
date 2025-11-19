#!/bin/bash
set -e
REPO="https://raw.githubusercontent.com/Zahorone/fail2ban-hybrid-manager/main/filters"
TARGET="/etc/fail2ban/filter.d"

# Filtre zoznam
FILTERS=(
    manualblock.conf
    nginx-444.conf
    nginx-exploit-pattern.conf
    nginx-limit-req.conf
    nginx-npm-4xx.conf
    nginx-recon.conf
    npm-fasthttp.conf
    npm-iot-exploit.conf
    recidive.conf
)

echo "📥 Inštalujem custom Fail2Ban filtre..."
for filter in "${FILTERS[@]}"; do
    curl -sSLO "$REPO/$filter"
    sudo mv "$filter" "$TARGET/$filter"
    echo "✅ $filter nainštalovaný do $TARGET"
done

