#!/bin/bash
echo "Fixing wrapper docker-block set name..."

if [[ -f /usr/local/bin/f2b ]]; then
    sudo cp /usr/local/bin/f2b /usr/local/bin/f2b.backup-patch
    sudo sed -i 's/docker-blocked-ports/blocked_ports/g' /usr/local/bin/f2b
    echo "✅ Wrapper docker-block fixed"
else
    echo "⚠️  Wrapper not installed yet (will be fixed after installation)"
fi
