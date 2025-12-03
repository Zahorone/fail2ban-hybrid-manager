#!/bin/bash
################################################################################
# Fix docker-block set name in f2b wrapper
# Changes: docker-blocked-ports → blocked_ports
################################################################################

set -e

GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

log() { echo -e "${GREEN}[✓]${NC} $1"; }
info() { echo -e "${BLUE}[i]${NC} $1"; }

echo ""
info "Fixing docker-block set name in wrapper..."

# Backup
BACKUP="/usr/local/bin/f2b.backup-$(date +%Y%m%d-%H%M)"
sudo cp /usr/local/bin/f2b "$BACKUP"
log "Backup: $BACKUP"

# Fix
sudo sed -i 's/docker-blocked-ports/blocked_ports/g' /usr/local/bin/f2b
log "Fixed: docker-blocked-ports → blocked_ports"

# Verify
COUNT=$(grep -c "blocked_ports" /usr/local/bin/f2b | grep docker-block || echo 0)
log "Verified: $COUNT references updated"

echo ""
log "✅ Wrapper fixed successfully!"
echo ""

# Test
info "Testing functionality..."
sudo f2b manage docker-info | grep -q "docker-block table" && log "Test passed" || echo "Test failed"
echo ""
