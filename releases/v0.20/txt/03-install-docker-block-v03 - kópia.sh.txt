#!/bin/bash
################################################################################
# Docker Port Blocking v0.3 - Standalone
# Works with nftables-rebuild v2.1
# Creates PERSISTENT configuration via /etc/nftables/docker-block.nft
# Preserves existing /etc/nftables.conf if correct, creates/fixes if needed
# Embedded docker-block logic - no external dependencies
################################################################################

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
echo "══════════════════════════════════════════════════════════"
echo "  Docker Port Blocking Setup v0.3 (Standalone)"
echo "══════════════════════════════════════════════════════════"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    error "Please run with sudo"
fi

# Auto-fix mode (non-interactive)
DOCKER_BLOCK_AUTOFIX=1

################################################################################
# STEP 1: CREATE DOCKER-BLOCK NFT FILE
################################################################################

info "Step 1: Creating /etc/nftables/docker-block.nft..."
mkdir -p /etc/nftables

cat > /etc/nftables/docker-block.nft << 'EOF'
#!/usr/sbin/nft -f
# Docker Port Blocking v0.3
# Blocks external access to Docker ports while allowing localhost

table inet docker-block {
    set blocked_ports {
        type inet_service
        flags interval
        auto-merge
    }

    chain prerouting {
        type filter hook prerouting priority -100; policy accept;
        
        # Allow localhost to access Docker ports
        iif "lo" return
        
        # Allow Docker bridge
        iif "docker0" return
        
        # Block external access to blocked ports
        tcp dport @blocked_ports drop
        udp dport @blocked_ports drop
    }
}
EOF

chown root:root /etc/nftables/docker-block.nft
chmod 644 /etc/nftables/docker-block.nft

log "/etc/nftables/docker-block.nft created"
echo ""

################################################################################
# STEP 2: CHECK /etc/nftables.conf STRUCTURE
################################################################################

info "Step 2: Checking /etc/nftables.conf..."
echo ""

CORRECT_STRUCTURE=true

if [ ! -f /etc/nftables.conf ]; then
    warning "/etc/nftables.conf does not exist"
    CORRECT_STRUCTURE=false
else
    # Check for required components
    if ! grep -q "flush ruleset" /etc/nftables.conf; then
        warning "Missing 'flush ruleset' in /etc/nftables.conf"
        CORRECT_STRUCTURE=false
    fi
    
    if ! grep -q "/etc/nftables/docker-block.nft" /etc/nftables.conf; then
        warning "Missing docker-block include in /etc/nftables.conf"
        CORRECT_STRUCTURE=false
    fi
    
    if ! grep -q "/etc/nftables.d/fail2ban-filter.nft" /etc/nftables.conf; then
        warning "Missing fail2ban-filter include in /etc/nftables.conf"
        CORRECT_STRUCTURE=false
    fi
fi

################################################################################
# STEP 3: FIX /etc/nftables.conf (AUTO MODE)
################################################################################

if [ "$CORRECT_STRUCTURE" != true ] && [ "$DOCKER_BLOCK_AUTOFIX" = 1 ]; then
    info "Creating/fixing /etc/nftables.conf..."
    
    cat > /etc/nftables.conf << 'EOF'
#!/usr/sbin/nft -f

flush ruleset

# Fail2Ban nftables (v2.1)
include "/etc/nftables.d/fail2ban-filter.nft"

# Docker port blocking (v0.3)
include "/etc/nftables/docker-block.nft"
EOF
    
    chown root:root /etc/nftables.conf
    chmod 644 /etc/nftables.conf
    log "/etc/nftables.conf created/fixed"
elif [ "$CORRECT_STRUCTURE" = true ]; then
    log "/etc/nftables.conf is correctly configured"
else
    warning "Manual configuration required for /etc/nftables.conf"
    info "Add: include \"/etc/nftables/docker-block.nft\""
fi

echo ""

################################################################################
# STEP 4: TEST CONFIGURATION
################################################################################

info "Step 3: Testing nftables configuration..."
if nft -c -f /etc/nftables.conf 2>&1; then
    log "nftables configuration is valid"
else
    error "nftables configuration has errors - check manually: sudo nft -f /etc/nftables.conf"
fi

echo ""

################################################################################
# STEP 5: LOAD DOCKER-BLOCK TABLE
################################################################################

info "Step 4: Loading docker-block table..."

# Load the docker-block table
if nft -f /etc/nftables/docker-block.nft 2>&1; then
    log "docker-block table loaded successfully"
else
    error "Failed to load docker-block table"
fi

echo ""

################################################################################
# STEP 6: ENABLE NFTABLES SERVICE
################################################################################

info "Step 5: Enabling nftables.service..."

if ! systemctl is-enabled --quiet nftables.service 2>/dev/null; then
    systemctl enable nftables.service
    log "nftables.service enabled"
else
    log "nftables.service already enabled"
fi

echo ""

################################################################################
# STEP 7: VERIFY INSTALLATION
################################################################################

info "Step 6: Verifying installation..."
echo ""

# Check if table exists
if nft list table inet docker-block &>/dev/null; then
    log "✓ Table inet docker-block exists"
else
    warning "✗ Table inet docker-block NOT found"
fi

# Check if blocked_ports set exists
if nft list set inet docker-block blocked_ports &>/dev/null; then
    log "✓ Set blocked_ports exists"
    
    # Show current blocked ports
    BLOCKED=$(nft list set inet docker-block blocked_ports 2>/dev/null | sed -n '/elements = {/,/}/p' | grep -oE '[0-9]+' | tr '\n' ',' | sed 's/,$//')
    
    if [ -z "$BLOCKED" ]; then
        info "  Currently no ports blocked (empty set)"
    else
        info "  Currently blocked ports: $BLOCKED"
    fi
else
    warning "✗ Set blocked_ports NOT found"
fi

echo ""

################################################################################
# SUMMARY
################################################################################

echo "══════════════════════════════════════════════════════════"
log "✅ Docker Port Blocking Setup Complete"
echo "══════════════════════════════════════════════════════════"
echo ""
echo "Files created/updated:"
echo "  • /etc/nftables/docker-block.nft"
echo "  • /etc/nftables.conf (verified/created)"
echo ""
echo "Behavior:"
echo "  ✓ localhost (127.0.0.1) → ALLOWED"
echo "  ✓ Docker bridge (docker0) → ALLOWED"
echo "  ✗ External IPs → BLOCKED (for ports in set)"
echo ""
echo "Manage Docker ports with f2b wrapper:"
echo "  f2b manage list-blocked-ports"
echo "  f2b manage block-port 8081"
echo "  f2b manage unblock-port 8081"
echo "  f2b manage docker-info"
echo ""
echo "Manual management (if needed):"
echo "  nft add element inet docker-block blocked_ports { 8081 }"
echo "  nft delete element inet docker-block blocked_ports { 8081 }"
echo "  nft list set inet docker-block blocked_ports"
echo ""
echo "Test reload:"
echo "  sudo nft -f /etc/nftables.conf"
echo ""

