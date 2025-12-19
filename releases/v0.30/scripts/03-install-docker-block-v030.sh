#!/bin/bash
set -e
################################################################################
# Docker Port + IP Blocking v0.4 - WITH FAIL2BAN INTEGRATION 
# Uses prerouting hook to catch IPs BEFORE Docker NAT
# Component: INSTALL-DOCKER-BLOCK
# Part of: Fail2Ban Hybrid Nftables Manager
################################################################################

# shellcheck disable=SC2034
RELEASE="v0.30"
# shellcheck disable=SC2034
VERSION="0.30"
# shellcheck disable=SC2034
BUILD_DATE="2025-12-19"
# shellcheck disable=SC2034
COMPONENT_NAME="INSTALL-DOCKER-BLOCK"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_header()  { echo -e "${BLUE}$1${NC}"; }
log_success() { echo -e "${GREEN}✓${NC} $1"; }
log_error()   { echo -e "${RED}✗${NC} $1"; }
log_info()    { echo -e "${BLUE}ℹ${NC} $1"; }
log_warn()    { echo -e "${YELLOW}⚠${NC} $1"; }

echo ""
echo "╔════════════════════════════════════════════════════════════╗"
echo "║                                                            ║"
echo "║   Docker Port Blocking Installer ${RELEASE} (v0.4 rules)  ║"
echo "║   docker-block table + DOCKER-USER integration             ║"
echo "║                                                            ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""


# Check if running as root
if [ "$EUID" -ne 0 ]; then
    error "Please run with sudo"
fi

DOCKER_BLOCK_AUTOFIX=1

################################################################################
# STEP 1: CREATE DOCKER-BLOCK NFT FILE (WITH IP BLOCKING)
################################################################################

info "Step 1: Creating /etc/nftables/docker-block.nft..."

mkdir -p /etc/nftables

cat > /etc/nftables/docker-block.nft << 'EOF'
#!/usr/sbin/nft -f

# Docker Port + IP Blocking v0.4
# Blocks external access to Docker ports AND banned IPs

table inet docker-block {
    # Set for blocked ports
    set docker-blocked-ports {
        type inet_service
        flags interval
        auto-merge
    }

    # Set for banned IPv4 addresses (from fail2ban)
    set docker-banned-ipv4 {
        type ipv4_addr
        flags interval, timeout
        auto-merge
        timeout 7d
    }

    # Set for banned IPv6 addresses (from fail2ban)
    set docker-banned-ipv6 {
        type ipv6_addr
        flags interval, timeout
        auto-merge
        timeout 7d
    }

    chain prerouting {
        type filter hook prerouting priority dstnat; policy accept;

        # CRITICAL: Drop banned IPs FIRST (before any NAT)
        ip saddr @docker-banned-ipv4 drop
        ip6 saddr @docker-banned-ipv6 drop

        # Allow localhost to access Docker ports
        iif "lo" return

        # Allow Docker bridge
        iif "docker0" return

        # Block external access to blocked ports
        tcp dport @docker-blocked-ports drop
        udp dport @docker-blocked-ports drop
    }
}
EOF

chown root:root /etc/nftables/docker-block.nft
chmod 644 /etc/nftables/docker-block.nft

log "/etc/nftables/docker-block.nft created (with IP blocking)"
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

# Docker port + IP blocking (v0.4)
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
    error "nftables configuration has errors"
fi

echo ""

################################################################################
# STEP 5: LOAD DOCKER-BLOCK TABLE
################################################################################

info "Step 4: Loading docker-block table..."

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

# Check table
if nft list table inet docker-block &>/dev/null; then
    log "✓ Table inet docker-block exists"
else
    warning "✗ Table inet docker-block NOT found"
fi

# Check port set
if nft list set inet docker-block docker-blocked-ports &>/dev/null; then
    log "✓ Set docker-blocked-ports exists (empty - ready to use)"
else
    warning "✗ Set docker-blocked-ports NOT found"
fi

# Check IP sets
if nft list set inet docker-block docker-banned-ipv4 &>/dev/null; then
    log "✓ Set docker-banned-ipv4 exists (ready for fail2ban sync)"
    
    BANNED=$(nft list set inet docker-block docker-banned-ipv4 2>/dev/null \
        | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | wc -l)
    
    if [ "$BANNED" -eq 0 ]; then
        info "   Currently 0 banned IPs"
    else
        info "   Currently $BANNED banned IPs"
    fi
else
    warning "✗ Set docker-banned-ipv4 NOT found"
fi

echo ""

################################################################################
# SUMMARY
################################################################################

echo "══════════════════════════════════════════════════════════"
log "✅ Docker Port + IP Blocking Setup Complete"
echo "══════════════════════════════════════════════════════════"
echo ""
echo "Files created/updated:"
echo "  • /etc/nftables/docker-block.nft (v0.4 - with IP blocking)"
echo "  • /etc/nftables.conf (verified/created)"
echo ""
echo "Features:"
echo "  ✓ Port blocking (external → blocked)"
echo "  ✓ IP blocking (banned IPs → dropped in PREROUTING)"
echo "  ✓ Docker NAT bypass protection"
echo ""
echo "IP management (manual):"
echo "  # Add banned IP (with 1h timeout):"
echo "  sudo nft add element inet docker-block docker-banned-ipv4 { 194.154.241.170 timeout 1h }"
echo ""
echo "  # List all banned IPs:"
echo "  sudo nft list set inet docker-block docker-banned-ipv4"
echo ""
echo "  # Remove IP:"
echo "  sudo nft delete element inet docker-block docker-banned-ipv4 { 194.154.241.170 }"
echo ""
echo "Test reload:"
echo "  sudo nft -f /etc/nftables.conf"
echo ""
