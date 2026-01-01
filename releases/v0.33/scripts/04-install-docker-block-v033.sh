#!/bin/bash
set -e
set -o pipefail

################################################################################
# Docker Port + IP Blocking v0.4 - WITH FAIL2BAN INTEGRATION
# Uses prerouting hook to catch IPs BEFORE Docker NAT
# Component: INSTALL-DOCKER-BLOCK
# Part of: Fail2Ban Hybrid Nftables Manager
################################################################################

# shellcheck disable=SC2034
RELEASE="v0.33"
# shellcheck disable=SC2034
VERSION="0.33"
# shellcheck disable=SC2034
BUILD_DATE="2026-01-01"
# shellcheck disable=SC2034
COMPONENT_NAME="INSTALL-DOCKER-BLOCK"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Unified visuals with INSTALL-ALL-v033.sh
log()     { echo -e "${GREEN}✓${NC} $1"; }
error()   { echo -e "${RED}✗${NC} $1"; exit 1; }
warning() { echo -e "${YELLOW}⚠${NC} $1"; }
info()    { echo -e "${BLUE}ℹ${NC} $1"; }

DOCKER_BLOCK_AUTOFIX=1
DOCKER_BLOCK_NFT="/etc/nftables.d/docker-block.nft"
NFTABLES_CONF="/etc/nftables.conf"
F2B_NFT="/etc/nftables.d/fail2ban-filter.nft"

################################################################################
# HELPERS (idempotent primitives)
################################################################################

write_if_changed() {
  # args: src tmpfile, dst
  local src="$1" dst="$2"
  if [ -f "$dst" ] && cmp -s "$src" "$dst"; then
    log "No change: $dst"
    return 1
  fi
  install -o root -g root -m 0644 "$src" "$dst"
  log "Updated: $dst"
  return 0
}

ensure_line_in_file() {
  # args: line, file
  local line="$1" file="$2"
  grep -Fqx "$line" "$file" && return 0
  echo "$line" >> "$file"
  return 0
}

################################################################################
# HEADER
################################################################################

echo ""
echo "══════════════════════════════════════════════════════════"
echo " Docker Port + IP Blocking Setup v0.4 (${RELEASE})"
echo "══════════════════════════════════════════════════════════"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
  error "Please run with sudo"
fi

################################################################################
# STEP 1: CREATE / UPDATE DOCKER-BLOCK NFT FILE (idempotent)
################################################################################

info "Step 1: Ensuring ${DOCKER_BLOCK_NFT}..."

mkdir -p /etc/nftables.d

TMP_NFT="$(mktemp)"
cat > "$TMP_NFT" << 'EOF'
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

CHANGED_NFT=0
if write_if_changed "$TMP_NFT" "$DOCKER_BLOCK_NFT"; then
  CHANGED_NFT=1
fi
rm -f "$TMP_NFT"

echo ""

################################################################################
# STEP 2: CHECK / PATCH /etc/nftables.conf (non-destructive)
################################################################################

info "Step 2: Checking ${NFTABLES_CONF}..."

if [ ! -f "$NFTABLES_CONF" ]; then
  warning "${NFTABLES_CONF} does not exist"
  if [ "$DOCKER_BLOCK_AUTOFIX" = "1" ]; then
    info "Creating minimal ${NFTABLES_CONF}..."
    cat > "$NFTABLES_CONF" <<EOF
#!/usr/sbin/nft -f

flush ruleset

# Fail2Ban nftables (managed by installer)
include "${F2B_NFT}"

# Docker port + IP blocking (managed by installer)
include "${DOCKER_BLOCK_NFT}"
EOF
    chown root:root "$NFTABLES_CONF"
    chmod 0644 "$NFTABLES_CONF"
    log "${NFTABLES_CONF} created"
  else
    warning "AUTOFIX disabled; skipping ${NFTABLES_CONF} creation"
  fi
else
  # Only warn about flush ruleset; do NOT rewrite user's file automatically.
  if ! grep -q "flush ruleset" "$NFTABLES_CONF"; then
    warning "Missing 'flush ruleset' in ${NFTABLES_CONF} (not rewriting; only warning)"
  fi

  if [ "$DOCKER_BLOCK_AUTOFIX" = "1" ]; then
    # Append missing includes only (idempotent)
    if ! grep -q "${F2B_NFT}" "$NFTABLES_CONF"; then
      warning "Missing fail2ban-filter include in ${NFTABLES_CONF} -> appending"
      echo "" >> "$NFTABLES_CONF"
      ensure_line_in_file "# Fail2Ban nftables (added by installer)" "$NFTABLES_CONF"
      ensure_line_in_file "include \"${F2B_NFT}\"" "$NFTABLES_CONF"
      log "Patched: added Fail2Ban include"
    else
      log "Fail2Ban include present"
    fi

    if ! grep -q "${DOCKER_BLOCK_NFT}" "$NFTABLES_CONF"; then
      warning "Missing docker-block include in ${NFTABLES_CONF} -> appending"
      echo "" >> "$NFTABLES_CONF"
      ensure_line_in_file "# Docker port + IP blocking (added by installer)" "$NFTABLES_CONF"
      ensure_line_in_file "include \"${DOCKER_BLOCK_NFT}\"" "$NFTABLES_CONF"
      log "Patched: added docker-block include"
    else
      log "docker-block include present"
    fi
  else
    warning "AUTOFIX disabled; not patching ${NFTABLES_CONF}"
  fi
fi

echo ""

################################################################################
# STEP 3: TEST CONFIGURATION
################################################################################

info "Step 3: Testing nftables configuration..."

if nft -c -f "$NFTABLES_CONF" >/dev/null 2>&1; then
  log "nftables configuration is valid"
else
  error "nftables configuration has errors (nft -c failed)"
fi

echo ""

################################################################################
# STEP 4: LOAD DOCKER-BLOCK TABLE (idempotent: delete + load)
################################################################################

info "Step 4: Loading docker-block table (idempotent)..."

# Ensure we don't collide with an existing table definition.
if nft list table inet docker-block >/dev/null 2>&1; then
  info "Existing table inet docker-block detected -> deleting to avoid duplicates/conflicts"
  nft delete table inet docker-block >/dev/null 2>&1 || error "Failed to delete existing docker-block table"
fi

if nft -f "$DOCKER_BLOCK_NFT" >/dev/null 2>&1; then
  log "docker-block table loaded successfully"
else
  error "Failed to load docker-block table"
fi

# If f2b wrapper exists, repopulate banned IPs (because deleting table resets set elements)
if command -v f2b >/dev/null 2>&1; then
  info "Repopulating docker-block sets from Fail2Ban..."
  f2b docker sync full || warning "f2b docker sync full failed (manual sync may be needed)"
else
  info "Tip: run 'sudo f2b docker sync full' if you need to repopulate banned IPs"
fi

echo ""

################################################################################
# STEP 5: ENABLE NFTABLES SERVICE
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
# STEP 6: VERIFY INSTALLATION
################################################################################

info "Step 6: Verifying installation..."
echo ""

if nft list table inet docker-block &>/dev/null; then
  log "Table inet docker-block exists"
else
  warning "Table inet docker-block NOT found"
fi

if nft list set inet docker-block docker-blocked-ports &>/dev/null; then
  log "Set docker-blocked-ports exists (ready)"
else
  warning "Set docker-blocked-ports NOT found"
fi

if nft list set inet docker-block docker-banned-ipv4 &>/dev/null; then
  log "Set docker-banned-ipv4 exists (ready for sync)"

  BANNED=$(nft list set inet docker-block docker-banned-ipv4 2>/dev/null | \
    grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | wc -l)

  if [ "$BANNED" -eq 0 ]; then
    info "Currently 0 banned IPs"
  else
    info "Currently $BANNED banned IPs"
  fi
else
  warning "Set docker-banned-ipv4 NOT found"
fi

echo ""

################################################################################
# SUMMARY  (keep your original style here)
################################################################################

echo "══════════════════════════════════════════════════════════"
log "Docker Port + IP Blocking Setup Complete"
echo "══════════════════════════════════════════════════════════"
echo ""

echo "Files created/updated:"
echo " • ${DOCKER_BLOCK_NFT} (v0.4 - with IP blocking)"
echo " • ${NFTABLES_CONF} (verified/patched if needed)"
echo ""

echo "Features:"
echo " ✓ Port blocking (external → blocked)"
echo " ✓ IP blocking (banned IPs → dropped in PREROUTING)"
echo " ✓ Docker NAT bypass protection"
echo ""

echo "IP management (manual):"
echo " # Add banned IP (with 7d timeout):"
echo " sudo nft add element inet docker-block docker-banned-ipv4 { 194.154.241.170 timeout 7d }"
echo ""
echo " # List all banned IPs:"
echo " sudo nft list set inet docker-block docker-banned-ipv4"
echo ""
echo " # Remove IP:"
echo " sudo nft delete element inet docker-block docker-banned-ipv4 { 194.154.241.170 }"
echo ""
echo "Test reload:"
echo " sudo nft -f ${NFTABLES_CONF}"
echo ""

