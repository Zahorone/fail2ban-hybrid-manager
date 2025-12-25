#!/bin/bash

################################################################################

# Nftables Fail2Ban Configuration v0.31
# f2b-recidive timeout 30d (IPv4+IPv6), ostatné 7d
# COMPLETE REBUILD: nftables Fail2Ban Infrastructure
# Vytvorí kompletnú nftables tabuľku, reťazce, sety a pravidlá

# Version: 3.1 (final v0.31 structure, based on v0.30)
# Date: 2025-12-19
# Changelog: Unified IPv4/IPv6 sets (11+11), final FORWARD protection,
#            v0.30 metadata framework, consistent backup & persist setup

# Component: INSTALL-NFTABLES
# Part of: Fail2Ban Hybrid Nftables Manager

################################################################################

set -e

# shellcheck disable=SC2034 # Metadata used for release tracking
RELEASE="v0.31"

# shellcheck disable=SC2034
VERSION="0.31"

# shellcheck disable=SC2034
BUILD_DATE="2025-12-26"

# shellcheck disable=SC2034
COMPONENT_NAME="INSTALL-NFTABLES"

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

log_header() { echo -e "${BLUE}$1${NC}"; }
log_success() { echo -e "${GREEN}✓${NC} $1"; }
log_error() { echo -e "${RED}✗${NC} $1"; }
log_info() { echo -e "${BLUE}ℹ${NC} $1"; }
log_warn() { echo -e "${YELLOW}⚠${NC} $1"; }

clear

echo ""
echo "╔════════════════════════════════════════════════════════════╗"
echo "║                                                            ║"
echo "║   Nftables Fail2Ban Setup ${RELEASE}                       ║"
echo "║   IPv4/IPv6 + recidive 30d + FORWARD protection           ║"
echo "║                                                            ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

# Root check
if [ "$EUID" -ne 0 ]; then
  log_error "Please run with sudo"
  exit 1
fi

################################################################################
# KROK 1: KONTROLA nftables TABUĽKY
################################################################################

log_header "═══ KROK 1: KONTROLA nftables TABUĽKY ═══"

if sudo nft list tables 2>/dev/null | grep -q "fail2ban"; then
  log_info "Tabuľka existuje, backupujem..."
  sudo nft list table inet fail2ban-filter 2>/dev/null | \
    sudo tee "/tmp/nftables-backup-$(date +%s).nft" &>/dev/null || true
  log_info "Odstraňujem starú tabuľku..."
  sudo nft delete table inet fail2ban-filter 2>/dev/null || true
  sleep 1
else
  log_info "Tabuľka neexistuje (OK)"
fi

echo ""

################################################################################
# KROK 2: VYTVOR NOVÚ nftables TABUĽKU
################################################################################

log_header "═══ KROK 2: VYTVOR NOVÚ nftables TABUĽKU ═══"

log_info "Vytváram tabuľku inet fail2ban-filter..."
sudo nft add table inet fail2ban-filter 2>/dev/null || true

log_success "Tabuľka vytvorená"

echo ""

################################################################################
# KROK 3: VYTVOR REŤAZCE
################################################################################

log_header "═══ KROK 3: VYTVOR REŤAZCE (CHAINS) ═══"

log_info "Vytváram reťazec INPUT..."
sudo nft add chain inet fail2ban-filter f2b-input '{ type filter hook input priority -100; }' 2>/dev/null || true

log_info "Vytváram reťazec FORWARD..."
sudo nft add chain inet fail2ban-filter f2b-forward '{ type filter hook forward priority -100; }' 2>/dev/null || true

log_success "Reťazce vytvorené"

echo ""

################################################################################
# KROK 4: VYTVOR VŠETKY SETY (11 x IPv4 + IPv6) - RECIDIVE 30d!
################################################################################

log_header "═══ KROK 4: VYTVOR VŠETKY SETY (IPv4 + IPv6) ═══"

SETS=(
  "f2b-sshd"
  "f2b-sshd-slowattack"
  "f2b-exploit-critical"
  "f2b-dos-high"
  "f2b-web-medium"
  "f2b-nginx-recon-bonus"
  "f2b-recidive"
  "f2b-manualblock"
  "f2b-fuzzing-payloads"
  "f2b-botnet-signatures"
  "f2b-anomaly-detection"
)

for set in "${SETS[@]}"; do
  # Conditional timeout: recidive = 30d, ostatné = 7d
  if [ "$set" = "f2b-recidive" ]; then
    TIMEOUT="2592000s"  # 30 days
    LABEL="(30d)"
  else
    TIMEOUT="604800s"   # 7 days
    LABEL="(7d)"
  fi

  echo -n "  $set (IPv4) $LABEL ... "
  sudo nft add set inet fail2ban-filter "$set" \
    "{ type ipv4_addr; flags interval,timeout; auto-merge; timeout $TIMEOUT; }" 2>/dev/null && echo "✓" || echo ""

  echo -n "  $set-v6 (IPv6) $LABEL ... "
  sudo nft add set inet fail2ban-filter "$set-v6" \
    "{ type ipv6_addr; flags interval,timeout; auto-merge; timeout $TIMEOUT; }" 2>/dev/null && echo "✓" || echo ""
done

echo ""

log_success "Sety vytvorené: recidive 30d, ostatné 7d"

################################################################################
# KROK 5: PRIDAJ DROP PRAVIDLÁ
################################################################################

log_header "═══ KROK 5: PRIDAJ DROP PRAVIDLÁ ═══"

# Idempotent: vyčisti chainy aby nevznikali duplicity pri rerune
sudo nft flush chain inet fail2ban-filter f2b-input 2>/dev/null || true
sudo nft flush chain inet fail2ban-filter f2b-forward 2>/dev/null || true

log_info "INPUT reťazec (22 pravidiel: 11 IPv4 + 11 IPv6)..."

# IPv4 pravidlá
for set in "${SETS[@]}"; do
  echo -n "  $set (v4) ... "
  sudo nft add rule inet fail2ban-filter f2b-input ip saddr @"$set" drop 2>/dev/null && echo "✓" || echo ""
done

# IPv6 pravidlá
for set in "${SETS[@]}"; do
  echo -n "  $set-v6 (v6) ... "
  sudo nft add rule inet fail2ban-filter f2b-input ip6 saddr @"$set-v6" drop 2>/dev/null && echo "✓" || echo ""
done

log_success "INPUT pravidlá pridané (22/22)"

echo ""

log_info "FORWARD reťazec (8 pravidiel: 4 IPv4 + 4 IPv6) - kritické + recidive..."

# Kritické sety pre FORWARD (ochrana backend služieb: Apache2, MariaDB)
FORWARD_SETS=("f2b-exploit-critical" "f2b-dos-high" "f2b-manualblock" "f2b-recidive")

# IPv4
for set in "${FORWARD_SETS[@]}"; do
  echo -n "  $set (v4) ... "
  sudo nft add rule inet fail2ban-filter f2b-forward ip saddr @"$set" drop 2>/dev/null && echo "✓" || echo ""
done

# IPv6
for set in "${FORWARD_SETS[@]}"; do
  echo -n "  $set-v6 (v6) ... "
  sudo nft add rule inet fail2ban-filter f2b-forward ip6 saddr @"$set-v6" drop 2>/dev/null && echo "✓" || echo ""
done

log_success "FORWARD pravidlá pridané (8/8)"

echo ""

################################################################################
# KROK 6: MIGRÁCIA IP Z FAIL2BAN - FIX v0.30 (CORRECTNÉ PARSOVANIE)
################################################################################

log_header "═══ KROK 6: MIGRÁCIA IP Z FAIL2BAN ═══"

if ! systemctl is-active --quiet fail2ban 2>/dev/null; then
  log_warn "Fail2Ban nie je aktívny - preskakujem migráciu (čistá inštalácia)"
  echo ""
else
  # Mapovanie jail -> nft set (v4); v6 je automaticky "${set}-v6"
  declare -A JAILS=(
    ["sshd"]="f2b-sshd"
    ["sshd-slowattack"]="f2b-sshd-slowattack"
    ["f2b-exploit-critical"]="f2b-exploit-critical"
    ["f2b-dos-high"]="f2b-dos-high"
    ["f2b-web-medium"]="f2b-web-medium"
    ["nginx-recon-bonus"]="f2b-nginx-recon-bonus"
    ["recidive"]="f2b-recidive"
    ["manualblock"]="f2b-manualblock"
    ["f2b-fuzzing-payloads"]="f2b-fuzzing-payloads"
    ["f2b-botnet-signatures"]="f2b-botnet-signatures"
    ["f2b-anomaly-detection"]="f2b-anomaly-detection"
  )

  MIGRATED_TOTAL=0

  for jail in "${!JAILS[@]}"; do
    set="${JAILS[$jail]}"

    # Jail nemusí existovať (fresh install / custom)
    if ! sudo fail2ban-client status "$jail" >/dev/null 2>&1; then
      continue
    fi

    # DÔLEŽITÉ: banip je space-separated => split na newline
    IPS="$(sudo fail2ban-client get "$jail" banip 2>/dev/null | tr ' \t' '\n' | sed '/^$/d' | sort -u)"

    [ -z "$IPS" ] && continue

    COUNT="$(echo "$IPS" | wc -l | tr -d ' ')"
    log_info "$jail -> $set ($COUNT IP)"

    while IFS= read -r ip; do
      [ -z "$ip" ] && continue

      if echo "$ip" | grep -q ":"; then
        # IPv6
        sudo nft add element inet fail2ban-filter "${set}-v6" "{ $ip }" 2>/dev/null || \
          log_warn "Nepodarilo sa pridať IPv6 $ip do ${set}-v6"
      else
        # IPv4
        sudo nft add element inet fail2ban-filter "$set" "{ $ip }" 2>/dev/null || \
          log_warn "Nepodarilo sa pridať IPv4 $ip do $set"
      fi

      MIGRATED_TOTAL=$((MIGRATED_TOTAL + 1))
    done <<< "$IPS"
  done

  echo ""
  if [ "$MIGRATED_TOTAL" -gt 0 ]; then
    log_success "Migrovalo sa $MIGRATED_TOTAL IP adries"
  else
    log_info "Žiadne IP na migráciu"
  fi
  echo ""
fi

################################################################################
# KROK 7: REŠTART FAIL2BAN
################################################################################

log_header "═══ KROK 7: REŠTART FAIL2BAN ═══"

if ! systemctl list-unit-files 2>/dev/null | grep -q "fail2ban.service"; then
  log_info "Fail2Ban service neexistuje - preskakujem reštart (čistá inštalácia)"
  log_info "Fail2Ban sa nainštaluje v ďalšom kroku"
  echo ""
else
  if systemctl is-active --quiet fail2ban 2>/dev/null; then
    ACTIVE_JAILS=$(sudo fail2ban-client status 2>/dev/null | grep "Jail list:" | sed 's/.*://' | tr ',' '\n' | grep -cv '^ *$' || echo 0)
    if [ "$ACTIVE_JAILS" -gt 0 ]; then
      log_info "Reštartujem Fail2Ban (detekovaný $ACTIVE_JAILS jails)..."
      sudo systemctl restart fail2ban
      sleep 3
      log_success "Fail2Ban reštartovaný"
    else
      log_info "Fail2Ban beží ale bez jailov - reštart nie je potrebný"
      log_info "Jails sa nainštalujú v ďalšom kroku"
    fi
  else
    log_info "Fail2Ban nie je aktívny - preskakujem reštart"
    log_info "Fail2Ban sa spustí po inštalácii jails"
  fi
  echo ""
fi

################################################################################
# KROK 8: FINÁLNA KONTROLA
################################################################################

log_header "═══ KROK 8: FINÁLNA KONTROLA ═══"

log_info "nftables Tabuľka (prvých 35 riadkov):"
sudo nft list table inet fail2ban-filter 2>/dev/null | head -35

echo ""

log_info "Vytvorené sety (22 expected: 11 IPv4 + 11 IPv6):"

SETSV4=$(sudo nft list table inet fail2ban-filter 2>/dev/null | grep -E "^[[:space:]]*set f2b-" | grep -vc -- "-v6" || echo 0)
SETSV6=$(sudo nft list table inet fail2ban-filter 2>/dev/null | grep -E "^[[:space:]]*set f2b-.*-v6" | wc -l | tr -d ' ' || echo 0)
TOTALSETS=$((SETSV4 + SETSV6))

log_info "Počet setov: ${TOTALSETS} / 22"

if [ "$TOTALSETS" -eq 22 ]; then
  log_success "Všetky sety vytvorené!"
else
  log_warn "Očakávaných 22 setov, nájdených ${TOTALSETS}"
fi

echo ""

log_info "Recidive timeout verification:"
echo -n "  f2b-recidive (IPv4): "
sudo nft list set inet fail2ban-filter f2b-recidive 2>/dev/null | grep "timeout" | sed 's/.*timeout //'
echo -n "  f2b-recidive-v6 (IPv6): "
sudo nft list set inet fail2ban-filter f2b-recidive-v6 2>/dev/null | grep "timeout" | sed 's/.*timeout //'

echo ""

log_info "DROP pravidlá v INPUT chain:"
INPUT_RULES=$(sudo nft list chain inet fail2ban-filter f2b-input 2>/dev/null | grep -c "drop" || echo 0)
echo "  Počet: $INPUT_RULES / 22 (11 IPv4 + 11 IPv6)"

if [ "$INPUT_RULES" -eq 22 ]; then
  log_success "Všetky INPUT pravidlá vytvorené!"
else
  log_warn "Očakávaných 22 pravidiel, nájdených $INPUT_RULES"
fi

echo ""

log_info "DROP pravidlá v FORWARD chain:"
FORWARD_RULES=$(sudo nft list chain inet fail2ban-filter f2b-forward 2>/dev/null | grep -c "drop" || echo 0)
echo "  Počet: $FORWARD_RULES / 8 (4 IPv4 + 4 IPv6)"

if [ "$FORWARD_RULES" -eq 8 ]; then
  log_success "Všetky FORWARD pravidlá vytvorené!"
  log_info "   ✓ f2b-exploit-critical (ochrana Apache2/MariaDB)"
  log_info "   ✓ f2b-dos-high (ochrana bandwidth)"
  log_info "   ✓ f2b-manualblock (permanentný block)"
  log_info "   ✓ f2b-recidive (30d recidivisti) ⭐ NEW"
else
  log_warn "Očakávaných 8 pravidiel, nájdených $FORWARD_RULES"
fi

echo ""

################################################################################
# KROK 9: ULOŽENIE PERZISTENTNEJ KONFIGURÁCIE
################################################################################

log_header "═══ KROK 9: ULOŽENIE PERZISTENTNEJ KONFIGURÁCIE ═══"

log_info "Vytváram /etc/nftables.d/fail2ban-filter.nft..."

sudo mkdir -p /etc/nftables.d

sudo nft list table inet fail2ban-filter 2>/dev/null | \
  sudo tee /tmp/fail2ban-filter.nft &>/dev/null

sudo mv /tmp/fail2ban-filter.nft /etc/nftables.d/fail2ban-filter.nft

log_success "Konfigurácia uložená"

echo ""

log_info "Kontrolujem /etc/nftables.conf..."

EXPECTED_CONF='#!/usr/sbin/nft -f

flush ruleset

# Fail2Ban nftables (v'$VERSION' - IPv4/IPv6, recidive 30d + FORWARD)
include "/etc/nftables.d/fail2ban-filter.nft"

# Docker port blocking (v0.4)
include "/etc/nftables.d/docker-block.nft"'

if [ ! -s /etc/nftables.conf ]; then
  log_info "Vytváram nový /etc/nftables.conf..."
  echo "$EXPECTED_CONF" | sudo tee /etc/nftables.conf &>/dev/null
  log_success "/etc/nftables.conf vytvorený"
else
  if ! grep -q "/etc/nftables.d/fail2ban-filter.nft" /etc/nftables.conf 2>/dev/null; then
    log_warn "/etc/nftables.conf existuje ale chýba fail2ban include"
    log_info "MANUÁLNE pridaj: include \"/etc/nftables.d/fail2ban-filter.nft\""
    log_info "Alebo spusti:"
    echo "  echo 'include \"/etc/nftables.d/fail2ban-filter.nft\"' | sudo tee -a /etc/nftables.conf"
  else
    log_success "Include už existuje v /etc/nftables.conf"
  fi
fi

echo ""

if ! systemctl is-enabled --quiet nftables.service 2>/dev/null; then
  log_info "Povoľujem nftables.service..."
  sudo systemctl enable nftables.service
  log_success "nftables.service enabled"
else
  log_info "nftables.service už je enabled"
fi

echo ""

log_success "Konfigurácia je PERZISTENTNÁ - prežije reboot!"

echo ""

################################################################################
# COMPLETE
################################################################################

log_header "╔════════════════════════════════════════════════════════════╗"
log_header "║           COMPLETE REBUILD HOTOVÝ v${VERSION}                 ║"
log_header "╚════════════════════════════════════════════════════════════╝"

echo ""
echo "Nasledujúce boli vykonané:"
echo "  1. Backup a odstránenie starej tabuľky"
echo "  2. Vytvorenie novej tabuľky inet fail2ban-filter"
echo "  3. Vytvorenie reťazcov INPUT a FORWARD"
echo "  4. Vytvorenie všetkých 11 setov (IPv4 + IPv6)"
echo "     ✓ f2b-recidive: 30 days timeout (2592000s)"
echo "     ✓ ostatné: 7 days timeout (604800s)"
echo "  5. Pridanie DROP pravidiel (22 INPUT + 8 FORWARD)"
echo "     ✓ INPUT: všetky jaile (ochrana servera)"
echo "     ✓ FORWARD: exploit-critical, dos-high, manualblock, recidive"
echo "       → Ochrana backend služieb (Apache2, MariaDB)"
echo "  6. Migrácia IP z Fail2Ban (s correct timeout)"
echo "  7. Reštart Fail2Ban"
echo "  8. Finálna kontrola + recidive timeout verification"
echo "  9. Uloženie perzistentnej konfigurácie"
echo ""
echo "Konfigurácia je PERZISTENTNÁ - prežije reboot!"
echo "IPv4 + IPv6 support aktívny!"
echo "Recidive: 30-day timeout ✅"
echo "FORWARD chain: ochrana MariaDB a Apache2 ✅"
echo ""
echo "Test:"
echo "  sudo nft list set inet fail2ban-filter f2b-recidive | grep timeout"
echo "  sudo nft list chain inet fail2ban-filter f2b-forward | grep recidive"
echo "  (mal by vrátiť 2 pravidlá: IPv4 + IPv6)"
echo ""
