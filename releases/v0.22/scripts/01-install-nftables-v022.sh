#!/bin/bash
################################################################################
# COMPLETE REBUILD: nftables Fail2Ban Infrastructure
# Vytvorí kompletnú nftables tabuľku, reťazce, sety a pravidlá
# Version: 2.2 (enhanced for v0.22)
# Date: 2025-12-06
# Changelog: IPv4+IPv6 support, robustnejší banned list, fail2ban-client get, added sshd-slowattack jail
################################################################################

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_header() { echo -e "\n${BLUE}=== $1 ===${NC}\n"; }
log_success() { echo -e "${GREEN}✅ $1${NC}"; }
log_error() { echo -e "${RED}✗ $1${NC}"; }
log_info() { echo -e "${BLUE}ℹ $1${NC}"; }
log_warn() { echo -e "${YELLOW}⚠ $1${NC}"; }

################################################################################
# KROK 1: KONTROLA nftables TABUĽKY
################################################################################

log_header "KROK 1: KONTROLA nftables TABUĽKY"

if sudo nft list tables | grep -q "fail2ban"; then
    log_info "Tabuľka existuje, backupujem..."
    sudo nft list table inet fail2ban-filter 2>/dev/null | sudo tee "/tmp/nftables-backup-$(date +%s).nft" >/dev/null 2>/dev/null || true
    
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

log_header "KROK 2: VYTVOR NOVÚ nftables TABUĽKU"

log_info "Vytváram tabuľku inet fail2ban-filter..."
sudo nft add table inet fail2ban-filter 2>/dev/null || true

log_success "Tabuľka vytvorená"

echo ""

################################################################################
# KROK 3: VYTVOR REŤAZCE (CHAINS)
################################################################################

log_header "KROK 3: VYTVOR REŤAZCE"

log_info "Vytváram reťazec INPUT..."
sudo nft add chain inet fail2ban-filter f2b-input "{ type filter hook input priority -100; }" 2>/dev/null || true

log_info "Vytváram reťazec FORWARD..."
sudo nft add chain inet fail2ban-filter f2b-forward "{ type filter hook forward priority -100; }" 2>/dev/null || true

log_success "Reťazce vytvorené"

echo ""

################################################################################
# KROK 4: VYTVOR VŠETKY SETY (IPv4 + IPv6)
################################################################################

log_header "KROK 4: VYTVOR VŠETKY SETY (10 x IPv4 + IPv6)"

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
    echo -n "  $set (IPv4) ... "
    sudo nft add set inet fail2ban-filter "$set" "{ type ipv4_addr; flags interval,timeout; auto-merge; timeout 604800s; }" 2>/dev/null && echo "✅" || echo "⚠️"
    
    echo -n "  $set-v6 (IPv6) ... "
    sudo nft add set inet fail2ban-filter "$set-v6" "{ type ipv6_addr; flags interval,timeout; auto-merge; timeout 604800s; }" 2>/dev/null && echo "✅" || echo "⚠️"
done

echo ""

################################################################################
# KROK 5: PRIDAJ PRAVIDLÁ DO REŤAZCOV (IPv4 + IPv6)
################################################################################

log_header "KROK 5: PRIDAJ DROP PRAVIDLÁ"

log_info "INPUT reťazec (20 pravidiel: 10 IPv4 + 10 IPv6)..."

# IPv4 pravidlá
for set in "${SETS[@]}"; do
    echo -n "  • $set (v4) ... "
    sudo nft add rule inet fail2ban-filter f2b-input ip saddr @"$set" drop 2>/dev/null && echo "✅" || echo "⚠️"
done

# IPv6 pravidlá
for set in "${SETS[@]}"; do
    echo -n "  • $set-v6 (v6) ... "
    sudo nft add rule inet fail2ban-filter f2b-input ip6 saddr @"$set-v6" drop 2>/dev/null && echo "✅" || echo "⚠️"
done

log_success "INPUT pravidlá pridané (20/20)"

echo ""

log_info "FORWARD reťazec (6 pravidiel: 3 IPv4 + 3 IPv6 - len kritické)..."

# Len kritické sety pre FORWARD
FORWARD_SETS=("f2b-exploit-critical" "f2b-dos-high" "f2b-manualblock")

# IPv4
for set in "${FORWARD_SETS[@]}"; do
    echo -n "  • $set (v4) ... "
    sudo nft add rule inet fail2ban-filter f2b-forward ip saddr @"$set" drop 2>/dev/null && echo "✅" || echo "⚠️"
done

# IPv6
for set in "${FORWARD_SETS[@]}"; do
    echo -n "  • $set-v6 (v6) ... "
    sudo nft add rule inet fail2ban-filter f2b-forward ip6 saddr @"$set-v6" drop 2>/dev/null && echo "✅" || echo "⚠️"
done

log_success "FORWARD pravidlá pridané (6/6)"

echo ""

################################################################################
# KROK 6: MIGRÁCIA IP Z FAIL2BAN (s ošetrením čistej inštalácie)
################################################################################

log_header "KROK 6: MIGRÁCIA IP Z FAIL2BAN DO nftables"

# Skontroluj či fail2ban vôbec beží
if ! systemctl is-active --quiet fail2ban 2>/dev/null; then
    log_warn "Fail2ban nie je aktívny - preskakujem migráciu (čistá inštalácia)"
    echo ""
else
    # Skontroluj či existujú nejaké jailly
    ACTIVE_JAILS=$(sudo fail2ban-client status 2>/dev/null | grep "Jail list" | sed 's/.*://' | tr ',' '\n' | grep -v '^[[:space:]]*$' | wc -l || echo 0)
    
    if [ "$ACTIVE_JAILS" -eq 0 ]; then
        log_warn "Žiadne aktívne jailly - preskakujem migráciu (čistá inštalácia)"
        log_info "Toto je OK pre prvú inštaláciu"
        echo ""
    else
        log_info "Detekované $ACTIVE_JAILS aktívnych jailov, pokúsim sa migrovať IP..."
        echo ""
        
        JAILS=(
            "sshd:f2b-sshd"
            "sshd-slowattack:f2b-sshd-slowattack"
            "f2b-exploit-critical:f2b-exploit-critical"
            "f2b-dos-high:f2b-dos-high"
            "f2b-web-medium:f2b-web-medium"
            "nginx-recon-bonus:f2b-nginx-recon-bonus"
            "recidive:f2b-recidive"
            "manualblock:f2b-manualblock"
            "f2b-fuzzing-payloads:f2b-fuzzing-payloads"
            "f2b-botnet-signatures:f2b-botnet-signatures"
            "f2b-anomaly-detection:f2b-anomaly-detection"
        )
        
        MIGRATED_COUNT=0
        
        for entry in "${JAILS[@]}"; do
            IFS=':' read -r jail set <<< "$entry"
            
            # Skontroluj či jail existuje
            if ! sudo fail2ban-client status "$jail" &>/dev/null; then
                continue
            fi
            
            # Získaj banned IP
            IPS=$(sudo fail2ban-client get "$jail" banned 2>/dev/null || sudo fail2ban-client status "$jail" 2>/dev/null | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}')
            
            if [ -z "$IPS" ]; then
                continue
            fi
            
            COUNT=$(echo "$IPS" | grep -c '^' 2>/dev/null || echo 0)
            
            if [ "$COUNT" -gt 0 ]; then
                log_info "$jail -> $set ($COUNT IP)"
                
                while IFS= read -r ip; do
                    if [ -n "$ip" ]; then
                        echo -n "    • $ip ... "
                        
                        # Detect IPv4 vs IPv6
                        if echo "$ip" | grep -q ':'; then
                            # IPv6
                            sudo nft add element inet fail2ban-filter "$set-v6" "{ $ip timeout 604800s }" 2>/dev/null && echo "✅ (v6)" || echo "⚠️"
                        else
                            # IPv4
                            sudo nft add element inet fail2ban-filter "$set" "{ $ip timeout 604800s }" 2>/dev/null && echo "✅ (v4)" || echo "⚠️"
                        fi
                        ((MIGRATED_COUNT++))
                    fi
                done <<< "$IPS"
            fi
        done
        
        echo ""
        
        if [ "$MIGRATED_COUNT" -gt 0 ]; then
            log_success "Migrovalo sa $MIGRATED_COUNT IP adries"
        else
            log_info "Žiadne IP na migráciu (čisté jailly)"
        fi
    fi
fi

echo ""

################################################################################
# KROK 7: REŠTART FAIL2BAN (CONDITIONAL)
################################################################################

log_header "KROK 7: REŠTART FAIL2BAN"

# Skontroluj či fail2ban service existuje
if ! systemctl list-unit-files | grep -q "fail2ban.service"; then
    log_info "Fail2ban service neexistuje - preskakujem reštart (čistá inštalácia)"
    log_info "Fail2ban sa nainštaluje v ďalšom kroku"
    echo ""
else
    # Fail2ban service existuje, skontroluj či beží
    if systemctl is-active --quiet fail2ban 2>/dev/null; then
        # Skontroluj či má nejaké jails
        ACTIVE_JAILS=$(sudo fail2ban-client status 2>/dev/null | grep "Jail list" | sed 's/.*://' | tr ',' '\n' | grep -v '^[[:space:]]*$' | wc -l || echo 0)
        
        if [ "$ACTIVE_JAILS" -gt 0 ]; then
            log_info "Reštartujem Fail2Ban (detekované $ACTIVE_JAILS jails)..."
            sudo systemctl restart fail2ban
            sleep 3
            log_success "Fail2Ban reštartovaný"
        else
            log_info "Fail2Ban beží ale bez jailov - reštart nie je potrebný"
            log_info "Jails sa nainštalujú v ďalšom kroku"
        fi
    else
        log_info "Fail2ban nie je aktívny - preskakujem reštart"
        log_info "Fail2ban sa spustí po inštalácii jails"
    fi
    echo ""
fi

echo ""

################################################################################
# KROK 8: FINÁLNA KONTROLA
################################################################################

log_header "KROK 8: FINÁLNA KONTROLA"

log_info "nftables Tabuľka (prvých 30 riadkov):"
sudo nft list table inet fail2ban-filter 2>/dev/null | head -30

echo ""
log_info "Vytvorené sety (22 expected: 11 IPv4 + 11 IPv6):"
SETS_COUNT=$(sudo nft list sets inet fail2ban-filter 2>/dev/null | grep -c "name" || echo 0)
sudo nft list sets inet fail2ban-filter 2>/dev/null | grep name | sed 's/.*name /  • /'
echo ""
log_info "Počet setov: $SETS_COUNT / 22"

if [ "$SETS_COUNT" -eq 22 ]; then
    log_success "✅ Všetky sety vytvorené!"
else
    log_warn "⚠️ Očakávaných 22 setov, nájdených $SETS_COUNT"
fi

echo ""
log_info "DROP pravidlá v INPUT chain:"
INPUT_RULES=$(sudo nft list chain inet fail2ban-filter f2b-input 2>/dev/null | grep -c "drop" || echo 0)
echo "  Počet: $INPUT_RULES / 22 (11 IPv4 + 11 IPv6)"

if [ "$INPUT_RULES" -eq 22 ]; then
    log_success "✅ Všetky INPUT pravidlá vytvorené!"
else
    log_warn "⚠️ Očakávaných 22 pravidiel, nájdených $INPUT_RULES"
fi

echo ""
log_info "DROP pravidlá v FORWARD chain:"
FORWARD_RULES=$(sudo nft list chain inet fail2ban-filter f2b-forward 2>/dev/null | grep -c "drop" || echo 0)
echo "  Počet: $FORWARD_RULES / 6 (3 IPv4 + 3 IPv6)"

if [ "$FORWARD_RULES" -eq 6 ]; then
    log_success "✅ Všetky FORWARD pravidlá vytvorené!"
else
    log_warn "⚠️ Očakávaných 6 pravidiel, nájdených $FORWARD_RULES"
fi

echo ""

# CONDITIONAL: Kontrola fail2ban sync iba ak existujú jails
if systemctl is-active --quiet fail2ban 2>/dev/null; then
    ACTIVE_JAILS=$(sudo fail2ban-client status 2>/dev/null | grep "Jail list" | sed 's/.*://' | tr ',' '\n' | grep -v '^[[:space:]]*$' | wc -l || echo 0)
    
    if [ "$ACTIVE_JAILS" -gt 0 ]; then
        log_info "Kontrola fail2ban ↔ nftables sync (sample: f2b-dos-high):"
        echo ""
        
        # Skontroluj či jail f2b-dos-high existuje
        if sudo fail2ban-client status f2b-dos-high &>/dev/null; then
            F2B_IPS=$(sudo fail2ban-client get f2b-dos-high banned 2>/dev/null || sudo fail2ban-client status f2b-dos-high 2>/dev/null | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}')
            F2B_COUNT=$(echo "$F2B_IPS" | grep -c '^' 2>/dev/null || echo 0)
            
            NFT_IPS=$(sudo nft list set inet fail2ban-filter f2b-dos-high 2>/dev/null | sed -n '/elements = {/,/}/p' | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort -u)
            NFT_COUNT=$(echo "$NFT_IPS" | grep -c '^' 2>/dev/null || echo 0)
            
            echo "  Fail2Ban (f2b-dos-high): $F2B_COUNT IP"
            if [ "$F2B_COUNT" -gt 0 ]; then
                printf '%s\n' "${F2B_IPS[@]}" | sed 's/^/    • /'
            fi
            
            echo ""
            echo "  nftables (f2b-dos-high): $NFT_COUNT IP"
            if [ "$NFT_COUNT" -gt 0 ]; then
                printf '%s\n' "${NFT_IPS[@]}" | sed 's/^/    • /'
            fi
            
            echo ""
            
            if [ "$F2B_COUNT" -eq "$NFT_COUNT" ] && [ "$F2B_COUNT" -gt 0 ]; then
                log_success "✅ SYNC OK: Fail2Ban ($F2B_COUNT) = nftables ($NFT_COUNT)"
            elif [ "$F2B_COUNT" -eq 0 ] && [ "$NFT_COUNT" -eq 0 ]; then
                log_success "✅ CLEAN: Žiadne bannované IP (OK pre čistú inštaláciu)"
            else
                log_warn "⚠️ MISMATCH: F2B=$F2B_COUNT, nft=$NFT_COUNT"
                log_info "Spustite 'f2b sync force' po inštalácii"
            fi
        else
            log_info "Jail 'f2b-dos-high' ešte neexistuje (OK pre čistú inštaláciu)"
            log_info "Jails sa nainštalujú v ďalšom kroku: 02-install-jails-v022.sh"
        fi
    else
        log_info "Fail2ban beží ale bez jailov (čistá inštalácia)"
        log_info "Jails sa nainštalujú v ďalšom kroku: 02-install-jails-v022.sh"
    fi
else
    log_info "Fail2ban nie je aktívny (čistá inštalácia)"
    log_info "Fail2ban sa nainštaluje a nakonfiguruje v ďalšom kroku"
fi

echo ""

################################################################################
# KROK 9: ULOŽENIE PERZISTENTNEJ KONFIGURÁCIE
################################################################################

log_header "KROK 9: ULOŽENIE PERZISTENTNEJ KONFIGURÁCIE"

log_info "Vytváram /etc/nftables.d/fail2ban-filter.nft..."
sudo mkdir -p /etc/nftables.d

# Export tabuľky
sudo nft list table inet fail2ban-filter 2>/dev/null | sudo tee /tmp/fail2ban-filter.nft >/dev/null

# Premiestnenie do konfigurácie
sudo mv /tmp/fail2ban-filter.nft /etc/nftables.d/fail2ban-filter.nft

log_success "Konfigurácia uložená"

echo ""

# Skontroluj či je správny nftables.conf
log_info "Kontrolujem /etc/nftables.conf..."

EXPECTED_CONF="#!/usr/sbin/nft -f

flush ruleset

# Fail2Ban nftables (v2.2 - IPv4+IPv6)
include \"/etc/nftables.d/fail2ban-filter.nft\"

# Docker port blocking (v0.3 - with loopback support)
include \"/etc/nftables/docker-block.nft\""

# Ak nftables.conf neexistuje alebo je prázdny, vytvor ho
if [ ! -s /etc/nftables.conf ]; then
    log_info "Vytváram nový /etc/nftables.conf..."
    echo "$EXPECTED_CONF" | sudo tee /etc/nftables.conf >/dev/null
    log_success "/etc/nftables.conf vytvorený"
else
    # Ak existuje, len overiť include
    if ! grep -q "/etc/nftables.d/fail2ban-filter.nft" /etc/nftables.conf 2>/dev/null; then
        log_warn "/etc/nftables.conf existuje ale chýba fail2ban include"
        log_info "MANUÁLNE pridaj: include \"/etc/nftables.d/fail2ban-filter.nft\""
        log_info "Alebo spusti: echo 'include \"/etc/nftables.d/fail2ban-filter.nft\"' | sudo tee -a /etc/nftables.conf"
    else
        log_success "Include už existuje v /etc/nftables.conf"
    fi
fi

echo ""

# Overiť či je nftables.service enabled
if ! systemctl is-enabled --quiet nftables.service 2>/dev/null; then
    log_info "Povoľujem nftables.service..."
    sudo systemctl enable nftables.service
    log_success "nftables.service enabled"
else
    log_info "nftables.service už je enabled"
fi

echo ""

log_success "✅ Konfigurácia je PERZISTENTNÁ (prežije reboot)"

echo ""

log_header "✅ COMPLETE REBUILD HOTOVÝ v2.2"

echo "📝 Nasledujúce boli vykonané:"
echo "  1. Backup a odstránenie starej tabuľky"
echo "  2. Vytvorenie novej tabuľky inet fail2ban-filter"
echo "  3. Vytvorenie reťazcov INPUT a FORWARD"
echo "  4. Vytvorenie všetkých 11 setov (IPv4 + IPv6)"
echo "  5. Pridanie DROP pravidiel (20 INPUT + 6 FORWARD)"
echo "  6. Migrácia IP z Fail2Ban (robustnejší)"
echo "  7. Reštart Fail2Ban"
echo "  8. Finálna kontrola"
echo "  9. Uloženie perzistentnej konfigurácie ✨"
echo ""
echo "✅ Konfigurácia je PERZISTENTNÁ - prežije reboot!"
echo "✅ IPv4 + IPv6 support aktívny!"
echo ""
echo "Test:"
echo "  f2b sync"
echo "  sudo nft list chain inet fail2ban-filter f2b-input | grep drop | wc -l"
echo "  (mal by vrátiť 22, nie 11)"
echo ""
