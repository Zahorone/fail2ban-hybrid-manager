#!/bin/bash

################################################################################
# FAIL2BAN v0.8 - CONFIGURATION FILES ARCHIVE
# Pre GitHub release — všetky konfiguračné súbory v jednom balíku
################################################################################

# Vytvor v0.8-config adresár so všetkými potrebnými súbormi

RELEASE_DIR="fail2ban-v0.8-configs"
mkdir -p "$RELEASE_DIR"/{jail.d,filter.d,action.d,nftables}

echo "📦 Vytvárám v0.8 konfiguračný balík..."

# =====================================================================
# FILE 1: jail.local v0.8
# =====================================================================

cat > "$RELEASE_DIR/jail.d/jail.local" << 'JAILEOF'
# =====================================================================
# FAIL2BAN HYBRID CONFIGURATION - OPTIMIZED v0.8
# Hybrid UFW + nftables orchestration s manualblock support
# GitHub: https://github.com/bakic-net/fail2ban-hybrid/releases/tag/v0.8
# =====================================================================

[DEFAULT]
destemail = zahor@tuta.io
sender = fail2ban@terminy.bakic.net
sendername = TermFail2Ban terminy.bakic.net
action = %(action_mwl)s
findtime = 600
bantime = 3600
maxretry = 5
backend = systemd
ignoreip = 127.0.0.1/8 ::1 192.168.0.0/16 10.0.0.0/8 172.16.0.0/12

# =====================================================================
# [sshd] - SSH BRUTE-FORCE DETECTION (UFW)
# =====================================================================
[sshd]
enabled = true
port = ssh
logpath = /var/log/auth.log
backend = %(sshd_backend)s
maxretry = 5
findtime = 600
bantime = 86400
action = ufw

# =====================================================================
# [recidive] - REPEAT OFFENDERS (UFW)
# =====================================================================
[recidive]
enabled = true
logpath = /var/log/fail2ban.log
action = ufw
maxretry = 10
findtime = 604800
bantime = 2592000

# =====================================================================
# [manualblock] - MANUÁLNE ZADANÉ IP (ZACHOVANÉ z v0.7.3)
# =====================================================================
[manualblock]
enabled = true
port = http,https,ssh
logpath = /etc/fail2ban/blocked-ips.txt
maxretry = 1
bantime = 31536000
action = ufw
filter = manualblock

# =====================================================================
# WEB/HTTP JAILY (NFTABLES) - OPTIMALIZOVANÉ
# =====================================================================

[f2b-exploit-critical]
enabled = true
port = http,https
logpath = /opt/rustnpm/data/logs/fallback_access.log
           /opt/rustnpm/data/logs/proxy-host-*_access.log
maxretry = 1
findtime = 600
bantime = 31536000
action = nftables[name=f2b-exploit]
unbanaction = nftables
filter = f2b-exploit-critical

[f2b-dos-high]
enabled = true
port = http,https
logpath = /opt/rustnpm/data/logs/fallback_access.log
           /opt/rustnpm/data/logs/proxy-host-*_access.log
maxretry = 1
findtime = 600
bantime = 604800
action = nftables[name=f2b-dos]
unbanaction = nftables
filter = f2b-dos-high

[f2b-web-medium]
enabled = true
port = http,https
logpath = /opt/rustnpm/data/logs/fallback_access.log
           /opt/rustnpm/data/logs/proxy-host-*_access.log
           /opt/rustnpm/data/logs/proxy-host-*_error.log
maxretry = 6
findtime = 600
bantime = 1800
bantime.increment = true
bantime.maxtime = 604800
bantime.overalljails = false
action = nftables[name=f2b-web]
unbanaction = nftables
filter = f2b-web-medium
JAILEOF

echo "✅ jail.local v0.8"

# =====================================================================
# FILE 2: FILTRY v0.8
# =====================================================================

cat > "$RELEASE_DIR/filter.d/f2b-exploit-critical.conf" << 'FILTEREOF'
# =====================================================================
# FILTER: f2b-exploit-critical
# RCE/CVE/Shell exploity - 1 ROK ban
# v0.8 Optimized
# =====================================================================

[Definition]
failregex = ^.*/vendor/phpunit/src/Util/PHP/eval-stdin\.php.*\[Client <HOST>\].*$
            ^.*allow_url_include.*php-cgi.*\[Client <HOST>\].*$
            ^.*/\.?_ignition/(execute-solution|api).*\[Client <HOST>\].*$
            ^.*/actuator.*\[Client <HOST>\].*$
            ^.*jndi:(ldap|rmi)://.*\[Client <HOST>\].*$
            ^.*system\(.*\[Client <HOST>\].*$
            ^.*shell_exec\(.*\[Client <HOST>\].*$
            ^.*exec\(.*\[Client <HOST>\].*$
            ^.*(wget|curl).*(sh|bash).*\|.*sh\[Client <HOST>\].*$
            ^.*/shell\.php.*\[Client <HOST>\].*$
            ^.*/backdoor\.php.*\[Client <HOST>\].*$

ignoreregex = ^.*booking/reschedule/.*$
FILTEREOF

cat > "$RELEASE_DIR/filter.d/f2b-dos-high.conf" << 'FILTEREOF'
# =====================================================================
# FILTER: f2b-dos-high
# IoT exploity, 444 HTTP, FastHTTP, Shellshock - 7 DNÍ ban
# v0.8 Optimized
# =====================================================================

[Definition]
failregex = ^.*444.*\[Client <HOST>\].*$
            ^.*(cgi-bin|goform|apply|boafrm|GponForm|dvr|setup\.cgi).*\[Client <HOST>\].*$
            ^.*\(\) \{ :; \};.*\[Client <HOST>\].*$
            ^.*(formSysCmd|boardDataWW|diag_Form).*\[Client <HOST>\].*$
            ^.*fasthttp.*\[Client <HOST>\].*$

ignoreregex =
FILTEREOF

cat > "$RELEASE_DIR/filter.d/f2b-web-medium.conf" << 'FILTEREOF'
# =====================================================================
# FILTER: f2b-web-medium
# 4xx errors, sensitive files recon, rate limiting - 30min-7d increment
# v0.8 Optimized
# =====================================================================

[Definition]
failregex = ^.* (400|401|403|404|429).*\[Client <HOST>\].*$
            ^.* GET https [^ ]+ "/\.git/.*" \[Client <HOST>\].*$
            ^.* GET https [^ ]+ "/\.env.*" \[Client <HOST>\].*$
            ^.* GET https [^ ]+ "/shell\.php" \[Client <HOST>\].*$
            ^.* GET https [^ ]+ "/admin.*" \[Client <HOST>\].*$
            ^.*limiting requests, excess:.*by zone.*<HOST>.*$

ignoreregex = ^.*booking/reschedule/.*$
              ^.*/assets/.*$
FILTEREOF

echo "✅ Filtry v0.8 (3x)"

# =====================================================================
# FILE 3: nftables v0.8
# =====================================================================

cat > "$RELEASE_DIR/nftables/nftables-v0.8.conf" << 'NFTEOF'
#!/usr/sbin/nft -f

# =====================================================================
# NFTABLES CONFIGURATION v0.8 - FAIL2BAN INTEGRATION
# Hybrid firewall pre UFW + Docker + Fail2Ban orchestration
# GitHub: https://github.com/bakic-net/fail2ban-hybrid/releases/tag/v0.8
# =====================================================================

# =====================================================================
# TABLE: inet filter (IPv4 + IPv6)
# =====================================================================

table inet fail2ban-filter {
  
  # SETS - Dynamické IP množiny pre fail2ban
  
  # EXPLOIT - 1 rok ban (RCE/CVE)
  set f2b-exploit {
    type ipv4_addr
    flags dynamic, timeout
    timeout 31536000s
    comment "v0.8: RCE/CVE exploity (1 rok)"
  }
  
  # DOS/IoT - 7 dní ban
  set f2b-dos {
    type ipv4_addr
    flags dynamic, timeout
    timeout 604800s
    comment "v0.8: IoT/DoS/444 (7 dní)"
  }
  
  # WEB - 30 min ban (increment control)
  set f2b-web {
    type ipv4_addr
    flags dynamic
    comment "v0.8: Web scans (increment 30min-7d)"
  }
  
  # IPv6 sety
  set f2b-exploit-v6 {
    type ipv6_addr
    flags dynamic, timeout
    timeout 31536000s
    comment "v0.8: RCE/CVE exploity IPv6 (1 rok)"
  }
  
  set f2b-dos-v6 {
    type ipv6_addr
    flags dynamic, timeout
    timeout 604800s
    comment "v0.8: IoT/DoS/444 IPv6 (7 dní)"
  }
  
  set f2b-web-v6 {
    type ipv6_addr
    flags dynamic
    comment "v0.8: Web scans IPv6 (increment)"
  }
  
  # INPUT chain
  chain input {
    type filter hook input priority filter; policy accept;
    
    # Fail2ban exploit bans (1 rok)
    ip saddr @f2b-exploit counter drop comment "v0.8-exploit"
    ip6 saddr @f2b-exploit-v6 counter drop comment "v0.8-exploit-v6"
    
    # Fail2ban dos bans (7 dní)
    ip saddr @f2b-dos counter drop comment "v0.8-dos"
    ip6 saddr @f2b-dos-v6 counter drop comment "v0.8-dos-v6"
    
    # Fail2ban web bans (30 min - 7 dní increment)
    ip saddr @f2b-web counter drop comment "v0.8-web"
    ip6 saddr @f2b-web-v6 counter drop comment "v0.8-web-v6"
  }
  
  # FORWARD chain (Docker - spravuje docker-firewall.service)
  chain forward {
    type filter hook forward priority filter; policy accept;
  }
}

# =====================================================================
# TABLE: ip filter (IPv4 only - legacy compatibility)
# =====================================================================

table ip fail2ban-v4 {
  
  set f2b-exploit {
    type ipv4_addr
    flags dynamic, timeout
    timeout 31536000s
  }
  
  set f2b-dos {
    type ipv4_addr
    flags dynamic, timeout
    timeout 604800s
  }
  
  set f2b-web {
    type ipv4_addr
    flags dynamic
  }
  
  chain input {
    type filter hook input priority filter; policy accept;
    ip saddr @f2b-exploit counter drop comment "v0.8-exploit"
    ip saddr @f2b-dos counter drop comment "v0.8-dos"
    ip saddr @f2b-web counter drop comment "v0.8-web"
  }
}

# =====================================================================
# TABLE: ip6 filter (IPv6 only - legacy compatibility)
# =====================================================================

table ip6 fail2ban-v6 {
  
  set f2b-exploit {
    type ipv6_addr
    flags dynamic, timeout
    timeout 31536000s
  }
  
  set f2b-dos {
    type ipv6_addr
    flags dynamic, timeout
    timeout 604800s
  }
  
  set f2b-web {
    type ipv6_addr
    flags dynamic
  }
  
  chain input {
    type filter hook input priority filter; policy accept;
    ip6 saddr @f2b-exploit counter drop comment "v0.8-exploit"
    ip6 saddr @f2b-dos counter drop comment "v0.8-dos"
    ip6 saddr @f2b-web counter drop comment "v0.8-web"
  }
}
NFTEOF

echo "✅ nftables-v0.8.conf"

# =====================================================================
# SUMMARY
# =====================================================================

cat << 'SUMMARY'

════════════════════════════════════════════════════════════════════

✅ v0.8 KONFIGURAČNÝ BALÍK VYTVORENÝ:

📦 Obsah ($RELEASE_DIR/):

  jail.d/
  └─ jail.local          ← Hlavná konfigurácia (5 jailov)
  
  filter.d/
  ├─ f2b-exploit-critical.conf    ← RCE/CVE filtery
  ├─ f2b-dos-high.conf            ← IoT/444 filtery
  └─ f2b-web-medium.conf          ← 4xx/recon filtery
  
  nftables/
  └─ nftables-v0.8.conf           ← nftables konfigurácia (3 sety)

════════════════════════════════════════════════════════════════════

🚀 INŠTALÁCIA:

  sudo bash fail2ban_v0.8-setup.sh

════════════════════════════════════════════════════════════════════

📖 DOKUMENTÁCIA:

  README-v0.8.md

════════════════════════════════════════════════════════════════════

SUMMARY

echo ""
echo "✅ Všetko hotovo! Adresár: $RELEASE_DIR"
ls -la "$RELEASE_DIR"/*
