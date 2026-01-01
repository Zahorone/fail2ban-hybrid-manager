## v0.33 - PHP Error Detection & Docker Auto-Sync

**Release Date:** 2026-01-01  
**Status:** Production Ready  
**Breaking Changes:** None (safe upgrade from v0.31)

---

### 🎯 Production Release

Full IPv4/IPv6 dual-stack protection with critical Docker-block improvements and universal PHP error detection for **all PHP applications** (WordPress, Laravel, Symfony, Magento, EasyAppointment, custom apps, etc.).

### ✨ Key Highlights

- ⭐ **nginx-php-errors Jail (NEW)** - PHP fatal error & HTTP 5xx anomaly detection for ALL PHP applications
- 🐳 **Docker-Block v0.4 (CRITICAL)** - Two-tier auto-sync (validate every 1min, full every 15min) + immediate bans via hook
- 🌐 **24 nftables Sets** - Full IPv4/IPv6 coverage (12 jails × 2 protocols)
- 🛠️ **Wrapper v0.33** - 50+ functions with enhanced monitoring
- 📧 **Interactive Installer** - Email config + SSH IP detection + Docker whitelist

---

### 📦 What's New

#### Added

**nginx-php-errors Jail (NEW)** ⭐
Universal PHP error detection for all PHP applications:
- Filter: `nginx-php-errors.conf`
- Sets: `f2b-nginx-php-errors` (IPv4) + `f2b-nginx-php-errors-v6` (IPv6)
- Ban time: 7 days (configurable)
- Works with: WordPress, Laravel, Symfony, Magento, EasyAppointment, custom PHP apps
- Detects: PHP fatal errors, parse errors, HTTP 5xx patterns
- Compatible with nginx reverse proxy (X-Real-IP headers)

**Docker Auto-Sync Cron (CRITICAL)** 🐳
Two-tier synchronization strategy:

1. **Validate Cron** – Every 1 minute (`*/1`)
   - Quick validation & repair of inconsistencies between Fail2Ban, nftables, and docker-block
   - Non-invasive (doesn't modify or delete valid bans)
   - Uses `flock` to prevent concurrent execution
   - Log: `syslog` with tag `f2b-docker-validate`

2. **Full Sync Cron** – Every 15 minutes (`*/15`)
   - Complete re-sync of all banned IPs to docker-block
   - Handles edge cases and recovery scenarios
   - Ensures maximum consistency
   - Log: `syslog` with tag `f2b-docker-full`

3. **Immediate Bans** – Real-time via fail2ban hook
   - Banned IPs are dropped immediately (no cron delay)
   - Uses `docker-sync-hook` action integrated with Fail2Ban
   - Zero latency between ban and enforcement

**Interactive Installer v0.33**
- Restored Email/Network configuration with auto-detection
- Auto-detect mail service for notifications
- Auto-detect server IP (optional whitelist)
- Configure Docker subnet whitelist (ignoreip)
- Pre-cleanup with nftables backup

#### Changed
- nftables: 22 → 24 sets (added PHP jail IPv4/IPv6)
- INPUT rules: 22 → 24 (added PHP jail rules)
- FORWARD rules: 6 → 8 (improved Docker container protection)
- All jails now use `nftables-multiport` with docker-hook integration
- Wrapper v0.33 with enhanced logging and diagnostics
- Docker sync strategy: Two-tier (validate + full) + immediate hook

#### Fixed
- Docker container restarts no longer clear nftables bans (two-tier sync)
- Race conditions in fail2ban-client during high load (flock mechanism)
- Email configuration conflicts in installer
- IPv6 address logging consistency
- Edge cases in docker-block synchronization (full sync fallback)

---

### 📊 Infrastructure Comparison

| Feature | v0.31 | v0.33 |
|---------|-------|-------|
| **Jails** | 11 | **12** ⭐ |
| **nftables Sets** | 22 (11+11) | **24 (12+12)** ⭐ |
| **INPUT Rules** | 22 | **24** |
| **FORWARD Rules** | 6 | **8** |
| **Docker Sync Strategy** | ✅ Immediate hook + cron | ✅ Two-tier + immediate hook |
| **Sync Validate** | Every 1 min | **Every 1 min (improved)** |
| **Sync Full** | Every 1 min | **Every 15 min (new)** |
| **PHP Error Detection** | ❌ | **✅ NEW** |
| **Total Files** | 34 | **42** |

---

### 🚀 Installation

**Quick Start:**
```bash
# Download
wget https://github.com/Zahorone/fail2ban-hybrid-manager/releases/download/v0.33/fail2ban-hybrid-manager-v0.33.tar.gz

# Extract & Install
tar -xzf fail2ban-hybrid-manager-v0.33.tar.gz
cd v0.33/
sudo bash INSTALL-ALL-v033.sh

# Verify
sudo f2b status
sudo f2b doctor
```

**Installation Steps:**
1. Pre-cleanup (backup nftables)
2. Install nftables infrastructure (24 sets)
3. Install Fail2Ban jails (12 jails)
4. Install wrapper v0.33 (50+ functions)
5. Install Docker port blocking v0.4
6. Install auto-sync service
7. Install bash aliases
8. Setup docker-block auto-sync crons ⚠️ **CRITICAL**
   - Validate cron (every 1 minute)
   - Full sync cron (every 15 minutes)
   - Immediate hook integration
9. Final verification

---

### 🔄 Upgrade from v0.31

```bash
# Backup existing installation
sudo cp -r /etc/fail2ban /etc/fail2ban.backup-v031

# Extract & Install v0.33
tar -xzf fail2ban-hybrid-manager-v0.33.tar.gz
cd v0.33/
sudo bash INSTALL-ALL-v033.sh

# Verify upgrade
sudo f2b status
sudo nft list table inet fail2ban-filter | grep "set f2b" | wc -l
# Should show: 24 sets

# Verify cron jobs
sudo crontab -l | grep f2b-docker
# Should show 2 lines: validate (*/1) and full (*/15)
```

**Preserves:**
- ✅ All existing banned IPs (IPv4 + IPv6)
- ✅ Custom jail.local settings
- ✅ Email notifications configuration
- ✅ Docker whitelists

**Adds:**
- 📝 12th jail: nginx-php-errors
- 📝 2 new IPv6 sets
- 📝 Two-tier docker sync crons (validate + full)
- 📝 Enhanced wrapper v0.33

---

### 🛠️ Quick Commands

```bash
# Check status
sudo f2b status

# Monitor live attacks
sudo f2b monitor watch

# List banned IPs
sudo f2b list banned

# Ban/unban IPs
sudo f2b ban 192.168.1.100
sudo f2b unban 192.168.1.100

# Docker sync (manual)
sudo f2b docker sync validate    # Quick validation & repair
sudo f2b docker sync full        # Complete re-sync

# Generate reports
sudo f2b report json
sudo f2b report csv

# System diagnostics
sudo f2b doctor

# Check PHP errors jail
sudo f2b status nginx-php-errors

# Check docker sync crons
sudo crontab -l | grep f2b-docker
```

---

### ✅ Verified On

- ✅ Ubuntu 20.04/22.04/24.04 LTS
- ✅ Debian 11/12
- ✅ Fail2Ban v0.11+
- ✅ nftables v0.9+
- ✅ Docker 20.10+ (optional)
- ✅ All PHP frameworks (WordPress, Laravel, Symfony, Magento, EasyAppointment, custom apps)

---

### 📋 All 12 Jails

1. **sshd** – SSH brute-force attacks
2. **sshd-slowattack** – Slow SSH attacks (< 3 attempts/min)
3. **f2b-exploit-critical** – Critical exploits & RCE attempts
4. **f2b-dos-high** – DoS/DDoS patterns
5. **f2b-web-medium** – SQLi, path traversal, XSS
6. **nginx-recon-optimized** – Nginx recon attempts
7. **f2b-fuzzing-payloads** – Fuzzing & polyglot payloads
8. **f2b-botnet-signatures** – Known botnet signatures
9. **f2b-anomaly-detection** – Anomaly pattern matching
10. **nginx-php-errors** ⭐ **NEW** – PHP fatals & HTTP 5xx (all PHP apps)
11. **manualblock** – Manual IP banning
12. **recidive** – 30-day repeat offenders

---

### 🎯 PHP Error Detection Features

**Universal PHP Error Coverage:**
- ✅ Catches script injection attempts early
- ✅ Detects service abuse patterns (HTTP 5xx spikes)
- ✅ Prevents "Fatal error in X.php" DoS attacks
- ✅ Works with all PHP frameworks and custom apps
- ✅ Compatible with nginx reverse proxy (X-Real-IP)
- ✅ Docker-aware (persistent bans across restarts)

**Perfect For:**
- WordPress, Drupal, Joomla, custom PHP apps
- Laravel, Symfony, Yii, Zend Framework
- Magento e-commerce
- EasyAppointment appointment system
- Any nginx + PHP-FPM setup

---

### 🐋 Docker Auto-Sync Architecture

**Three-Layer Protection:**

1. **Immediate Hook** (Real-time, < 100ms)
   - Triggered by Fail2Ban action immediately upon ban
   - Drops banned IP in nftables before container sees it
   - Uses `docker-sync-hook` action
   - Zero latency

2. **Validate Cron** (Every 1 minute)
   - Checks consistency between Fail2Ban and docker-block
   - Repairs drift without deleting valid bans
   - Non-blocking with `flock` mechanism
   - Lightweight operation

3. **Full Sync Cron** (Every 15 minutes)
   - Complete re-sync of all bans
   - Safety net for edge cases
   - Ensures maximum consistency
   - Heavier operation, runs less frequently

**Result:**
- ✅ Immediate enforcement (hook)
- ✅ Consistency validation (every 1 min)
- ✅ Recovery safety net (every 15 min)
- ✅ Persistent bans across container restarts

---

### 🐛 Troubleshooting

**Docker-Block Not Syncing?**
```bash
# Check cron jobs
sudo crontab -l | grep f2b-docker

# Manual validate
sudo f2b docker sync validate

# Manual full sync
sudo f2b docker sync full

# Check logs
sudo tail -f /var/log/syslog | grep f2b-docker
```

**Missing IPv6 Sets?**
```bash
sudo nft list table inet fail2ban-filter | grep "\-v6" | wc -l
# Should show: 12
```

**PHP Errors Not Detected?**
```bash
sudo tail -f /var/log/nginx/error.log
sudo f2b status nginx-php-errors
sudo f2b filter test nginx-php-errors "/var/log/nginx/error.log"
```

**Bans Disappearing After Container Restart?**
```bash
# Verify crons are active
sudo crontab -l | grep f2b-docker
# Should show 2 lines

# Check if hook is working
sudo tail -f /var/log/fail2ban.log | grep docker-sync-hook

# Manual re-sync if needed
sudo f2b docker sync full
```

---

### 📦 Package Contents

```
v0.33/ (42 files)
├── INSTALL-ALL-v033.sh               # Main installer (interactive)
├── scripts/                          # 8 install scripts
│   ├── 00-pre-cleanup-v033.sh
│   ├── 01-install-nftables-v033.sh
│   ├── 02-install-jails-v033.sh
│   ├── 02-verify-jails-v033.sh
│   ├── 03-install-wrapper-v033.sh
│   ├── 04-install-docker-block-v033.sh
│   ├── 05-install-auto-sync-v033.sh
│   ├── 06-install-aliases-v033.sh
│   └── 07-setup-docker-sync-cron-v033.sh
├── filters/                          # 12 filter configs
│   ├── sshd.conf
│   ├── f2b-*.conf (9 filters)
│   └── nginx-php-errors.conf ⭐ NEW
├── actions/                          # Action scripts
│   ├── nftables-multiport
│   ├── nftables-allports
│   ├── docker-hook
│   └── f2b-docker-hook.sh
├── config/                           # Configuration files
│   ├── jail.local
│   ├── *.local (local tuning files)
│   └── nginx-php-errors.local ⭐ NEW
├── f2b-wrapper-v033.sh              # Main wrapper (50+ functions)
├── README.md                         # Full documentation
├── CHANGELOG.md                      # Detailed version history
├── MIGRATION-GUIDE.md                # v0.31 → v0.33 upgrade guide
├── PACKAGE-INFO.txt                  # Package metadata
└── LICENSE                           # MIT License
```

---

### 🔗 Documentation

- **README.md** – Full feature overview and quick start
- **CHANGELOG.md** – Detailed version history and improvements
- **MIGRATION-GUIDE.md** – Step-by-step upgrade from v0.31
- **PACKAGE-INFO.txt** – Technical details and system requirements

---

### 📌 Key Improvements Summary

**New in v0.33:**
- 12 jails (was 11)
- 24 nftables sets (was 22)
- 24 INPUT rules (was 22)
- 8 FORWARD rules (was 6)
- nginx-php-errors jail for all PHP applications
- Two-tier docker sync (validate every 1min, full every 15min) + immediate hook
- Enhanced wrapper with better diagnostics
- Interactive installer with auto-detection

**What's Preserved:**
- All existing banned IPs survive upgrade
- All custom configurations preserved
- All Docker whitelists intact
- Zero downtime upgrade possible

---

### ✅ Production Ready

v0.33 is recommended for:
- ✅ All PHP-based applications (WordPress, Laravel, EasyAppointment, etc.)
- ✅ Docker and containerized deployments
- ✅ High-traffic production environments
- ✅ Servers needing aggressive intrusion detection
- ✅ IPv4 and IPv6 dual-stack networks

---

**v0.33 - Production Ready for All PHP Applications & Docker Deployments** 🚀
