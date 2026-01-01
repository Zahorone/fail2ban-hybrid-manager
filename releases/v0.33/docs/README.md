# 🚀 Fail2Ban Hybrid Manager v0.33 - EasyAppointment Optimized

**Release Date:** 2026-01-01  
**Wrapper:** v0.33 (50+ functions)  
**Total Files:** 42  
**Status:** Production Ready

---

## ✨ Key Features

✅ **12 Jails, 24 nftables Sets** - Full IPv4/IPv6 dual-stack protection  
✅ **nginx-php-errors Jail (NEW)** - Dedicated PHP fatal error & 5xx anomaly detection  
✅ **Docker-Block v0.4 (CRITICAL)** - Auto-sync cron every 1 minute → persistent bans after container restart  
✅ **Wrapper v0.33** - 50+ functions: status, monitor, report (JSON/CSV), docker sync, doctor  
✅ **Interactive Installer** - Email notifications, SSH client IP detection, Docker subnet whitelist  
✅ **Safe Upgrade** - From v0.31 preserves all existing bans + adds PHP jail  
✅ **Production Ready** - 12 jails, 24 nftables sets, 24 INPUT + 8 FORWARD rules  
✅ **EasyAppointment Optimized** - PHP error detection, nginx proxy support, Docker-aware  

---

## 📋 Infrastructure Overview

### Jails (12 Total)
1. **sshd** - SSH brute-force (IPv4 + IPv6)
2. **sshd-slowattack** - Slow SSH attacks (IPv4 + IPv6)
3. **f2b-exploit-critical** - Critical exploits (IPv4 + IPv6)
4. **f2b-dos-high** - DoS/DDoS patterns (IPv4 + IPv6)
5. **f2b-web-medium** - SQLi, path traversal (IPv4 + IPv6)
6. **nginx-recon-optimized** - Nginx recon attempts (IPv4 + IPv6)
7. **f2b-fuzzing-payloads** - Fuzzing detection (IPv4 + IPv6)
8. **f2b-botnet-signatures** - Botnet signatures (IPv4 + IPv6)
9. **f2b-anomaly-detection** - Anomaly patterns (IPv4 + IPv6)
10. **nginx-php-errors** ⭐ NEW - PHP fatals + HTTP 5xx (IPv4 + IPv6)
11. **manualblock** - Manual IP banning (IPv4 + IPv6)
12. **recidive** - 30-day repeat offenders (IPv4)

### nftables Sets (24 Total)
- **12 IPv4 Sets**: `f2b-sshd`, `f2b-exploit-critical`, `f2b-dos-high`, ... (one per jail)
- **12 IPv6 Sets**: `f2b-sshd-v6`, `f2b-exploit-critical-v6`, ... (one per jail)

### Rules
- **INPUT Rules**: 24 (12 IPv4 + 12 IPv6) - Inbound attack protection
- **FORWARD Rules**: 8 (4 IPv4 + 4 IPv6) - Docker container protection
- **Docker-Block**: Auto-sync cron every 1 minute (prevents bans from clearing on container restart)

---

## 🎯 What's New in v0.33

### nginx-php-errors Jail (EasyAppointment Optimized)
Detects PHP fatal errors and HTTP 5xx responses that could indicate:
- Malformed requests exploiting PHP vulnerabilities
- Script injection attempts
- API abuse patterns

```
Log Pattern: PHP Fatal error, PHP Parse error, HTTP 5xx
Ban Time: 7 days (configurable)
Action: nftables-multiport + docker-hook
Sets: f2b-nginx-php-errors (IPv4), f2b-nginx-php-errors-v6 (IPv6)
```

### Docker-Block v0.4 Auto-Sync (CRITICAL)
**Problem**: Docker restart clears nftables rules → bans disappear  
**Solution**: Cron job runs every 1 minute to re-sync banned IPs

```bash
* * * * * /usr/local/bin/f2b sync docker >> /var/log/f2b-docker-sync.log 2>&1
```

### Interactive Installer (v0.33)
During installation, you'll be prompted for:
1. **Email address** - For Fail2Ban notifications
2. **SSH client IP** - Auto-detected or manual entry
3. **Docker subnets** - For whitelist (ignoreip)

---

## 📥 Download & Installation

```bash
# Download release
tar -xzf fail2ban-hybrid-manager-v0.33.tar.gz
cd v0.33/

# Install (interactive)
sudo bash INSTALL-ALL-v033.sh

# Verify
sudo f2b status
sudo f2b doctor
```

### Installation Sequence
1. **Step 1**: Pre-cleanup (backup nftables)
2. **Step 2**: Install nftables infrastructure (24 sets)
3. **Step 3**: Install Fail2Ban jails (12 jails)
4. **Step 4**: Install F2B wrapper v0.33
5. **Step 5**: Install Docker port blocking v0.4
6. **Step 6**: Install auto-sync service
7. **Step 7**: Install bash aliases
8. **Step 8**: Setup docker-block auto-sync cron ⚠️ **CRITICAL**
9. **Step 9**: Final verification

---

## 🛠️ Quick Commands

```bash
# Check status
sudo f2b status

# Monitor live attacks
sudo f2b monitor watch

# List banned IPs
sudo f2b list banned

# Ban an IP manually
sudo f2b ban 192.168.1.100

# Unban an IP
sudo f2b unban 192.168.1.100

# Docker sync (manual)
sudo f2b sync docker

# Generate report (JSON)
sudo f2b report json

# System doctor check
sudo f2b doctor
```

---

## 🔧 Configuration

### Email Notifications
Edit `/etc/fail2ban/jail.local`:
```ini
[DEFAULT]
destemail = admin@example.com
sender = fail2ban@example.com
```

### Ignore IPs (Whitelist)
```ini
[DEFAULT]
ignoreip = 127.0.0.1/8 ::1 10.0.0.0/8 172.17.0.0/16
```

### Jail-Specific Tuning
```bash
# Edit jail config
sudo vim /etc/fail2ban/jail.d/sshd.local

# Common parameters:
# maxretry = 5          # Ban after 5 failures
# findtime = 600        # In 10 minutes
# bantime = 3600        # Ban for 1 hour
```

### Docker-Block Whitelist
```bash
# Containers to exclude from bans
sudo f2b docker whitelist add my-trusted-service
```

---

## ✅ Verified On

- ✅ Ubuntu 20.04/22.04/24.04 LTS
- ✅ Debian 11/12
- ✅ Fail2Ban v0.11+
- ✅ nftables v0.9+
- ✅ Docker 20.10+ (optional, for docker-block)
- ✅ EasyAppointment 1.3+ (PHP-based appointment system)

---

## 🚀 EasyAppointment-Specific Features

### 1. PHP Error Detection
- Monitors `/var/log/nginx/error.log` for PHP fatals
- Catches script injection attempts early
- Prevents "Fatal error in X.php" DoS patterns

### 2. HTTP 5xx Anomaly Detection
- Detects unusual spike in 500/502/503 responses
- Indicates backend service issues or attacks
- Bans source IP for 7 days

### 3. Docker-Aware
- Automatically whitelists Docker bridge subnets
- Persistent bans survive container restarts (auto-sync)
- Works with docker-compose and Kubernetes

### 4. Nginx Reverse Proxy Support
- Properly forwards X-Real-IP headers
- Logs real client IPs (not container IPs)
- Compatible with nginx upstream configs

---

## 📊 Statistics

**Before v0.33** (v0.31):
- 11 jails
- 11 IPv4 + 11 IPv6 sets = 22 sets
- 22 INPUT rules
- 6 FORWARD rules

**v0.33** (Current):
- 12 jails (+1 nginx-php-errors)
- 12 IPv4 + 12 IPv6 sets = 24 sets
- 24 INPUT rules
- 8 FORWARD rules
- Docker auto-sync cron (every 1 minute)

---

## 🔄 Upgrade from v0.31

```bash
# Backup current installation
sudo cp -r /etc/fail2ban /etc/fail2ban.backup-v031

# Extract and install v0.33
tar -xzf fail2ban-hybrid-manager-v0.33.tar.gz
cd v0.33/
sudo bash INSTALL-ALL-v033.sh

# Verify upgrade
sudo f2b status
sudo nft list table inet fail2ban-filter | grep "set f2b" | wc -l
# Should show: 24 sets
```

### What's Preserved
- ✅ All existing banned IPs (IPv4 + IPv6)
- ✅ Custom jail.local settings
- ✅ Email notifications config
- ✅ Docker whitelists

### What's New
- 📝 12th jail (nginx-php-errors)
- 📝 2 new nftables sets (v6)
- 📝 Docker auto-sync cron (1 minute interval)
- 📝 Wrapper v0.33

---

## 📦 Release Contents

```
v0.33/
├── INSTALL-ALL-v033.sh          # Main installer (interactive)
├── scripts/
│   ├── 00-pre-cleanup-v033.sh
│   ├── 01-install-nftables-v033.sh
│   ├── 02-install-jails-v033.sh
│   ├── 02-verify-jails-v033.sh
│   ├── 03-install-wrapper-v033.sh
│   ├── 04-install-docker-block-v033.sh
│   ├── 05-install-auto-sync-v033.sh
│   ├── 06-install-aliases-v033.sh
│   └── 07-setup-docker-sync-cron-v033.sh
├── filters/
│   ├── sshd.conf
│   ├── f2b-*.conf (9 filters)
│   └── nginx-php-errors.conf ⭐ NEW
├── actions/
│   ├── nftables-multiport
│   ├── nftables-allports
│   ├── docker-hook
│   └── f2b-docker-hook.sh
├── config/
│   ├── jail.local
│   ├── *.local (local tuning files)
│   └── nginx-php-errors.local ⭐ NEW
├── f2b-wrapper-v033.sh          # Main wrapper (50+ functions)
├── README.md                     # This file
├── CHANGELOG.md                  # Version history
├── MIGRATION-GUIDE.md            # v0.31 → v0.33 upgrade
└── LICENSE                       # MIT license
```

---

## 🐛 Troubleshooting

### Docker-Block Not Syncing?
```bash
# Check cron job
sudo crontab -l | grep docker

# Manual sync
sudo f2b sync docker

# Check log
sudo tail -f /var/log/f2b-docker-sync.log
```

### Missing IPv6 Sets?
```bash
# Verify IPv6 infrastructure
sudo nft list table inet fail2ban-filter | grep "\-v6"

# Should show 12 v6 sets
# If missing, run:
sudo bash INSTALL-ALL-v033.sh --clean-install
```

### PHP Errors Not Detected?
```bash
# Check nginx error log
sudo tail -f /var/log/nginx/error.log

# Verify php-errors jail active
sudo f2b status nginx-php-errors

# Check filter matches
sudo f2b filter test nginx-php-errors "/var/log/nginx/error.log"
```

---

## 📞 Support & Issues

For bugs, feature requests, or deployment help:
- 📧 Open an issue on GitHub
- 📝 Check MIGRATION-GUIDE.md for upgrade problems
- 🔧 Run `sudo f2b doctor` for diagnostics

---

## 📄 License

MIT License - See LICENSE file for details

---

**v0.33 - Production Ready for EasyAppointment & Docker Deployments** 🎉
