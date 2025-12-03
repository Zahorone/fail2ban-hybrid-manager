# F2B Setup v0.19 - Fail2Ban + nftables Production Setup

Complete Fail2Ban + nftables integration with docker-block support and unified management wrapper.

## 📋 Features

- **10 Production Jails** - SSH, exploit detection, DoS protection, web attacks, fuzzing, botnets, anomaly detection
- **nftables Integration** - Modern firewall with native Fail2Ban support
- **docker-block v0.3** - Block external access to Docker ports (localhost allowed)
- **F2B Wrapper v0.19** - Unified management tool with monitoring, trends, and reports
- **Attack Trend Analysis** - Monitor attack patterns (hourly, 6h, 24h)
- **JSON/CSV Export** - Export reports for external monitoring tools
- **Persistent Logging** - All operations logged to `/var/log/f2b-wrapper.log`
- **Jail Log Filtering** - View specific jail activity logs
- **Lock Mechanism** - Safe concurrent operations

## 🚀 Quick Start

### Prerequisites

- Ubuntu/Debian server
- Root/sudo access
- Fail2Ban installed
- nftables installed

### Installation

```bash
# 1. Extract and enter directory
tar xzf f2b-setup-v019.tar.gz
cd f2b-setup-v019/

# 2. CONFIGURE BEFORE INSTALLATION (IMPORTANT!)
nano config/jail.local
# Edit: destemail, sender, sendername, SSH port, logpaths

# 3. Run installer
sudo bash INSTALL-ALL-v019.sh

# 4. Activate aliases
source ~/.bashrc

# 5. Verify
f2b-status
```

## 📁 Pre-Installation Setup

**⚠️ REQUIRED: Edit `config/jail.local` before running installer**

```bash
cd config/
nano jail.local
```

### Key Configuration Points

**[DEFAULT] section (lines 2-4):**
```ini
destemail = your-email@example.com
sender = fail2ban@your-server.com
sendername = Fail2Ban your-server.com
```

**[DEFAULT] section (line 10):**
```ini
ignoreip = 127.0.0.1/8 ::1 YOUR_ADMIN_IP
```

**[sshd] section (lines 18, 24-26):**
```ini
port = YOUR_SSH_PORT

banaction = nftables-multiport[name=sshd, port="YOUR_SSH_PORT"]
banaction_allports = nftables-multiport[name=sshd, port="YOUR_SSH_PORT"]
unbanaction = nftables-multiport[name=sshd, port="YOUR_SSH_PORT", actiontype=unban]
```

**Log paths (if using Nginx Proxy Manager):**
```ini
logpath = /opt/rustnpm/data/logs/fallback_access.log
          /opt/rustnpm/data/logs/proxy-host-*_access.log
```

## 📂 Directory Structure

```
f2b-setup-v019/
├── README.md                          # This file
├── F2B-QUICK-REFERENCE-v019.txt       # Command cheat sheet
├── INSTALL-ALL-v019.sh                # Master installer
├── 01-install-nftables.sh             # nftables setup
├── 02-install-jails.sh                # Copy config files
├── 03-install-docker-block-v03.sh     # Docker port blocking
├── 04-install-wrapper-v019.sh         # F2B wrapper
├── 05-install-auto-sync.sh            # Initial sync
├── 06-install-aliases.sh              # Bash aliases
├── config/
│   ├── jail.local                     # ← EDIT THIS BEFORE INSTALL
│   ├── jail.local.example             # Template reference
│   └── filters/
│       ├── f2b-exploit-critical.conf
│       ├── f2b-dos-high.conf
│       ├── f2b-web-medium.conf
│       ├── f2b-fuzzing-payloads.conf
│       ├── f2b-botnet-signatures.conf
│       └── f2b-anomaly-detection.conf
└── f2b-wrapper-v019.sh
```

## 🛡️ Active Jails (10)

| # | Jail | Trigger | Ban Time | Port |
|---|------|---------|----------|------|
| 1 | sshd | 2 failures | 24h | SSH |
| 2 | f2b-exploit-critical | 1 attempt | ∞ Permanent | http,https |
| 3 | f2b-dos-high | 1 attempt | 7d | http,https |
| 4 | f2b-web-medium | 6 failures | 30m-7d | http,https |
| 5 | nginx-recon-bonus | 3 failures | 1h-7d | http,https |
| 6 | recidive | 5 failures | 30d | 0:65535 |
| 7 | manualblock | Manual | ∞ Permanent | 0:65535 |
| 8 | f2b-fuzzing-payloads | 2 failures | 30m-24h | http,https |
| 9 | f2b-botnet-signatures | 1 attempt | 24h | http,https |
| 10 | f2b-anomaly-detection | 3 failures | 15m-1h | http,https |

## 🔧 F2B Wrapper v0.19 Commands

### Daily Monitoring

```bash
f2b-status              # Quick overview
f2b-audit               # Full audit of all jails
f2b-watch               # Real-time monitoring (Ctrl+C to exit)
f2b-trends              # Attack trend analysis (NEW v0.19)
```

### IP Management

```bash
f2b-find 1.2.3.4        # Find IP in jails
f2b-ban 1.2.3.4 30d     # Ban IP for 30 days
f2b-unban 1.2.3.4       # Unban IP
f2b-bans                # Show all banned IPs
f2b-top                 # Top 10 historical attackers
```

### Port Management

```bash
f2b-block-port 8081     # Block Docker port (external)
f2b-unblock-port 8081   # Unblock port
f2b-list-ports          # List blocked ports
f2b-docker              # Show docker-block status
```

### Monitoring & Logs (NEW v0.19)

```bash
f2b-log sshd 50         # Show last 50 sshd log lines
f2b-log f2b-dos-high 100  # Show last 100 log lines
f2b-trends              # Attack trend analysis
```

### Reports (NEW v0.19)

```bash
f2b-json                # Export JSON report
f2b-csv                 # Export CSV report
f2b-report              # Daily summary
f2b-quick               # Quick stats
```

### Sync & System

```bash
f2b-sync                # Check/force sync
f2b-reload              # Reload firewall
f2b-backup              # Create backup
```

## 🐋 docker-block v0.3

Block external Docker access while allowing localhost.

```bash
# Block port 8081 from external access
f2b-block-port 8081

# Unblock
f2b-unblock-port 8081

# Status
f2b-docker
```

**Behavior:**
- ✅ localhost (127.0.0.1) → ALLOWED
- ✅ Docker bridge → ALLOWED
- ❌ External → BLOCKED

## 📊 Log Files

```
/var/log/f2b-wrapper.log     Main wrapper operations
/var/log/f2b-sync.log        Sync operations
/var/log/f2b-audit.log       Audit results
/var/log/fail2ban.log        Fail2Ban activity
```

## 🔄 Multi-Server Setup

For different server configurations:

```bash
# Server 1: terminy.bakic.net
cd config/
cp jail.local jail.local.terminy
sed -i 's/objednavky.bakic.net/terminy.bakic.net/g' jail.local.terminy
sed -i 's/port = 2229/port = 22/g' jail.local.terminy
sed -i 's/port="2229"/port="22"/g' jail.local.terminy

# Use this config for terminy deployment
cp jail.local.terminy jail.local
sudo bash ../INSTALL-ALL-v019.sh

# Server 2: objednavky.bakic.net  
# Use original jail.local with SSH port 2229
```

## 🆕 What's New in v0.19

✅ **Lock mechanism** - Prevents concurrent operation conflicts  
✅ **Input validation** - Port (1-65535) and IP address validation  
✅ **Attack trends** - `f2b monitor trends` shows pattern analysis  
✅ **Jail log filter** - `f2b monitor jail-log <jail>` for specific logs  
✅ **JSON/CSV export** - `f2b report json|csv` for monitoring integration  
✅ **Historical top attackers** - Track from fail2ban logs (not just current)  
✅ **Persistent logging** - All operations → `/var/log/f2b-wrapper.log`  
✅ **Enhanced aliases** - New aliases for all v0.19 features

## ✨ Workflow Examples

### Check if IP is banned

```bash
f2b-find 203.0.113.50
# Output: Found in jail: f2b-dos-high, Ban time: 604800
```

### Ban suspicious IP

```bash
f2b-ban 192.0.2.100 30d
# Bans for 30 days
```

### View attack trends

```bash
f2b-trends
# Shows: Last hour: 15 attempts, Last 6h: 45 attempts, Last 24h: 120 attempts
```

### Export for monitoring

```bash
f2b-json > /tmp/f2b-report.json
# Import to Prometheus/Grafana/monitoring system
```

### Real-time monitoring

```bash
f2b-watch
# Updates every 5 seconds (Ctrl+C to exit)
```

## 📝 Notes

- Always edit `config/jail.local` **before** running installer
- For email alerts, ensure mail server is configured
- SSH port must match your actual SSH port (usually 22 or custom)
- Use strong email passwords if enabling notifications
- Backup current config before updating

## 🆘 Troubleshooting

**Check installation:**
```bash
f2b-status
f2b-audit
```

**Verify sync:**
```bash
f2b sync check
```

**View specific jail:**
```bash
f2b monitor show-bans sshd
```

**Check logs:**
```bash
tail -f /var/log/f2b-wrapper.log
tail -f /var/log/fail2ban.log
```

**Force full sync:**
```bash
sudo f2b sync force
```

---

**Version:** v0.19  
**Date:** 2025-12-01  
**Server:** objednavky.bakic.net / terminy.bakic.net