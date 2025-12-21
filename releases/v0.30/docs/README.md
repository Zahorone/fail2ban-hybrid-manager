# Fail2Ban + nftables v0.30 - Production Bundle

Complete Fail2Ban + nftables integration with **one-click installer**, full IPv4 + IPv6 dual-stack support, 11 advanced detection filters, Docker port blocking v0.4, and comprehensive management wrapper with enhanced reporting.

## 🎯 Features

### Core Infrastructure
- **Full IPv4 + IPv6 Support** - 22 nftables sets (11 IPv4 + 11 IPv6)
- **11 Fail2Ban Jails** - Multi-layered security
- **11 Detection Filters** - Advanced threat detection
- **30d Recidive Jail** - Long-term repeat offender blocking
- **Safe Pre-Cleanup** - Backup + legacy cleanup before install

### Advanced Tools
- **One-Click Installer** - `INSTALL-ALL-v030.sh` (auto-detects upgrade paths)
- **Docker Port + IP Blocking v0.4** - Blocks before Docker NAT (PREROUTING)
- **Docker Auto-Sync** - Every minute sync via cron
- **Docker Dashboard** - Real-time docker-block monitoring
- **F2B Wrapper v0.30** - 50+ management functions with attack analysis
- **Auto-Sync Service** - Hourly fail2ban ↔ nftables sync
- **Minimal Bash Aliases** - Optional quick access shortcuts
- **ShellCheck Clean** - All scripts pass syntax + style checks

### Security Layers

#### 11 Fail2Ban Jails:
1. **sshd** - SSH brute-force protection (multi-mode)
2. **sshd-slowattack** - Slow SSH attacks
3. **f2b-exploit-critical** - Critical CVE exploits
4. **f2b-dos-high** - DoS/DDoS attacks
5. **f2b-web-medium** - SQL injection, path traversal
6. **nginx-recon-bonus** - Nginx reconnaissance
7. **f2b-fuzzing-payloads** - Fuzzing detection
8. **f2b-botnet-signatures** - Botnet signatures
9. **f2b-anomaly-detection** - Anomaly patterns
10. **manualblock** - Manual IP banning
11. **recidive** - Repeat offenders (30d ban)

#### 11 Detection Filters:
Each jail has a corresponding optimized filter in `filters/` directory.

## 🐋 Docker Protection

Docker containers are protected the same way as the host – all Fail2Ban bans are automatically propagated to the docker-block table (PREROUTING), so attackers are dropped before they ever reach Docker services.

Key features:
- Automatic sync of banned IPs from Fail2Ban jails to `docker-banned-ipv4`/`docker-banned-ipv6`
- Port-level blocking via `docker-blocked-ports` (services exposed from Docker)
- PREROUTING hook ensures packets are dropped before Docker NAT
- Every-minute cron sync (`07-setup-docker-sync-cron-v030.sh`)

### Docker-block nftables (v0.4)

`03-install-docker-block-v030.sh` creates `table inet docker-block` with:
- `docker-blocked-ports` - Docker service ports to block externally
- `docker-banned-ipv4` / `docker-banned-ipv6` - IPs dropped in PREROUTING
- Rules run in `hook prerouting priority dstnat` (before Docker NAT)

### Wrapper Commands (v0.30)

**Ports:**

```bash
sudo f2b manage block-port 8081
sudo f2b manage unblock-port 8081
sudo f2b manage list-blocked-ports
```

**Manual IP bans (manual quarantine, goes to f2b-manualblock → then docker-block):**

```bash
sudo f2b manage manual-ban 198.51.100.10 7d
sudo f2b manage manual-unban 198.51.100.10
```

**Unban IP from all jails + nftables:**

```bash
sudo f2b manage unban-all 198.51.100.10
```

### Sync & Docker Integration

**Enhanced bidirectional sync (Fail2Ban ↔ nftables):**

```bash
sudo f2b sync enhanced
sudo f2b sync force
```

**Silent sync for cron (logs only changes to /var/log/f2b-sync.log):**

```bash
sudo f2b sync silent
```

**Docker sync: propagate bans to docker-block (docker-banned-ipv4/v6):**

```bash
sudo f2b sync docker
```

**Docker visibility & monitoring:**

```bash
sudo f2b docker info
sudo f2b docker dashboard
```

### Auto-sync fail2ban → docker-block

- `07-setup-docker-sync-cron-v030.sh`:
  - Creates cron job: `*/1 * * * * /usr/local/bin/f2b sync docker >> /var/log/f2b-docker-sync.log 2>&1`
  - Initializes first sync and sets up logrotate for `/var/log/f2b-docker-sync.log`

- Wrapper (v0.30) has:
  - `f2b sync docker` - Bidirectional sync jails ↔ docker-banned-ipv4
  - `f2b docker info` - docker-block table status
  - `f2b docker dashboard` - Real-time dashboard (tail + stats)

## 🚀 Quick Start

### One-Command Installation

```bash
tar -xzf f2b-hybrid-nftables-v030.tar.gz
cd v030
sudo bash INSTALL-ALL-v030.sh
```

The installer auto-detects:
- Fresh installation (new server)
- Upgrade from v0.19–v0.24 (preserves bans, adds/rebuilds structure)
- Reinstall v0.30 (clean rebuild with ban preservation)

### Interactive Configuration (First Run)

The installer guides you through setup interactively:

1. **Email Notifications** (optional)
   - Detects mail service (postfix, sendmail)
   - Prompts for admin email + sender email
   - Updates all jails with email alerts on ban
   - Shows which jails send email notifications

2. **WAN/Server IP Detection** (auto)
   - Auto-detects your server's WAN or LAN IP
   - Adds it to Fail2Ban ignore list (prevents self-blocking)
   - Preserves 127.0.0.1/8 and ::1 loopback addresses

3. **Proceed to Installation**
   - After configuration, installer continues with nftables, jails, wrapper, docker-block

### Safe Test Mode (Recommended for Production First Run)

```bash
sudo bash INSTALL-ALL-v030.sh --cleanup-only
```

This runs `00-pre-cleanup-v030.sh` with backup + legacy cleanup, then exits before touching nftables/jails.

### Verification

```bash
sudo f2b status
sudo nft list chain inet fail2ban-filter f2b-input | grep -c drop
# Expected: 22 (11 IPv4 + 11 IPv6)
sudo f2b audit
sudo bash scripts/02-verify-jails-v030.sh
```

## 📁 Repository Structure

```
v030/
├── INSTALL-ALL-v030.sh
├── scripts/
│   ├── 00-pre-cleanup-v030.sh
│   ├── 01-install-nftables-v030.sh
│   ├── 02-install-jails-v030.sh
│   ├── 02-verify-jails-v030.sh
│   ├── 03-install-docker-block-v030.sh
│   ├── 04-install-wrapper-v030.sh
│   ├── 05-install-auto-sync-v030.sh
│   ├── 06-install-aliases-v030.sh
│   ├── 07-setup-docker-sync-cron-v030.sh
│   └── f2b-wrapper-v030.sh
├── config/
│   ├── jail.local
│   ├── nginx-recon-optimized.local
│   └── f2b-anomaly-detection.local
├── filters/
│   ├── sshd.conf
│   ├── f2b-exploit-critical.conf
│   ├── f2b-dos-high.conf
│   ├── f2b-web-medium.conf
│   ├── f2b-fuzzing-payloads.conf
│   ├── f2b-botnet-signatures.conf
│   ├── f2b-anomaly-detection.conf
│   ├── nginx-recon-optimized.conf
│   ├── manualblock.conf
│   └── recidive.conf
├── action.d/
│   ├── nftables-common.local
│   ├── nftables-multiport.conf
│   └── nftables-recidive.conf
└── docs/
    ├── README-v030.md
    ├── CHANGELOG-v030.md
    ├── MIGRATION-GUIDE.md
    └── PACKAGE-INFO-v030.txt
```

## 🔧 F2B Wrapper Commands

### Core

```bash
sudo f2b status          # System overview
sudo f2b audit           # Audit all jails
sudo f2b find <IP>       # Find IP in jails
sudo f2b version         # Version info (--human, --json, --short)
```

### Sync

```bash
sudo f2b sync check      # Verify sync
sudo f2b sync enhanced   # Enhanced checks
sudo f2b sync force      # Force sync + verify
sudo f2b sync silent     # Silent (cron-friendly)
sudo f2b sync docker     # Sync to docker-block
```

### Manage - Ports

```bash
sudo f2b manage block-port 8081
sudo f2b manage unblock-port 8081
sudo f2b manage list-blocked-ports
```

### Manage - IPs

```bash
sudo f2b manage manual-ban 192.0.2.1 30d
sudo f2b manage manual-unban 192.0.2.1
sudo f2b manage unban-all 192.0.2.1
```

### Manage - System

```bash
sudo f2b manage reload   # Reload fail2ban
sudo f2b manage backup   # Backup configs
```

### Monitor

```bash
sudo f2b monitor watch           # Real-time dashboard
sudo f2b monitor trends          # Attack trends
sudo f2b monitor top-attackers   # Top 10
sudo f2b monitor show-bans       # Show banned IPs
sudo f2b monitor jail-log sshd 50 # Jail log (last 50 lines)
```

### Reports & Analysis (NEW in v0.30)

```bash
sudo f2b report json > report.json
sudo f2b report csv > report.csv
sudo f2b report daily
sudo f2b report timeline
sudo f2b report attack-analysis
sudo f2b report attack-analysis --npm-only
sudo f2b report attack-analysis --ssh-only
```

### Docker

```bash
sudo f2b docker dashboard
sudo f2b docker info
sudo f2b docker sync
```

### Silent / Cron

```bash
sudo f2b audit-silent
```

## 🆕 What's New in v0.30

### One-Click Production Installer
- **INSTALL-ALL-v030.sh** - Orchestrates full install/upgrade
- Auto-detects: fresh / upgrade from v0.19–v0.24 / reinstall v0.30
- Safe pre-cleanup with `--cleanup-only` mode
- Preserves existing bans and structure during upgrade

### Enhanced Wrapper v0.30
- **Attack Analysis Reporting**
  - `f2b report attack-analysis` (NPM + SSH combined)
  - `--npm-only` / `--ssh-only` modes
  - `f2b report timeline` for hourly attack trends
- **Improved Sync & Monitoring**
  - Enhanced docker dashboard
  - Better jq helpers for JSON parsing
  - Safer lock handling
- **ShellCheck Clean**
  - Fixed SC2034/SC2086/SC2126/SC2155/SC2188/SC1083
  - Unified metadata header across all scripts

### Safe Pre-Cleanup (NEW)
- **00-pre-cleanup-v030.sh**
  - Full backup of nftables + fail2ban configs
  - Safe cleanup of legacy systemd units, cron entries, aliases
  - FORCE mode for full reinstall
  - Verification snapshot at the end

### Minimal Aliases (Optional)
- **06-install-aliases-v030.sh**
  - Minimal set: f2b-status, f2b-audit, f2b-watch, f2b-trends
  - f2b-sync, f2b-sync-enhanced, f2b-sync-docker
  - f2b-docker-dashboard, f2b-attack-analysis, f2b-audit-silent
  - Idempotent update of `~/.bashrc` with backup

### Infrastructure (Unchanged from v0.24)
- 22 nftables sets (11 IPv4 + 11 IPv6)
- 22 INPUT rules (11 + 11)
- 6 FORWARD rules (3 + 3)
- 11 jails with correct banaction mapping
- 30d recidive jail (nftables-recidive.conf)

## 🎓 Advanced Usage

### Manual Configuration (Production Best Practice)

```bash
cd v030
nano config/jail.local
nano filters/*.conf
sudo bash INSTALL-ALL-v030.sh
sudo bash scripts/02-verify-jails-v030.sh
```

### Upgrade from v0.19–v0.24

The installer automatically detects previous versions and handles upgrade.

**Verification:**

```bash
sudo nft list table inet fail2ban-filter | grep "set f2b-.*-v6" | wc -l
# Should return: 11

sudo f2b version --short
# Should return: 0.30
```

## 📊 Minimal Aliases (Optional)

After running `06-install-aliases-v030.sh`:

```bash
f2b-status           # sudo f2b status
f2b-audit            # sudo f2b audit
f2b-watch            # sudo f2b monitor watch
f2b-trends           # sudo f2b monitor trends
f2b-sync             # sudo f2b sync check
f2b-sync-enhanced    # sudo f2b sync enhanced
f2b-sync-docker      # sudo f2b sync docker
f2b-docker-dashboard # sudo f2b docker dashboard
f2b-attack-analysis  # sudo f2b report attack-analysis
f2b-audit-silent     # sudo f2b audit-silent
```

Activate with: `source ~/.bashrc`

## 📦 Installation Scenarios

### Fresh Server (Clean Install)

```bash
sudo bash INSTALL-ALL-v030.sh
```

### Upgrade from v0.22/v0.24

```bash
sudo bash INSTALL-ALL-v030.sh
```

### Production Test (--cleanup-only)

```bash
sudo bash INSTALL-ALL-v030.sh --cleanup-only
```

### Multi-Server Deployment

```bash
nano config/jail.local
sudo bash INSTALL-ALL-v030.sh
```

## 🛠️ Troubleshooting

### Scripts can't find config/ or filters/

```bash
cd v030/
sudo bash INSTALL-ALL-v030.sh
# Not from scripts/ directory ❌
```

### Jail not starting

```bash
sudo tail -f /var/log/fail2ban.log
sudo fail2ban-regex /path/to/logfile /etc/fail2ban/filter.d/filtername.conf
sudo bash scripts/02-verify-jails-v030.sh
```

### nftables rules missing

```bash
sudo nft list table inet fail2ban-filter
sudo nft list chain inet fail2ban-filter f2b-input | grep -c drop
# Should be: 22
sudo bash scripts/01-install-nftables-v030.sh
```

### Sync problems

```bash
sudo f2b sync check
sudo f2b sync force
sudo f2b sync enhanced
```

### Docker-block not working

```bash
sudo nft list table inet docker-block
sudo f2b sync docker
crontab -l | grep f2b
sudo f2b docker dashboard
```

## 📜 License

MIT License - See LICENSE file

## 👤 Author

Peter Bakič - vibes coder · self-hosted infra & security

## 📞 Support

- Email: zahor@tuta.io
- GitHub Issues: Report bugs or feature requests
- Documentation: See `docs/` directory
- Verification Tool: `sudo bash scripts/02-verify-jails-v030.sh`

## 🎉 Acknowledgments

- Fail2Ban Project
- nftables/netfilter team
- Community contributors

---

**Version:** 0.30
**Last Updated:** December 19, 2025
**Production Ready:** ✅
