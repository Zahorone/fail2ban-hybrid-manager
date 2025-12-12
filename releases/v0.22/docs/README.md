# Fail2Ban + nftables v0.22 - Production Setup

Complete Fail2Ban + nftables integration with **full IPv4 + IPv6 dual-stack support**, 11 advanced detection filters, Docker port blocking, and comprehensive management wrapper.

## 🎯 Features

### Core Infrastructure
- **Full IPv4 + IPv6 Support** - 22 nftables sets (11 IPv4 + 11 IPv6)
- **11 Fail2Ban Jails** - Multi-layered security (added f2b-anomaly-detection)
- **11 Detection Filters** - Advanced threat detection
- **3 Configuration Files** - jail.local + 2 filter extensions

### Advanced Tools
- **Docker Port + IP Blocking v0.4** – blokovanie portov a IP adries ešte pred Docker NAT
- **Docker Auto-Sync (f2b sync docker)** – prenáša Fail2Ban bans do `docker-block` tabuliek
- **Docker Dashboard (v0.23)** – živý prehľad docker-block stavu
- **F2B Wrapper v0.23** - 43 management functions
- **Auto-Sync Service** - Hourly fail2ban ↔ nftables sync
- **Bash Aliases** - Quick access shortcuts

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
9. **f2b-anomaly-detection** - Anomaly patterns **[NEW in v0.22]**
10. **manualblock** - Manual IP banning
11. **recidive** - Repeat offenders


#### 11 Detection Filters:
Each jail has a corresponding optimized filter in `filters/` directory.

## 🐋 Docker Protection
Docker containers are protected the same way as the host – all Fail2Ban bans are automatically propagated to the docker-block table (PREROUTING), so attackers are dropped before they ever reach Docker services.
Key features:
- Automatic sync of banned IPs from Fail2Ban jails to `docker-banned-ipv4`/`docker-banned-ipv6`
- Port-level blocking via `docker-blocked-ports` (services exposed from Docker)
- PREROUTING hook ensures packets are dropped before Docker NAT

### Docker-block nftables (v0.4)
- `03-install-docker-block-v04.sh` vytvorí `table inet docker-block` s:
  - `docker-blocked-ports` – porty Docker služieb, ktoré majú byť zvonku blokované
  - `docker-banned-ipv4` / `docker-banned-ipv6` – IP adresy, ktoré sa zahodia v PREROUTING
- Pravidlá bežia v `hook prerouting priority dstnat`, takže IP sú dropnuté ešte pred Docker NAT.

### Wrapper príkazy (v0.22/v0.23)
Porty
```bash
sudo f2b manage block-port 8081
sudo f2b manage unblock-port 8081
sudo f2b manage list-blocked-ports
```

### Manage - Advanced IP Control

Manuálne IP (manuálna karanténa, ide do f2b-manualblock → následne aj docker-block)
```bash
sudo f2b manage manual-ban 198.51.100.10 7d
sudo f2b manage manual-unban 198.51.100.10
```

Unban IP from all jails + nftables
```bash
sudo f2b manage unban-all 198.51.100.10
```

### Sync & Docker Integration

Enhanced bidirectional sync (Fail2Ban ↔ nftables)
```bash
sudo f2b sync enhanced
sudo f2b sync force
```
Silent sync for cron (logs only changes to /var/log/f2b-sync.log)
```bash
sudo f2b sync silent
```

Docker sync: propagate bans to docker-block (docker-banned-ipv4/v6)
```bash
sudo f2b sync docker
```

Docker visibility & monitoring (v0.23)
```bash
sudo f2b docker info
sudo f2b docker dashboard
```

### Auto-sync fail2ban → docker-block

- `07-setup-docker-sync-cron.sh`:
  - vytvorí cron job: `*/1 * * * * /usr/local/bin/f2b sync docker >> /var/log/f2b-docker-sync.log 2>&1`
  - inicializuje prvý sync a nastaví logrotate pre `/var/log/f2b-docker-sync.log`.
- Wrapper (v0.23) má:
  - `f2b sync docker` – bidirekčný sync jaily ↔ docker-banned-ipv4
  - `f2b docker info` – stav docker-block tabuľky
  - `f2b docker dashboard` – real-time dashboard (tail + štatistiky)

## 🚀 Quick Start

### One-Command Installation

```bash
# Download and extract
tar -xzf fail2ban-nftables-v022-production.tar.gz
cd fail2ban-nftables

# Run universal installer
chmod +x INSTALL-ALL-v022.sh
sudo bash INSTALL-ALL-v022.sh
```

The installer auto-detects:
- Fresh installation
- Upgrade from v0.20 (adds IPv6) or v0.20
- Reinstall v0.21

### Verification

```bash
# Check system status
sudo f2b status

# Verify nftables rules
sudo nft list chain inet fail2ban-filter f2b-input | grep -c drop
# Expected: 22 (was 20 in v0.21)

# Audit all jails
sudo f2b audit
```

## 📁 Repository Structure

```
v0.22/
├── INSTALL-ALL-v022.sh              # Universal installer
├── scripts/
│   ├── 00-pre-cleanup-v021.sh
│   ├── 01-install-nftables-v022.sh  # [UPDATED] Clean install support
│   ├── 02-install-jails-v022.sh     # [UPDATED] Path resolution fix
│   ├── 02-verify-jails-v022.sh      # [UPDATED] 11 jails check
│   ├── 03-install-docker-block-v04.sh
│   ├── 04-install-wrapper-v023.sh
│   ├── 05-install-auto-sync.sh
│   ├── 06-install-aliases-v023.sh
│   ├── f2b-wrapper-v023.sh          # Main wrapper
│   └── 07-setup-docker-sync-cron.sh
├── config/
│   ├── jail.local                   # 11 jails configuration
│   ├── nginx-recon-optimized.local  # Filter extension (→ filter.d)
│   └── f2b-anomaly-detection.local  # Filter extension (→ filter.d) [NEW]
├── filters/                         # 11 detection filters
│   ├── sshd.conf
│   ├── f2b-exploit-critical.conf
│   ├── f2b-dos-high.conf
│   ├── f2b-web-medium.conf
│   ├── f2b-fuzzing-payloads.conf
│   ├── f2b-botnet-signatures.conf
│   ├── f2b-anomaly-detection.conf   # [NEW in v0.22]
│   ├── nginx-recon-optimized.conf
│   ├── manualblock.conf
│   └── recidive.conf
└── docs/
    ├── README.md
    ├── CHANGELOG.md
    └── PACKAGE-INFO.txt
```

## 🔧 F2B Wrapper Commands

### Core
```bash
sudo f2b status          # System overview
sudo f2b audit           # Audit all jails
sudo f2b find <IP>       # Find IP in jails
sudo f2b version         # Version info
```

### Sync
```bash
sudo f2b sync check      # Verify sync
sudo f2b sync force      # Force sync + verify
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
```

### Monitor
```bash
sudo f2b monitor watch           # Real-time
sudo f2b monitor trends          # Attack trends
sudo f2b monitor top-attackers   # Top 10
sudo f2b monitor jail-log sshd 50
```

### Reports
```bash
sudo f2b report json > report.json
sudo f2b report csv > report.csv
sudo f2b report daily
```

## 🆕 What's New in v0.22

### Critical Fixes
- ✅ **Clean Install Support** - No more errors on fresh servers without fail2ban
- ✅ **Path Resolution Fix** - Scripts correctly find config/ and filters/ from scripts/ directory
- ✅ **Filter Extension Logic** - *.local files now properly go to filter.d (not jail.d)

### New Features
- ✅ **11th Jail Added** - `f2b-anomaly-detection` for anomaly pattern detection
- ✅ **Enhanced Verification** - `02-verify-jails-v022.sh` checks all 11 jails
- ✅ **Idempotent Installation** - Automatic backup before overwriting filters
- ✅ `f2b manage unban-all <IP>` – removes an IP from all jails and syncs nftables
- ✅ Manual quarantine via `f2b manage manual-ban` / `manual-unban` (uses `f2b-manualblock` set)
- ✅ Enhanced sync reporting with `f2b sync enhanced` / `sync force` and `sync silent` for cron
- ✅ Full Docker integration:
  - `f2b sync docker` feeds all banned IPs into `docker-banned-ipv4/v6`
  - `f2b docker info` and `f2b docker dashboard` show docker-block status in real time


### Infrastructure
- ✅ 22 nftables sets (11 IPv4 + 11 IPv6) - was 20
- ✅ 22 INPUT rules (11 + 11) - was 20
- ✅ 6 FORWARD rules (3 + 3) - unchanged

### Scripts Enhanced
- `01-install-nftables-v022.sh` - Conditional fail2ban operations
- `02-install-jails-v022.sh` - Proper parent directory resolution
- `02-verify-jails-v022.sh` - Checks all 11 jails including new ones

## 🎓 Advanced Usage

### Manual Configuration (Production Best Practice)

By default, email notification addresses (`destemail`, `sender`) and `ignoreip` are set to generic values.  
For production, update them in `config/jail.local` before running the installer.

For production servers with custom requirements:

1. **Edit Configuration**
```bash
cd fail2ban-nftables
nano config/jail.local           # Customize emails, ports, logpaths
nano filters/*.conf              # Adjust detection patterns
```

2. **Manual Installation**
```bash
# Copy configurations
sudo cp config/jail.local /etc/fail2ban/
sudo cp config/nginx-recon-optimized.local /etc/fail2ban/filter.d/
sudo cp config/f2b-anomaly-detection.local /etc/fail2ban/filter.d/

# Copy all filters
sudo cp filters/*.conf /etc/fail2ban/filter.d/

# Restart Fail2Ban
sudo systemctl restart fail2ban
```

3. **Verify Configuration**
```bash
sudo bash scripts/02-verify-jails-v021.sh
```

This diagnostic script checks:
- Banaction configuration
- nftables integration
- Active jails vs configured jails
- Configuration consistency

### Upgrade from v0.20

The installer automatically detects v0.20 and upgrades to v0.21:

**Changes:**
- Adds 10 IPv6 sets
- Adds 10 IPv6 INPUT rules
- Adds 3 IPv6 FORWARD rules
- Updates wrapper to v0.21
- Preserves all existing bans

**Verification:**
```bash
sudo nft list table inet fail2ban-filter | grep "set f2b-.*-v6" | wc -l
# Should return: 10
```

## 📊 What's New in v0.20

### Infrastructure
- ✅ Full IPv4 + IPv6 dual-stack support
- ✅ 20 nftables sets (10 IPv4 + 10 IPv6)
- ✅ 20 INPUT rules (10 + 10)
- ✅ 6 FORWARD rules (3 + 3)

### Jails & Filters
- ✅ 10 Fail2Ban jails
- ✅ 10 advanced detection filters
- ✅ 2 configuration files

### Tools
- ✅ F2B Wrapper v0.21 - 43 functions
- ✅ Universal installer (auto-detect upgrade)
- ✅ Separate verifier tool (diagnostic)
- ✅ Docker blocking v0.3
- ✅ Auto-sync service
- ✅ Bash aliases

### Scripts
- ✅ `02-install-jails-v021.sh` - Full installer (copies filters)
- ✅ `02-verify-jails-v021.sh` - Verification tool (diagnostic)

## 📦 Installation Scenarios

### Scenario 1: Fresh Server
```bash
sudo bash INSTALL-ALL-v021.sh
```
Installs everything from scratch.

### Scenario 2: Upgrade from v0.21
```bash
sudo bash INSTALL-ALL-v021.sh
```
Auto-detects v0.19, adds IPv6 support.

### Scenario 3: Production with Custom Config
```bash
# Edit configs
nano config/jail.local

# Manual copy
sudo cp config/jail.local /etc/fail2ban/
sudo cp filters/*.conf /etc/fail2ban/filter.d/

# Verify
sudo bash scripts/02-verify-jails-v021.sh
```

### Scenario 4: Multi-Server Deployment
```bash
# Server 1
sed -i 's|/var/log/nginx/access.log|/var/log/web/access.log|' config/jail.local
sudo cp config/jail.local /etc/fail2ban/
sudo bash scripts/02-verify-jails-v020.sh

# Server 2
sed -i 's|destemail = root@localhost|destemail = admin@company.com|' config/jail.local
sudo cp config/jail.local /etc/fail2ban/
sudo bash scripts/02-verify-jails-v020.sh
```

## 🛠️ Troubleshooting

### Issue: Scripts can't find config/ or filters/
```bash
Make sure you run from main directory
cd v0.22/
sudo bash INSTALL-ALL-v022.sh

Not from scripts/ directory
cd v0.22/scripts/ # ❌ Wrong
sudo bash INSTALL-ALL-v022.sh
```

### Issue: Jail not starting
```bash
# Check logs
sudo tail -f /var/log/fail2ban.log

# Verify filter syntax
sudo fail2ban-regex /path/to/logfile /etc/fail2ban/filter.d/filtername.conf

# Run diagnostic
sudo bash scripts/02-verify-jails-v020.sh
```

### Issue: nftables rules missing
```bash
# Verify table exists
sudo nft list table inet fail2ban-filter

# Count rules
sudo nft list chain inet fail2ban-filter f2b-input | grep -c drop
# Should be: 20

# Reinstall
sudo bash scripts/01-install-nftables-v020.sh
```

### Issue: Sync problems
```bash
# Check sync status
sudo f2b sync check

# Force sync
sudo f2b sync force
```

## 📜 License

MIT License - See LICENSE file

## 👤 Author

Peter Bakič  
vibes coder · self-hosted infra & security  
Powered by Claude Sonnet 4.5 thinking

## 📞 Support

- Email: zahor@tuta.io
- GitHub Issues: Report bugs or feature requests
- Documentation: See `docs/` directory
- Verification Tool: `sudo bash scripts/02-verify-jails-v021.sh`

## 🎉 Acknowledgments

- Fail2Ban Project
- nftables/netfilter team
- Community contributors

---

**Version:** 0.21  
**Last Updated:** December 2025  
**Production Ready:** ✅
