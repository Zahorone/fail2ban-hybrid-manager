# Fail2Ban + nftables v0.20 - Production Setup

Complete Fail2Ban + nftables integration with **full IPv4 + IPv6 dual-stack support**, 10 advanced detection filters, Docker port blocking, and comprehensive management wrapper.

## 🎯 Features

### Core Infrastructure
- **Full IPv4 + IPv6 Support** - 20 nftables rules (10 IPv4 + 10 IPv6)
- **10 Fail2Ban Jails** - Multi-layered security
- **10 Detection Filters** - Advanced threat detection
- **2 Configuration Files** - jail.local + nginx config

### Advanced Tools
- **F2B Wrapper v0.20** - 43 management functions
- **Docker Port Blocking v0.3** - External access control
- **Auto-Sync Service** - Hourly fail2ban ↔ nftables sync
- **Bash Aliases** - Quick access shortcuts

### Security Layers

#### 10 Fail2Ban Jails:
1. **sshd** - SSH brute-force protection (multi-mode)
2. **f2b-exploit-critical** - Critical CVE exploits
3. **f2b-dos-high** - DoS/DDoS attacks
4. **f2b-web-medium** - SQL injection, path traversal
5. **nginx-recon-bonus** - Nginx reconnaissance
6. **f2b-fuzzing-payloads** - Fuzzing detection
7. **f2b-botnet-signatures** - Botnet signatures
8. **f2b-anomaly-detection** - Anomaly patterns
9. **manualblock** - Manual IP banning
10. **recidive** - Repeat offenders

#### 10 Detection Filters:
Each jail has a corresponding optimized filter in `filters/` directory.

## 🚀 Quick Start

### One-Command Installation

```bash
# Download and extract
tar -xzf fail2ban-nftables-v020-production.tar.gz
cd fail2ban-nftables

# Run universal installer
chmod +x INSTALL-ALL-v020.sh
sudo bash INSTALL-ALL-v020.sh
```

The installer auto-detects:
- Fresh installation
- Upgrade from v0.19 (adds IPv6)
- Reinstall v0.20

### Verification

```bash
# Check system status
sudo f2b status

# Verify nftables rules
sudo nft list chain inet fail2ban-filter f2b-input | grep -c drop
# Expected: 20

# Audit all jails
sudo f2b audit
```

## 📁 Repository Structure

```
fail2ban-nftables-v020/
├── INSTALL-ALL-v020.sh              # Universal installer
├── scripts/
│   ├── 00-pre-cleanup-v020.sh       # Pre-installation cleanup
│   ├── 01-install-nftables-v020.sh  # nftables (IPv4+IPv6)
│   ├── 02-install-jails-v020.sh     # Jails installer (copies filters)
│   ├── 02-verify-jails-v020.sh      # Jails verifier (diagnostic)
│   ├── 03-install-docker-block-v03.sh
│   ├── 04-install-wrapper-v020.sh
│   ├── 05-install-auto-sync.sh
│   ├── 06-install-aliases.sh
│   └── f2b-wrapper-v020.sh          # Main wrapper (43 functions)
├── config/
│   ├── jail.local                   # 10 jails configuration
│   └── nginx-recon-optimized.local  # Nginx jail config
├── filters/                         # 10 detection filters
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
└── docs/
    ├── README.md
    ├── CHANGELOG.md
    ├── MIGRATION-GUIDE.md
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
sudo cp config/nginx-recon-optimized.local /etc/fail2ban/jail.d/

# Copy all filters
sudo cp filters/*.conf /etc/fail2ban/filter.d/

# Restart Fail2Ban
sudo systemctl restart fail2ban
```

3. **Verify Configuration**
```bash
sudo bash scripts/02-verify-jails-v020.sh
```

This diagnostic script checks:
- Banaction configuration
- nftables integration
- Active jails vs configured jails
- Configuration consistency

### Upgrade from v0.19

The installer automatically detects v0.19 and upgrades to v0.20:

**Changes:**
- Adds 10 IPv6 sets
- Adds 10 IPv6 INPUT rules
- Adds 3 IPv6 FORWARD rules
- Updates wrapper to v0.20
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
- ✅ F2B Wrapper v0.20 - 43 functions
- ✅ Universal installer (auto-detect upgrade)
- ✅ Separate verifier tool (diagnostic)
- ✅ Docker blocking v0.3
- ✅ Auto-sync service
- ✅ Bash aliases

### Scripts
- ✅ `02-install-jails-v020.sh` - Full installer (copies filters)
- ✅ `02-verify-jails-v020.sh` - Verification tool (diagnostic)

## 📦 Installation Scenarios

### Scenario 1: Fresh Server
```bash
sudo bash INSTALL-ALL-v020.sh
```
Installs everything from scratch.

### Scenario 2: Upgrade from v0.19
```bash
sudo bash INSTALL-ALL-v020.sh
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
sudo bash scripts/02-verify-jails-v020.sh
```

### Scenario 4: Multi-Server Deployment
```bash
# Server 1
sed -i 's|/var/log/nginx/access.log|/var/log/web/access.log|' config/jail.local
sudo cp config/jail.local /etc/fail2ban/
sudo bash scripts/02-verify-jails-v020.sh

# Server 2
sed -i 's|destemail = root@localhost|destemail = maintainer@example.invalid|' config/jail.local
sudo cp config/jail.local /etc/fail2ban/
sudo bash scripts/02-verify-jails-v020.sh
```

## 🛠️ Troubleshooting

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

- Email: maintainer@example.invalid
- GitHub Issues: Report bugs or feature requests
- Documentation: See `docs/` directory
- Verification Tool: `sudo bash scripts/02-verify-jails-v020.sh`

## 🎉 Acknowledgments

- Fail2Ban Project
- nftables/netfilter team
- Community contributors

---

**Version:** 0.20  
**Last Updated:** December 2025  
**Production Ready:** ✅
