# Fail2Ban + nftables v0.33 - Production Bundle

Complete Fail2Ban + nftables integration with one-click installer, full IPv4 + IPv6 dual-stack support, 12 advanced detection filters, Docker port and IP blocking with immediate bans, and a management wrapper v0.33 with extended reporting and docker-block integration.

## Features

### Core Infrastructure

- **Full IPv4 + IPv6 Support** - 24 nftables sets (12 IPv4 + 12 IPv6) in table inet fail2ban-filter
- **12 Fail2Ban Jails** - Multi-layered security (sshd, exploit, DoS, web, recon, fuzzing, botnet, anomaly, PHP errors, recidive, manualblock)
- **12 Detection Filters** - Optimized filters for each jail
- **30d Recidive Jail** - Long-term repeat offender blocking
- **Safe Pre-Cleanup** - Backup and legacy cleanup before install

### Advanced Tools

- **One-Click Installer** - INSTALL-ALL-v033.sh orchestrates full install and upgrades from v0.19–v0.30
- **Docker Port + IP Blocking (v0.4)** - Blocks before Docker NAT using inet docker-block table and PREROUTING hook
- **Immediate Docker-Block Ban** - f2b-docker-hook.sh is called directly from Fail2Ban on ban/unban (no cron delay)
- **Docker Validate Cron** - Every-minute validation and repair of docker-banned-ipv4/ipv6 via f2b docker sync validate
- **F2B Wrapper v0.33** - 50+ management functions with attack analysis, reports, and improved locking
- **Auto-Sync Service** - Initial Fail2Ban → nftables sync after install
- **Minimal Bash Aliases** - Optional quick access shortcuts
- **ShellCheck Friendly** - Scripts follow consistent style and metadata headers

### Security Layers

#### 12 Fail2Ban Jails

1. **sshd** - SSH brute-force protection (multi-mode)
2. **sshd-slowattack** - Slow SSH attack patterns
3. **f2b-exploit-critical** - Critical exploit scanners and web payloads
4. **f2b-dos-high** - DoS and DDoS attack detection
5. **f2b-web-medium** - SQL injection, path traversal and similar web attacks
6. **nginx-recon-optimized** - Nginx reconnaissance and directory enumeration
7. **f2b-fuzzing-payloads** - Fuzzing detection for malformed requests
8. **f2b-botnet-signatures** - Known botnet and scanner signatures
9. **f2b-anomaly-detection** - Anomaly patterns (HTTP and access anomalies)
10. **nginx-php-errors** - PHP fatálne chyby / anomálne HTTP 5xx patterny
11. **manualblock** - Manual IP banning jail
12. **recidive** - Repeat offenders with 30-day ban

Each jail is configured in jail.local with proper banaction mapping to nftables and docker-hook.

#### 12 Detection Filters

All jail filters live in filters/ style configs:
- sshd.conf, f2b-exploit-critical.conf, f2b-dos-high.conf, f2b-web-medium.conf
- nginx-recon-optimized.conf, f2b-fuzzing-payloads.conf, f2b-botnet-signatures.conf
- f2b-anomaly-detection.conf, nginx-php-errors.conf, manualblock.conf, recidive.conf

Three local filter tuning files extend behaviour via ignoreregex and custom patterns: nginx-recon-optimized.local, f2b-anomaly-detection.local, and nginx-php-errors.local.

## Docker Protection

Docker containers are protected the same way as the host. All Fail2Ban bans are propagated to docker-block, so packets are dropped before reaching Docker services.

Key points:

- **Immediate ban path:**
  - Fail2Ban action docker-sync-hook.conf calls f2b-docker-hook.sh on ban/unban
  - Hook writes IP into docker-banned-ipv4 or docker-banned-ipv6 in inet docker-block with timeout equal to bantime

- **Validate cron path:**
  - 07-setup-docker-sync-cron-v033.sh installs root cron to run f2b docker sync validate every minute
  - Cron checks and repairs docker-banned-ipv4/ipv6 against Fail2Ban state and logs to /var/log/f2b-docker-sync.log

- **Port-level blocking:**
  - docker-blocked-ports set controls exposed Docker ports that should be blocked from outside

- **PREROUTING hook:**
  - nftables rules in docker-block table use hook prerouting priority dstnat to drop packets before Docker NAT

### Docker-block nftables (v0.4)

03-install-docker-block-v033.sh creates table inet docker-block with:

- **docker-blocked-ports** - ports to be blocked for external access
- **docker-banned-ipv4** - banned IPv4 addresses
- **docker-banned-ipv6** - banned IPv6 addresses
- **PREROUTING chain** that:
  - drops packets from docker-banned-ipv4/ipv6
  - enforces port restrictions from docker-blocked-ports

### Wrapper Commands (v0.33)

**Ports:**

```bash
sudo f2b manage block-port 8081
sudo f2b manage unblock-port 8081
sudo f2b manage list-blocked-ports
```

**Manual IP bans** (manual quarantine, goes to manualblock jail and nftables/docker-block):

```bash
sudo f2b manage manual-ban 198.51.100.10 7d
sudo f2b manage manual-unban 198.51.100.10
```

**Unban IP from all jails and nftables:**

```bash
sudo f2b manage unban-all 198.51.100.10
```

**Sync and docker integration:**

```bash
sudo f2b sync check
sudo f2b sync enhanced
sudo f2b sync force
sudo f2b sync silent
sudo f2b docker sync validate
```

**Docker visibility and monitoring:**

```bash
sudo f2b docker info
sudo f2b docker dashboard
```

## Quick Start

### One-Command Installation (v0.33)

```bash
tar -xzf f2b-hybrid-nftables-v033.tar.gz
cd v033
sudo bash INSTALL-ALL-v033.sh
```

The installer auto-detects:

- Fresh installation (new server)
- Upgrade from v0.19–v0.31 (preserves bans and structure)
- Reinstall v0.33 (rebuild with ban preservation)

### Interactive Configuration (First Run)

Installer can guide you through:

1. **Email notifications (optional):**
   - Detects mail service (postfix, sendmail, etc.)
   - Prompts for admin email and sender email
   - Updates jails which send email alerts on ban

2. **WAN/Server IP detection:**
   - Detects server WAN/LAN IP
   - Offers adding to ignore list to prevent self-blocking
   - Preserves loopback ranges

3. **Proceed to installation:**
   - Continues with nftables, jails, wrapper and docker-block setup

### Safe Test Mode (Recommended on Production)

```bash
sudo bash INSTALL-ALL-v033.sh --cleanup-only
```

This runs 00-pre-cleanup-v033.sh with backup and legacy cleanup, then exits before modifying nftables or jails.

### Verification

```bash
sudo f2b status
sudo nft list chain inet fail2ban-filter f2b-input | grep -c drop
sudo f2b audit
sudo bash 02-verify-jails-v033.sh
```

Expected: 24 drop rules (12 IPv4 + 12 IPv6) and all 12 jails active.

## Repository Structure (v0.33)

```
v033/
├── INSTALL-ALL-v033.sh
├── 00-pre-cleanup-v033.sh
├── 01-install-nftables-v033.sh
├── 02-install-jails-v033.sh
├── 02-verify-jails-v033.sh
├── 03-install-docker-block-v033.sh
├── 04-install-wrapper-v033.sh
├── 05-install-auto-sync-v033.sh
├── 06-install-aliases-v033.sh
├── 07-setup-docker-sync-cron-v033.sh
├── f2b-wrapper-v033.sh
├── f2b-docker-hook.sh
├── docker-sync-hook.conf
├── jail.local
├── sshd.conf
├── f2b-exploit-critical.conf
├── f2b-dos-high.conf
├── f2b-web-medium.conf
├── f2b-fuzzing-payloads.conf
├── f2b-botnet-signatures.conf
├── f2b-anomaly-detection.conf
├── nginx-recon-optimized.conf
├── nginx-php-errors.conf
├── recidive.conf
├── manualblock.conf
├── nginx-recon-optimized.local
├── f2b-anomaly-detection.local
├── nginx-php-errors.local
├── nftables-common.local
├── nftables.conf.local
├── nftables-multiport.conf
└── nftables-recidive.conf
```

## F2B Wrapper Commands (v0.33)

**Core:**

```bash
sudo f2b status           # System overview
sudo f2b audit            # Audit all jails
sudo f2b find <IP>        # Find IP in jails
sudo f2b version          # Version info (--human, --json, --short)
```

**Sync:**

```bash
sudo f2b sync check       # Verify sync
sudo f2b sync enhanced    # Enhanced checks
sudo f2b sync force       # Force sync + verify
sudo f2b sync silent      # Silent (cron-friendly)
sudo f2b docker sync validate  # Docker-block validation/repair
```

**Manage - ports:**

```bash
sudo f2b manage block-port 8081
sudo f2b manage unblock-port 8081
sudo f2b manage list-blocked-ports
```

**Manage - IPs:**

```bash
sudo f2b manage manual-ban 192.0.2.1 30d
sudo f2b manage manual-unban 192.0.2.1
sudo f2b manage unban-all 192.0.2.1
```

**Monitor:**

```bash
sudo f2b monitor watch
sudo f2b monitor trends
sudo f2b monitor top-attackers
sudo f2b monitor show-bans
sudo f2b monitor jail-log sshd 50
```

**Reports and analysis:**

```bash
sudo f2b report json > report.json
sudo f2b report csv > report.csv
sudo f2b report daily
sudo f2b report attack-analysis
sudo f2b report attack-analysis --npm-only
sudo f2b report attack-analysis --ssh-only
```

**Docker:**

```bash
sudo f2b docker dashboard
sudo f2b docker info
sudo f2b docker sync validate
```

**Silent / cron:**

```bash
sudo f2b audit-silent
```

## What Is New in v0.33

- Added nginx-php-errors jail + filter (12 jails, 12 filters, 24 nftables sets)
- Updated nftables installer to create 24 sets and 24 INPUT rules (12 IPv4 + 12 IPv6)
- Extended wrapper and verify scripts to support 12 jails
- Infrastructure counts: 12 jails, 12 filters, 12+12 sets, 24 INPUT, 8 FORWARD
- All scripts updated to v0.33 metadata

## Troubleshooting

**Scripts cannot find config or filters:**

```bash
cd v033/
sudo bash INSTALL-ALL-v033.sh
```

**Jail not starting:**

```bash
sudo tail -f /var/log/fail2ban.log
sudo fail2ban-regex /path/to/log /etc/fail2ban/filter.d/<filter>.conf
sudo bash 02-verify-jails-v033.sh
```

**nftables rules missing:**

```bash
sudo nft list table inet fail2ban-filter
sudo nft list chain inet fail2ban-filter f2b-input | grep -c drop
sudo bash 01-install-nftables-v033.sh
```

**Sync problems:**

```bash
sudo f2b sync check
sudo f2b sync force
sudo f2b sync enhanced
```

**Docker-block not working:**

```bash
sudo nft list table inet docker-block
sudo f2b docker info
sudo f2b docker sync validate
crontab -l | grep f2b
sudo f2b docker dashboard
sudo tail -50 /var/log/f2b-docker-sync.log
```

## License

MIT License - see LICENSE file.

## Author

Peter Bakic - self-hosted infrastructure and security.

## Support

- GitHub Issues for bugs and feature requests
- Verification tool: sudo bash 02-verify-jails-v033.sh

---

**Version:** 0.33
**Wrapper:** v0.33
**Last Updated:** December 29, 2025
**Production Ready:** Yes
