# 🚀 Fail2Ban Hybrid Manager

Fail2Ban Hybrid Manager je production-ready toolkit pre integráciu Fail2Ban s nftables (IPv4 + IPv6) a Dockerom, zameraný na hardened, opakovateľné servery – aktuálne s **v0.33 PHP Error Detection & Docker Auto-Sync Edition**.

## What this project provides

- A curated set of **12 Fail2Ban jails** and detection filters for SSH and web applications
- ⭐ **nginx-php-errors Jail (NEW)** – Universal PHP error detection for all PHP applications (WordPress, Laravel, Symfony, Magento, EasyAppointment, custom apps)
- 🌐 **Full IPv4/IPv6 dual-stack** – 24 nftables sets with complete protocol coverage
- 🔄 **HTTP/HTTPS backward compatibility** – filters work with both protocols
- A dual‑stack nftables ruleset (IPv4 + IPv6) managed via exportable `.nft` files
- 🐋 **Full Docker protection** – banned IPs are dropped before reaching Docker containers (PREROUTING)
- 🔄 **Docker Auto-Sync Cron v0.4 (CRITICAL)** – Every 1 minute, prevents bans from clearing on container restart ⚡
- A management wrapper (`f2b`) with 50+ commands for:
  - inspecting jails and bans
  - synchronizing Fail2Ban ↔ nftables ↔ docker-block
  - managing manual bans and unbans across all jails
  - controlling Docker‑exposed ports and IP blocking
  - real-time monitoring and dashboards
- 🚀 NPM Nginx Proxy Manager support (Force SSL, HSTS, HTTP/2)
- 📦 Self-contained production release packages
- ✅ **Clean install support** – works on fresh servers without existing Fail2Ban
- 🔄 **Auto-sync cron** – Docker containers stay protected automatically

## Releases

- **v0.33** (Latest) ⭐ **PHP Error Detection & Docker Auto-Sync**: 
  - ✨ Added 12th jail: `nginx-php-errors` (PHP fatals + HTTP 5xx)
  - 🐳 Docker-Block v0.4 with critical auto-sync cron (1 min)
  - 🌐 24 nftables sets (12 IPv4 + 12 IPv6)
  - 🛠️ Wrapper v0.33 with 50+ functions
  - 📧 Interactive installer (Email/Network/Docker config)
  - Safe upgrade from v0.31 (preserves all bans)
  - ✅ Verified on: WordPress, Laravel, Symfony, Magento, EasyAppointment, custom PHP apps

- **v0.31** – Immediate Docker Ban Edition: immediate docker-block bans via f2b-docker-hook.sh, wrapper v0.32, validate cron (11 jails, 22 sets, 22 INPUT, 6 FORWARD)

- **v0.30** – First fully one‑click production bundle (safe pre-cleanup, Docker-block v0.4 + auto-sync, wrapper v0.30 s attack analysis)

- **v0.24 / v0.22** – Older production bundles (recidive 30d, 11 jails, Docker integrácia)

- **v0.21** – HTTP/HTTPS backward compatibility, Force SSL podpora

- **v0.20** – Full IPv6 support

Pre detailný popis aktuálneho stable release:

- `releases/v0.33/README.md` – Fail2Ban + nftables v0.33 – PHP Error Detection Edition
- `releases/v0.33/CHANGELOG.md` – Detailed version history
- `releases/v0.33/MIGRATION-GUIDE.md` – Upgrade path from v0.31
- `releases/v0.33/PACKAGE-INFO.txt` – Package info a upgrade paths

## Repository layout

```
releases/
├── v0.33/ # Current stable PHP Error Detection bundle ⭐
│ ├── INSTALL-ALL-v033.sh
│ ├── scripts/ (8 install scripts)
│ ├── filters/ (12 filter configs)
│ ├── actions/
│ ├── config/
│ ├── f2b-wrapper-v033.sh
│ ├── README.md
│ ├── CHANGELOG.md
│ ├── MIGRATION-GUIDE.md
│ ├── PACKAGE-INFO.txt
│ └── LICENSE
├── v0.31/ # Previous one-click production bundle
├── v0.30/
├── v0.24/
├── v0.22/
├── v0.21/
└── v0.20/
```

## Usage

By default, email notification addresses (`destemail`, `sender`) and `ignoreip` in `config/jail.local` are set to generic values. For production, update them before running the installer.

### Interactive Setup

The installer guides you through configuration interactively:

- **Email Notifications** – detects mail service, prompts for admin email, shows which jails send alerts
- **WAN/Server IP Auto-Detection** – auto-detects your server IP, optionally adds it to Fail2Ban ignore list (prevents self-blocking)
- **Docker Configuration** – Configure Docker subnet whitelist (ignoreip)
- **No manual editing needed** – all configuration happens during installation

For most users, the recommended way is to download the packaged **v0.33** release:

```bash
wget https://github.com/Zahorone/fail2ban-hybrid-manager/releases/download/v0.33/fail2ban-hybrid-manager-v0.33.tar.gz

tar -xzf fail2ban-hybrid-manager-v0.33.tar.gz
cd v0.33/

sudo bash INSTALL-ALL-v033.sh
```

Safe test mode on production (no firewall changes yet):

```bash
sudo bash INSTALL-ALL-v033.sh --cleanup-only
```

After installation you can use:

```bash
sudo f2b status
sudo f2b monitor watch
sudo f2b list banned
sudo f2b ban 192.168.1.100
sudo f2b unban 192.168.1.100
sudo f2b sync docker          # Sync banned IPs to docker-block
sudo f2b docker info          # Docker-block table status
sudo f2b docker dashboard     # Live monitoring
sudo f2b report json          # Generate report
sudo f2b doctor               # System diagnostics
```

For full installation and troubleshooting instructions, follow:

- `releases/v0.33/README.md`
- `releases/v0.33/MIGRATION-GUIDE.md` (for v0.31 → v0.33 upgrade)
- `releases/v0.33/PACKAGE-INFO.txt`

## What's New in v0.33

- ⭐ **nginx-php-errors Jail (NEW)** – Universal PHP error detection for **ALL PHP applications**
  - Detects: PHP fatal errors, parse errors, HTTP 5xx patterns
  - Works with: WordPress, Drupal, Joomla, Laravel, Symfony, Magento, EasyAppointment, custom PHP apps
  - Compatible with nginx reverse proxy (X-Real-IP headers)
  - Docker-aware (persistent bans across container restarts)

- 🐳 **Docker-Block v0.4 (CRITICAL)** – Auto-sync cron every 1 minute
  - Prevents bans from clearing on container restart
  - Zero downtime protection for Docker deployments
  - Log: `/var/log/f2b-docker-sync.log`

- 🌐 **24 nftables Sets** – Full IPv4/IPv6 coverage (12 jails × 2 protocols)
  - All 12 jails protected on both protocols
  - IPv6 address logging and ban tracking

- 🛠️ **Wrapper v0.33** – 50+ functions with enhanced monitoring
  - Enhanced logging and diagnostics
  - Better error handling during high load

- 📧 **Interactive Installer v0.33**
  - Restored Email/Network configuration with auto-detection
  - Auto-detect mail service for notifications
  - Auto-detect server IP (optional whitelist)
  - Pre-cleanup with nftables backup

### Infrastructure Comparison

| Feature | v0.31 | v0.33 |
|---------|-------|-------|
| **Jails** | 11 | **12** ⭐ |
| **nftables Sets** | 22 (11+11) | **24 (12+12)** ⭐ |
| **INPUT Rules** | 22 | **24** |
| **FORWARD Rules** | 6 | **8** |
| **Docker Auto-Sync** | ✅ | ✅ Every 1 min |
| **PHP Error Detection** | ❌ | **✅ NEW** |
| **Total Files** | 34 | **42** |

## License

MIT License – see `LICENSE`.

## 👤 Author

**Peter Bakič**  
vibes coder · self-hosted infra & security  
Powered by Claude Sonnet 4.5 thinking

## ☕ Support

If this project helps you secure your servers and you want to support further development:

- Buy me a coffee: https://www.buymeacoffee.com/peterdelac
- Star this repository ⭐
- Report issues and contribute improvements

---

**v0.33 - Production Ready for All PHP Applications & Docker Deployments** 🚀
