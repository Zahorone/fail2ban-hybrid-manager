# Fail2Ban Hybrid Manager

Fail2Ban Hybrid Manager is a production-ready toolkit for integrating Fail2Ban with nftables (IPv4 + IPv6) and Docker, with a focus on hardened, repeatable server setups.

## What this project provides

- A curated set of **11 Fail2Ban jails** and detection filters for SSH and web applications
- 🔄 **HTTP/HTTPS backward compatibility** – filters work with both protocols
- A dual‑stack nftables ruleset (IPv4 + IPv6) managed via exportable `.nft` files
- 🐋 **Full Docker protection** – banned IPs are dropped before reaching Docker containers (PREROUTING)
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

- **v0.30** (Latest) – First fully **one‑click** production bundle with `INSTALL-ALL-v030.sh`, safe pre-cleanup, Docker-block v0.4 + auto-sync, wrapper v0.30 with attack analysis
- **v0.24 / v0.22** – Previous production bundles (recidive 30d, 11 jails, Docker integration)
- **v0.21** – HTTP/HTTPS backward compatibility, Force SSL support
- **v0.20** – Full IPv6 support

For details of the current stable release, see:

- `releases/v0.30/docs/README-v030.md` – **Fail2Ban + nftables v0.30 – Production Bundle**
- `releases/v0.24/docs/README.md` – legacy v0.24 production setup (recidive 30d)

## Repository layout

```
releases/
├── v0.30/              # Current stable one-click production bundle
│   ├── INSTALL-ALL-v030.sh
│   ├── scripts/
│   ├── config/
│   ├── filters/
│   ├── action.d/
│   └── docs/
│       ├── README-v030.md
│       ├── CHANGELOG.md
│       ├── MIGRATION-GUIDE.md
│       └── PACKAGE-INFO-v030.txt
├── v0.24/              # Previous production bundle
├── v0.22/              # Older stable bundle
├── v0.21/              # Previous stable release
└── v0.20/              # Legacy release
```

## Usage

By default, email notification addresses (`destemail`, `sender`) and `ignoreip` in `config/jail.local` are set to generic values. For production, update them before running the installer.

### Interactive Setup

The installer guides you through configuration interactively:

- **Email Notifications** – detects mail service, prompts for admin email, shows which jails send alerts
- **WAN/Server IP Auto-Detection** – auto-detects your server IP, optionally adds it to Fail2Ban ignore list (prevents self-blocking)
- **No manual editing needed** – all configuration happens during installation


For most users, the recommended way is to download the packaged **v0.30** release:

```bash
tar -xzf f2b-hybrid-nftables-v030.tar.gz
cd v030

sudo bash INSTALL-ALL-v030.sh
```

Safe test mode on production (no firewall changes yet):

```bash
sudo bash INSTALL-ALL-v030.sh --cleanup-only
```

After installation you can use:

```bash
sudo f2b status
sudo f2b audit
sudo f2b sync check
sudo f2b sync docker          # Sync banned IPs to docker-block
sudo f2b docker info          # Docker-block table status
sudo f2b docker dashboard     # Live monitoring
sudo f2b manage unban-all <IP># Unban from all jails
```

For full installation and troubleshooting instructions, follow:

- `releases/v0.30/docs/README-v030.md`
- `releases/v0.30/docs/PACKAGE-INFO-v030.txt`

## What's New in v0.30

- ✅ **One-click installer** – `INSTALL-ALL-v030.sh` orchestrates pre-cleanup, nftables, jails, wrapper, Docker-block, auto-sync
- ✅ **Safe pre-cleanup** – `--cleanup-only` mode for backup + legacy cleanup without changes
- ✅ **Wrapper v0.30** – attack analysis reports (`report attack-analysis`, `--npm-only`, `--ssh-only`, `timeline`)
- ✅ **Docker-block v0.4 + cron** – PREROUTING protection, every-minute docker sync
- ✅ **Minimal alias set** – optional `f2b-*` aliases for most-used commands
- ✅ **ShellCheck-clean scripts** – consistent metadata headers and linted code

## License

MIT License – see `LICENSE`.

## 👤 Author

Peter Bakič
vibes coder · self-hosted infra & security
Powered by Claude Sonnet 4.5 thinking

## ☕ Support

If this project helps you secure your servers and you want to support further development:

- Buy me a coffee: https://www.buymeacoffee.com/peterdelac
