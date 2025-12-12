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

- **v0.22** (Latest) – Clean install fixes, 11th jail (anomaly detection), full Docker integration with auto-sync
- **v0.21** – HTTP/HTTPS backward compatibility, Force SSL support
- **v0.20** – Full IPv6 support

For details of the current stable release, see:

- `releases/v0.22/docs/README.md` – **Fail2Ban + nftables v0.22 – Production Setup**

## Repository layout

- `releases/` – versioned, self‑contained release packages (starting with v0.20)
- `releases/v0.22/` – current stable production bundle (latest)
- `releases/v0.21/` – previous stable release
- `releases/v0.20/` – legacy release
- `scripts/` (if present) – helper or development scripts
- `docs/` – additional project‑level documentation (optional)

## Usage

By default, email notification addresses (`destemail`, `sender`) and `ignoreip` in `config/jail.local` are set to generic values. 
For production, update them before running the installer.

For most users, the recommended way is to download the packaged release:

Example: using v0.22 release package
```bash
tar -xzf fail2ban-nftables-v0.22-production.tar.gz
cd v0.22

chmod +x INSTALL-ALL-v022.sh
sudo bash INSTALL-ALL-v022.sh
```

After installation you can use:
```bash
sudo f2b status
sudo f2b audit
sudo f2b sync check
sudo f2b sync docker # Sync banned IPs to docker-block
sudo f2b docker info # Docker-block table status
sudo f2b docker dashboard # Live monitoring
sudo f2b manage unban-all <IP> # Unban from all jails
```

For full installation and troubleshooting instructions, follow the documentation in `releases/v0.22/docs/README.md` and `docs/PACKAGE-INFO.txt` inside that release package.

## What's New in v0.22

- ✅ **Clean install support** – no more errors on fresh servers
- ✅ **11th jail** – f2b-anomaly-detection for pattern-based threat detection
- ✅ **Docker containers protected** – all Fail2Ban bans automatically propagate to docker-block (PREROUTING)
- ✅ **Auto-sync cron** – `f2b sync docker` runs every minute via cron
- ✅ **Path resolution fixes** – modular scripts correctly find config/ and filters/
- ✅ **Enhanced wrapper** – new commands: `unban-all`, `docker info`, `docker dashboard`
- ✅ **ShellCheck clean** – all scripts pass strict linting

## License

MIT License – see `LICENSE`.

## 👤 Author

Peter Bakič  
vibes coder · self-hosted infra & security  
Powered by Claude Sonnet 4.5 thinking

## ☕ Support

If this project helps you secure your servers and you want to support further development:

- Buy me a coffee: https://www.buymeacoffee.com/peterdelac
