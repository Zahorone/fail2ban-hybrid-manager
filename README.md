# Fail2Ban Hybrid Manager

Fail2Ban Hybrid Manager is a production-ready toolkit for integrating Fail2Ban with nftables (IPv4 + IPv6) and Docker, with a focus on hardened, repeatable server setups.

## What this project provides

- A curated set of Fail2Ban jails and filters for SSH and web applications.
- 🔄 **HTTP/HTTPS backward compatibility** – filters work with both protocols
- A dual‑stack nftables ruleset (IPv4 + IPv6) managed via exportable `.nft` files.
- A management wrapper (`f2b`) with convenience commands for:
  - inspecting jails and bans,
  - synchronizing Fail2Ban ↔ nftables,
  - managing manual bans,
  - controlling Docker‑exposed ports.
- 🚀 NPM Nginx Proxy Manager support (Force SSL, HSTS, HTTP/2)
- 📦 Self-contained production release packages
- A complete production release package under `releases/v0.21/` with a one‑command installer.

## Releases

- **v0.21** (Latest) – HTTP/HTTPS backward compatibility, Force SSL support
- **v0.20** – Previous release

For details of the current stable release, see:

- `releases/v0.21/README.md` – **Fail2Ban + nftables v0.21 – Production Setup**

## Repository layout

- `releases/` – versioned, self‑contained release packages (starting with v0.20)
- `releases/v0.21/` – current stable production bundle
- `releases/v0.20/` - Previous release
- `scripts/` (if present) – helper or development scripts
- `docs/` – additional project‑level documentation (optional)

## Usage

By default, email notification addresses (`destemail`, `sender`) and `ignoreip` in `config/jail.local` are set to generic values. 
For production, update them before running the installer.

For most users, the recommended way is to download the packaged release:

```bash
# Example: using v0.21 release package
tar -xzf fail2ban-nftables-v0.21-production.tar.gz
cd v0.21

chmod +x INSTALL-ALL-v021.sh
sudo bash INSTALL-ALL-v021.sh
```

After installation you can use:

```bash
sudo f2b status
sudo f2b audit
sudo f2b sync check
sudo f2b manage docker-info
```

For full installation and troubleshooting instructions, follow the documentation in `releases/v0.21/README.md` and the `docs/` directory inside that release package.

## License

MIT License – see `LICENSE`.

## 👤 Author

Peter Bakič  
vibes coder · self-hosted infra & security  
Powered by Claude Sonnet 4.5 thinking

## ☕ Support

If this project helps you secure your servers and you want to support further development:

- Buy me a coffee: https://www.buymeacoffee.com/peterdelac
