# Fail2Ban Hybrid Manager

Fail2Ban Hybrid Manager je production-ready toolkit pre integráciu Fail2Ban s nftables (IPv4 + IPv6) a Dockerom, zameraný na hardened, opakovateľné servery – aktuálne s v0.31 Immediate Docker Ban Edition.

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

- **v0.31** (Latest) – Immediate Docker Ban Edition: INSTALL-ALL-v031.sh, immediate docker-block bans cez f2b-docker-hook.sh + docker-sync-hook.conf, wrapper v0.32, validate cron (f2b docker sync validate), rovnaká infra (11 jails, 11+11 sets, 22 INPUT, 6 FORWARD)
- **v0.30** – First fully one‑click production bundle (safe pre-cleanup, Docker-block v0.4 + auto-sync, wrapper v0.30 s attack analysis)
- **v0.24 / v0.22** – Older production bundles (recidive 30d, 11 jails, Docker integrácia)
- **v0.21** – HTTP/HTTPS backward compatibility, Force SSL podpora
- **v0.20** – Full IPv6 support

Pre detailný popis aktuálneho stable release:

- `releases/v0.31/README.md` – Fail2Ban + nftables v0.31 – Production Bundle
- `releases/v0.31/PACKAGE-INFO.txt` – Package info a upgrade paths
- `releases/v0.30/docs/README-v030.md` – starší v0.30 bundle (referencia)

## Repository layout

```
releases/
├── v0.31/ # Current stable one-click production bundle
│ ├── INSTALL-ALL-v031.sh
│ ├── 00-07 install scripts
│ ├── *.conf / *.local / jail.local
│ ├── f2b-wrapper-v031.sh
│ ├── f2b-docker-hook.sh
│ ├── README.md
│ └── PACKAGE-INFO.txt
├── v0.30/ # Previous one-click production bundle
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
- **No manual editing needed** – all configuration happens during installation


For most users, the recommended way is to download the packaged **v0.31** release:

```bash
tar -xzf fail2ban-hybrid-manager-v0.31.tar.gz
cd v0.31

sudo bash INSTALL-ALL-v031.sh
```

Safe test mode on production (no firewall changes yet):

```bash
sudo bash INSTALL-ALL-v031.sh --cleanup-only
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

- `releases/v0.31/docs/README-v031.md`
- `releases/v0.31/docs/PACKAGE-INFO-v031.txt`

## What's New in v0.31

- ✅ Immediate Docker-Block Ban – Fail2Ban volá `f2b-docker-hook.sh` pri bane v reálnom čase, takže útočníci sú dropnutí ešte pred Dockerom (PREROUTING) bez čakania na cron.
- ✅ Wrapper v0.32 – rozšírený `f2b` wrapper s lock file (`/tmp/f2b-wrapper.lock`), vylepšenými `report` príkazmi (JSON/CSV/daily/attack-analysis) a robustnejším log parsingom.
- ✅ Docker Validate Cron – nový režim `f2b docker sync validate`, ktorý opravuje nekonzistencie medzi Fail2Ban, nftables a docker-block bez mazania platných bans.
- ✅ Stabilná infraštruktúra – stále 11 jails, 11+11 nftables sets, 22 INPUT a 6 FORWARD pravidiel, takže upgrade z v0.30 nemení sieťovú topológiu ani politiky.

## License

MIT License – see `LICENSE`.

## 👤 Author

Peter Bakič
vibes coder · self-hosted infra & security
Powered by Claude Sonnet 4.5 thinking

## ☕ Support

If this project helps you secure your servers and you want to support further development:

- Buy me a coffee: https://www.buymeacoffee.com/peterdelac
