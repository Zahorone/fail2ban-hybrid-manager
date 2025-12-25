# Changelog

All notable changes to this project will be documented in this file.
## [0.31] - 2025-12-26

### 🚀 Wrapper v0.32 + okamžitý Docker-block ban

Production release pre infraštruktúru v0.31 s novým wrapperom v0.32, okamžitým banom do docker-block a vylepšeným IPv4/IPv6 sync.

### Added

- **F2B Unified Wrapper v0.32 (release v0.31)**  
  - Lock mechanizmus `/tmp/f2b-wrapper.lock` proti paralelným behom wrappera.  
  - Vylepšené `validate_ip()` (IPv6 check cez `ip(8)` + fallback) a prísnejšie `validate_port()`.  
  - `jq` helpery (`jq_safe_parse`, `jq_prettify`) pre bezpečnejšie parsovanie `nft -j` výstupov.  
  - Nové reporty: `report json/csv/daily`, `audit-silent`, `stats-quick`, attack-analýza (NPM + SSH). [file:58]

- **Okamžitý Docker-block ban (Fail2Ban → nftables)**  
  - Nová Fail2Ban action `docker-sync-hook.conf` volá  
    `f2b-docker-hook ban|unban <ip> <jail> <bantime>`. [file:36][file:51]  
  - `f2b-docker-hook.sh` pridáva/odstraňuje IP priamo do/z setov `docker-banned-ipv4` / `docker-banned-ipv6` v tabuľke `inet docker-block` s timeoutom podľa `bantime`. [file:51][file:61]  
  - Banned IP sú tak blokované v PREROUTING okamžite pri bane, bez čakania na periodický docker sync. [file:61]

- **Docker-block cron validate**  
  - `07-setup-docker-sync-cron-v031.sh` nastaví root cron:  
    `*/1 * * * * flock -n /run/f2b-docker-validate.lock /usr/local/bin/f2b docker sync validate …`. [file:54]  
  - Cron každú minútu validuje a opravuje stav `docker-banned-ipv4/ipv6` podľa Fail2Ban a rotuje log `/var/log/f2b-docker-sync.log`. [file:54]

- **Initial F2B → nftables auto-sync**  
  - `05-install-auto-sync-v031.sh` spraví jednorazový full sync všetkých jailov F2B → `inet fail2ban-filter` (IPv4 + IPv6) a porovná počty IP. [file:50]  
  - Podporuje dodatočný repair cez `f2b sync force` (wrapper). [file:58]

### Changed

- **nftables infra (v0.31)**  
  - `01-install-nftables-v031.sh` udržiava štruktúru 11 IPv4 + 11 IPv6 setov v `inet fail2ban-filter`, s aktualizovaným komentárom a metadátami v0.31. [file:52]  
  - `nftables-*.conf` a `nftables-*.local` sú zladené na jednotné mená: `addr_set = f2b-<name>`, `table = fail2ban-filter`, `chain = f2b-input`, `table_family = inet`. [file:39][file:42][file:41][file:40]

- **Docker-block v0.4 (v0.31)**  
  - `03-install-docker-block-v031.sh` vytvára `table inet docker-block` so setmi `docker-blocked-ports`, `docker-banned-ipv4`, `docker-banned-ipv6` a PREROUTING chainom, ktorý najprv dropne banned IP, potom rieši porty. [file:61]  
  - Inštalátor `07-setup-docker-sync-cron-v031.sh` bol prepísaný na použitie `f2b docker sync validate` namiesto starého `f2b sync docker` patternu. [file:54]

- **Wrapper installer a aliasy**  
  - `04-install-wrapper-v031.sh` kontroluje `RELEASE/ VERSION` wrappera (min. 0.32) a inštaluje ho ako `/usr/local/bin/f2b`. [file:56][file:58]  
  - `06-install-aliases-v031.sh` aktualizovaný, aby mapoval na nové príkazy wrappera (vrátane `audit-silent`, `report attack-analysis`, `docker dashboard`). [file:57][file:58]

- **Verify & jails tooling**  
  - `02-verify-jails-v031.sh` aktualizovaný pre v0.31: presné počítanie IPv4/IPv6 IP vo F2B vs. nft setoch (vrátane `-v6`), tolerancia ±1 kvôli interval merge a rozšírené výpisy. [file:60]  
  - `02-install-jails-v031.sh` inštaluje všetky jail + filter + action súbory v novej štruktúre (vrátane anomaly detection a nginx recon tuningu). [file:59][file:43][file:49][file:38][file:46][file:47]

### Version Comparison (update)

Do existujúcej tabuľky pridať stĺpec v0.31:


## [0.30] - 2025-12-19

### 🚀 One‑Click Production Installer (v0.30)

First fully consolidated **one‑click** production release for Fail2Ban Hybrid Nftables Manager.

### Added
- **Universal Installer v0.30**
  - `INSTALL-ALL-v030.sh` orchestrates full install/upgrade:
    - Pre‑cleanup & backup (`00-pre-cleanup-v030.sh`)
    - nftables infrastructure (`01-install-nftables-v030.sh`)
    - Jails + filters + actions (`02-install-jails-v030.sh`)
    - Wrapper v0.30 (`f2b-wrapper-v030.sh` → `/usr/local/bin/f2b`)
    - Auto‑sync service + cron (`05-install-auto-sync-v030.sh`, `07-setup-docker-sync-cron-v030.sh`)
  - Auto‑detects: fresh install / upgrade from v0.19–v0.24 / reinstall v0.30
  - Preserves existing bans and nftables structure

- **Safe Pre‑Cleanup**
  - `00-pre-cleanup-v030.sh`:
    - Full backup of fail2ban and nftables configs
    - Safe cleanup of legacy systemd units, cron entries, aliases
    - FORCE mode (`--clean-install/--force-cleanup`) with explicit warnings
    - `--cleanup-only` mode for dry‑run on production
    
### Interactive Setup & Configuration

- **Email Configuration**
  - Interactive prompts for `destemail` and `sender`
  - Auto-detects mail service (postfix, sendmail, etc.)
  - Shows which jails send email alerts: sshd, sshd-slowattack, exploit-critical, dos-high, web-medium, nginx-recon, recidive
  - Updates `config/jail.local` before installation

- **WAN/Server IP Auto-Detection**
  - 3-method detection: `hostname -I`, `ip addr`, `ifconfig`
  - Prompts to add server IP to Fail2Ban `ignoreip` list
  - Prevents accidental self-blocking during SSH/web brute-force
  - Preserves localhost (127.0.0.1/8, ::1)

- **Metadata Framework v0.30**
  - Unified metadata header in all scripts:
    - `RELEASE`, `VERSION`, `BUILD_DATE`, `COMPONENT_NAME`
  - Consistent banners, logging functions, and colors
  - ShellCheck‑clean scripts (syntax + style)

- **Minimal F2B Aliases (Optional)**
  - `06-install-aliases-v030.sh`:
    - Minimal alias set:
      - `f2b-status`, `f2b-audit`
      - `f2b-watch`, `f2b-trends`
      - `f2b-sync`, `f2b-sync-enhanced`, `f2b-sync-docker`
      - `f2b-docker-dashboard`
      - `f2b-attack-analysis`
      - `f2b-audit-silent`
    - Idempotent update of `~/.bashrc` with backup

### Changed
- **Wrapper v0.30 (`f2b-wrapper-v030.sh`)**
  - Refined attack analysis (NPM + SSH):
    - `report attack-analysis`
    - `--npm-only` / `--ssh-only` modes
  - Improved jq helpers and numeric sanitization
  - Safer lock handling, better error messages
  - ShellCheck cleanup (SC2034, SC2086, SC2126, SC2155, SC2188, SC1083)

- **nftables & jails**
  - Structure from v0.22/v0.24 preserved:
    - 11 IPv4 sets + 11 IPv6 sets
    - 22 INPUT rules, 6 FORWARD rules
    - 11 jails + 11 filters
  - `02-install-jails-v030.sh` and `02-verify-jails-v030.sh` updated:
    - Unified component metadata
    - Fixed minor path/variable typos
    - Explicit verification of banactions (7d vs 30d)

- **Docker‑Block Integration**
  - `03-install-docker-block-v030.sh`:
    - Installs `docker-block` table and DOCKER-USER integration
    - Ensures persistent port set in `/etc/nftables/docker-block.nft`
  - `05-install-auto-sync-v030.sh` + `07-setup-docker-sync-cron-v030.sh`:
    - Install auto‑sync service + cron (every minute)
    - Clear status banners and checks for existing cron entries
    
## Version Comparison
| Feature               | v0.18 | v0.19 | v0.20        | v0.30                 | v0.31                       |
|-----------------------|-------|-------|--------------|-----------------------|-----------------------------|
| IPv4 Support          | ✅    | ✅    | ✅           | ✅                    | ✅                          |
| IPv6 Support          | ❌    | ❌    | ✅ (10 sets) | ✅ (11 sets)          | ✅ (11 sets)                |
| nftables Sets         | 10    | 10    | 20 (10+10)   | 22 (11+11)            | 22 (11+11)                  |
| INPUT Rules           | 10    | 10    | 20 (10+10)   | 22 (11+11)            | 22 (11+11)                  |
| FORWARD Rules         | 3     | 3     | 6 (3+3)      | 6 (3+3)               | 6 (3+3)                     |
| Fail2Ban Jails        | 10    | 10    | 10           | 11                    | 11                          |
| Detection Filters     | 10    | 10    | 10           | 11                    | 11                          |
| F2B Wrapper Functions | 35    | 43    | 43           | 50+                   | 50+ (reports, analysis)     |
| Lock Mechanism        | ❌    | ✅    | ✅           | ✅                    | ✅ (improved, /tmp lock)   |
| Attack Trends         | ❌    | ✅    | ✅           | ✅ (enhanced)         | ✅ (with attack analysis)  |
| JSON/CSV Export       | ❌    | ✅    | ✅           | ✅                    | ✅                         |
| Dual Install Scripts  | ❌    | ❌    | ✅           | ✅ (kept for tools)   | ✅ (kept for tooling)      |
| Universal Installer   | ❌    | ❌    | ✅ (v0.20)   | ✅ (v0.30 one‑click)  | ✅ (v0.31 updated bundle)  |
| Auto-Upgrade Detect.  | ❌    | ❌    | ✅           | ✅ (multi‑path)       | ✅                         |
| Docker Immediate Ban  | ❌    | ❌    | ❌           | ❌                    | ✅ (f2b-docker-hook)       |
| Docker Validate Cron  | ❌    | ❌    | ✅ (basic)   | ✅                    | ✅ (docker sync validate)  |


### Compatibility
- ✅ Clean install support (fresh servers)
- ✅ Upgrade from v0.19–v0.24 while preserving bans
- ✅ One‑click reinstall v0.30 (rebuild with preserved bans)
- ✅ All scripts ShellCheck‑clean and consistent with v0.30 metadata

---

## [0.22] - 2025-12-12

### 🎯 Clean Install & Path Resolution Fix

Critical fixes for clean installations and proper path handling in modular structure.

### Fixed
- **Clean Install Support**
  - `01-install-nftables-v022.sh`: Conditional fail2ban restart (only if service exists and has jails)
  - `02-install-jails-v022.sh`: Proper path resolution from parent directory
  - KROK 7/8 in nftables script now skip fail2ban operations if service not yet installed
  - No more errors during fresh installations

- **Path Resolution**
  - Scripts now correctly resolve paths when called from `INSTALL-ALL-v022.sh`
  - `PARENTDIR` detection: `scripts/` → `v0.22/` → finds `config/` and `filters/`
  - Fixed: filters not found when scripts run from `scripts/` subdirectory

- **Filter Installation Logic**
  - `nginx-recon-optimized.local` → `/etc/fail2ban/filter.d/` (not `jail.d`)
  - `f2b-anomaly-detection.local` → `/etc/fail2ban/filter.d/` (not `jail.d`)
  - Both files now treated as filter extensions (ignoreregex), not jail configs
  - Idempotent filter installation with automatic backup

### Changed
- **02-install-jails-v022.sh**
  - Updated from v021 to v022
  - Added 11th jail support (f2b-anomaly-detection)
  - Improved error handling and logging
  - Better file detection with fallbacks
  - Enhanced confirmation prompts showing exact target paths

- **02-verify-jails-v022.sh**
  - Added `sshd-slowattack` check
  - Added `f2b-anomaly-detection` check
  - Enhanced runtime status checks
  - Better error handling when fail2ban not running
  - Improved nftables integration verification

- **01-install-nftables-v022.sh**
  - Conditional KROK 7: Only restart fail2ban if service exists and has jails
  - Conditional KROK 8: Only check sync if fail2ban is active
  - Added detailed nftables structure verification (counts sets, rules)
  - Better messaging for clean install vs upgrade scenarios

### Added
- **Robust Installation Flow**
  - Pre-checks before each critical operation
  - Graceful handling of missing services
  - Clear messaging for clean install vs upgrade paths
  - Detailed logging of what was installed where

### Jails
- Total jails: **11** (was 10 in v0.21)
  - Added: `f2b-anomaly-detection` (anomaly pattern detection)
  - Existing: sshd, sshd-slowattack, f2b-exploit-critical, f2b-dos-high, f2b-web-medium, nginx-recon-bonus, recidive, manualblock, f2b-fuzzing-payloads, f2b-botnet-signatures

### Filters
- Total filters: **11** (was 10 in v0.21)
  - Added: `f2b-anomaly-detection.conf`
  - Extra configs: `nginx-recon-optimized.local`, `f2b-anomaly-detection.local` (both → filter.d)

### Compatibility
- ✅ Clean install support (fresh servers)
- ✅ Upgrade from v0.21 (preserves bans)
- ✅ Proper modular directory structure
- ✅ All scripts work from parent installer

---

## v0.21 - ShellCheck Compliance Release (2025-12-06)

### Changes
- ShellCheck compliance fixes (SC2155, SC2001, SC2034)
- Split declare/assign statements (28x)
- Improved error handling with printf
- Export VERSION variable for external scripts
- All 53 functions preserved and tested

### Compatibility
- ✅ Backward compatible with v0.20
- ✅ Same functionality, improved code quality
- ✅ Production ready

---

## [0.20] - 2025-12-04

### 🎉 Major Release: Full IPv6 Support

Complete infrastructure upgrade with full IPv4 + IPv6 dual-stack support.

### Added
- **Full IPv6 Support**
  - 10 IPv6 nftables sets (f2b-*-v6)
  - 10 IPv6 INPUT rules
  - 3 IPv6 FORWARD rules
  - Total: 20 sets, 20 INPUT rules, 6 FORWARD rules

- **Dual Installation Scripts**
  - `02-install-jails-v020.sh` - Full installer (copies filters automatically)
  - `02-verify-jails-v020.sh` - Verification tool (diagnostic, non-invasive)

- **Universal Installer** (`INSTALL-ALL-v020.sh`)
  - Auto-detects installation type (fresh / upgrade from v0.19 / reinstall)
  - Intelligent upgrade path from v0.19 to v0.20
  - Preserves existing bans during upgrade

- **Advanced Configuration Workflow**
  - Manual configuration option for production servers
  - Separate verification tool for post-configuration validation
  - Support for multi-server deployments with custom configs

### Changed
- **F2B Wrapper**
  - Updated version number to 0.20
  - All 43 functions preserved (no changes to functionality)
  - Updated documentation references

- **nftables Structure**
  - IPv4 sets: 10 (unchanged)
  - IPv6 sets: 10 (new)
  - INPUT rules: 10 → 20
  - FORWARD rules: 3 → 6

- **Documentation**
  - Complete README rewrite with advanced usage scenarios
  - New MIGRATION-GUIDE for v0.19 → v0.20
  - Enhanced troubleshooting section

### Migration from v0.19
The installer automatically handles v0.19 → v0.20 upgrades:
- Detects existing v0.19 installation
- Adds IPv6 infrastructure alongside IPv4
- Preserves all banned IPs
- Updates wrapper to v0.20
- No downtime required

See [MIGRATION-GUIDE.md](MIGRATION-GUIDE.md) for details.

---

## [0.19] - 2025-12

### Added
- Lock mechanism for concurrent operations
- Port validation (1-65535 range)
- Persistent logging to `/var/log/f2b-wrapper.log`
- Enhanced top attackers with historical data
- Attack trend analysis (`monitor trends`)
- Jail-specific log filtering (`monitor jail-log`)
- JSON/CSV export (`report json`, `report csv`)
- Daily summary reports (`report daily`)

### Changed
- Enhanced error handling
- Improved logging functions (6 log levels)
- Better sync detection (±1 tolerance for range merges)

### Fixed
- Race conditions in sync operations
- Port validation edge cases
- Log file rotation issues

---

## [0.18] - 2025-11

### Added
- Initial unified wrapper implementation
- 10 Fail2Ban jails
- 10 Detection filters
- Docker port blocking v0.3
- Auto-sync service
- Bash aliases
- nftables integration

### Features
- Core commands: status, audit, find, version
- Sync operations: check, enhanced, force, silent
- Manage operations: ports, IPs, system
- Monitor operations: status, bans, top-attackers, watch
- Silent operations for cron

---

## Version Comparison

| Feature              | v0.18 | v0.19 | v0.20 |
|----------------------|-------|-------|-------|
| IPv4 Support         | ✅    | ✅    | ✅    |
| IPv6 Support         | ❌    | ❌    | ✅    |
| nftables Sets        | 10    | 10    | 20 (10+10) |
| INPUT Rules          | 10    | 10    | 20 (10+10) |
| FORWARD Rules        | 3     | 3     | 6 (3+3) |
| Fail2Ban Jails       | 10    | 10    | 10    |
| Detection Filters    | 10    | 10    | 10    |
| F2B Wrapper Functions| 35    | 43    | 43    |
| Lock Mechanism       | ❌    | ✅    | ✅    |
| Attack Trends        | ❌    | ✅    | ✅    |
| JSON/CSV Export      | ❌    | ✅    | ✅    |
| Dual Install Scripts | ❌    | ❌    | ✅    |
| Universal Installer  | ❌    | ❌    | ✅    |
| Auto-Upgrade Detect. | ❌    | ❌    | ✅    |

---

## Roadmap

### v1.0 (Future)
- Web dashboard for monitoring
- Email alerting integration
- GeoIP blocking support
- Advanced rate limiting
- Custom chain support
- Complete API
- Multi-node synchronization
- Cloud integration (AWS, Azure, GCP)
- Machine learning threat detection

---

## Contributing

We welcome contributions! Please:
1. Fork the repository
2. Create a feature branch
3. Submit a pull request

---

## Support

- **GitHub Issues:** Bug reports and feature requests
- **Documentation:** See `docs/` directory
- **Verification Tool:** `sudo bash scripts/02-verify-jails-v030.sh`
