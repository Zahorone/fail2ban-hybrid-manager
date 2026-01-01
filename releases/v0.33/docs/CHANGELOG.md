# Changelog

All notable changes to this project will be documented in this file.

## [v0.33] - 2026-01-01 - "Twelve Jails, Twenty-Four Sets"

### 🎯 nginx-php-errors Jail + Extended Infrastructure

Production release adding 12th jail for PHP error and HTTP 5xx anomaly detection with full IPv4/IPv6 support (24 nftables sets total), plus critical Docker-block improvements.

### Added
- **New Jail (12th)**: `nginx-php-errors`
  - Detects PHP fatal errors and HTTP 5xx anomalies.
  - Filter: `f2b-nginx-php-errors.conf` (logs PHP errors from nginx error_log).
  - Local tuning: `nginx-php-errors.local` (ignoreregex extensions).
  - Action: Mapped to `nftables-multiport` (7d ban) + docker-hook.
  - Sets: `f2b-nginx-php-errors` (IPv4) & `f2b-nginx-php-errors-v6` (IPv6).
- **Docker Port Blocking v0.4**:
  - **CRITICAL**: Added auto-sync cron job (running every 1 minute) to ensure bans persist even after container recreation.
  - Improved robustness against Docker restarts.
  - Added `f2b sync docker` command for manual synchronization.
- **Interactive Installer (v0.33)**:
  - Restored interactive Email & Network configuration from v0.31.
  - Automatic detection of SSH client IP for whitelist.
  - Improved Docker bridge network detection for `ignoreip`.
  - Added step-by-step verification of all 24 IPv4/IPv6 sets.

### Changed
- **nftables Infrastructure**:
  - Set count increased to 24 (12 IPv4 + 12 IPv6).
  - INPUT rules increased to 24 (12 IPv4 + 12 IPv6).
  - FORWARD rules increased to 8 (4 IPv4 + 4 IPv6, including PHP jail).
  - All jails now have consistent IPv4/IPv6 set pairs.
- **Fail2Ban Configuration**:
  - Updated `jail.local` to include `nginx-php-errors`.
  - Tuned `f2b-exploit-critical` and `recidive` bantimes.
  - All jails now use `nftables-multiport` action with seamless Docker hook integration.
- **Wrapper Script (`f2b`)**:
  - Extended JAILS array to 12 jails.
  - Updated `f2b status` to display both IPv4 and IPv6 set counts.
  - `f2b doctor` now checks for IPv6 connectivity and set existence.
  - `f2b monitor` updated to reflect new jail structure.
- **Security Headers**:
  - Nginx configuration updated with stricter HSTS (`max-age=63072000`), `Permissions-Policy`, and optimized `Content-Security-Policy`.

### Fixed
- Fixed issue where Docker container restarts could clear iptables/nftables rules (addressed by auto-sync cron).
- Resolved potential race conditions in `fail2ban-client` interactions during high load.
- Corrected `sed` conflict in `INSTALL-ALL` script regarding email configuration.

### Removed
- Legacy `iptables` dependencies (fully migrated to `nftables` native sets).

### Jails (Full List)
1. **sshd** (IPv4 + IPv6)
2. **sshd-slowattack** (IPv4 + IPv6)
3. **f2b-exploit-critical** (IPv4 + IPv6)
4. **f2b-dos-high** (IPv4 + IPv6)
5. **f2b-web-medium** (IPv4 + IPv6)
6. **nginx-recon-optimized** (IPv4 + IPv6)
7. **f2b-fuzzing-payloads** (IPv4 + IPv6)
8. **f2b-botnet-signatures** (IPv4 + IPv6)
9. **f2b-anomaly-detection** (IPv4 + IPv6)
10. **nginx-php-errors** ⭐ NEW (IPv4 + IPv6)
11. **manualblock** (IPv4 + IPv6)
12. **recidive** (IPv4 only logic, bans both protocols)

---
## [v0.31.1] (2025-12-28) - "Idempotent Fix & Sync Order"

[FIX] 🔧 docker-block timeout: 1h → 7d (set default)
      f2b docker sync full no longer inserts timeout 1h → expires 6d23h... (nft get element OK)

[FIX] 🔧 03-install-docker-block-v033.sh → FULLY IDEMPOTENT
      - write_if_changed(): file overwritten ONLY on change (cmp)
      - /etc/nftables.conf: NON-DESTRUCTIVE patch (adds include only)
      - Runtime: delete table inet docker-block → nft -f (no duplicates)
      - Auto-repopulation: f2b docker sync full after table reload

[FIX] 🔧 INSTALL-ALL: Swapped order wrapper → docker-block (step 4/5)
      Wrapper installed FIRST → f2b docker sync full works immediately after docker-block

[ENHANCEMENT] ➕ 03-install-wrapper-v033.sh: --yes / --non-interactive
               Suppresses all read prompts → fully automated from INSTALL-ALL

[ENHANCEMENT] ➕ INSTALL-ALL-v033.sh: SAFETY NET FALLBACK
               Step 4: 03-wrapper → fallback 04-wrapper
               Step 5: 04-docker-block → fallback 03-docker-block
               Upgrade compatibility without manual renaming

---

## [v0.31] (2025-12-26) - "Wrapper v0.32 + Immediate Docker-Block Ban"

### 🚀 Immediate Docker-Block Ban + Wrapper v0.32

Production release for v0.31 infrastructure with okamžitý docker-block ban, wrapper v0.32, and enhanced IPv4/IPv6 sync.

### Added

- **F2B Unified Wrapper v0.32 (release v0.31)**
  - Lock mechanizmus `/tmp/f2b-wrapper.lock` proti paralelným behom wrappera
  - Vylepšené `validate_ip()` (IPv6 check cez `ip(8)` + fallback) a prísnejšie `validate_port()`
  - `jq` helpery (`jq_safe_parse`, `jq_prettify`) pre bezpečnejšie parsovanie `nft -j` výstupov
  - Nové reporty: `report json/csv/daily`, `audit-silent`, `stats-quick`, attack-analýza (NPM + SSH)

- **Okamžitý Docker-block ban (Fail2Ban → nftables)**
  - Nová Fail2Ban action `docker-sync-hook.conf` volá `f2b-docker-hook ban|unban <ip> <jail> <bantime>`
  - `f2b-docker-hook.sh` pridáva/odstraňuje IP priamo do/z setov `docker-banned-ipv4` / `docker-banned-ipv6` v tabuľke `inet docker-block` s timeoutom podľa `bantime`
  - Banned IP sú tak blokované v PREROUTING okamžite pri bane, bez čakania na periodický docker sync

- **Docker-block cron validate**
  - `07-setup-docker-sync-cron-v033.sh` nastaví root cron: `*/1 * * * * flock -n /run/f2b-docker-validate.lock /usr/local/bin/f2b docker sync validate …`
  - Cron každú minútu validuje a opravuje stav `docker-banned-ipv4/ipv6` podľa Fail2Ban a rotuje log `/var/log/f2b-docker-sync.log`

- **Initial F2B → nftables auto-sync**
  - `05-install-auto-sync-v033.sh` spraví jednorazový full sync všetkých jailov F2B → `inet fail2ban-filter` (IPv4 + IPv6) a porovná počty IP

### Changed

- **nftables infra (v0.31)**
  - `01-install-nftables-v033.sh` udržiava štruktúru 11 IPv4 + 11 IPv6 setov v `inet fail2ban-filter`
  - `nftables-*.conf` a `nftables-*.local` sú zladené na jednotné mená: `addr_set = f2b-<name>`, `table = fail2ban-filter`, `chain = f2b-input`, `table_family = inet`

- **Docker-block v0.4 (v0.31)**
  - `03-install-docker-block-v033.sh` vytvára `table inet docker-block` so setmi `docker-blocked-ports`, `docker-banned-ipv4`, `docker-banned-ipv6` a PREROUTING chainom
  - Inštalátor `07-setup-docker-sync-cron-v033.sh` bol prepísaný na použitie `f2b docker sync validate` namiesto starého `f2b sync docker` patternu

- **Wrapper installer a aliasy**
  - `04-install-wrapper-v033.sh` kontroluje `RELEASE/ VERSION` wrappera (min. 0.32) a inštaluje ho ako `/usr/local/bin/f2b`
  - `06-install-aliases-v033.sh` aktualizovaný, aby mapoval na nové príkazy wrappera

- **Verify & jails tooling**
  - `02-verify-jails-v033.sh` aktualizovaný pre v0.31: presné počítanie IPv4/IPv6 IP vo F2B vs. nft setoch
  - `02-install-jails-v033.sh` inštaluje všetky jail + filter + action súbory v novej štruktúre

### Infrastructure Counts (v0.31)

- IPv4 sets: 11
- IPv6 sets: 11
- Total sets: 22
- INPUT rules: 22 (11 IPv4 + 11 IPv6)
- FORWARD rules: 6 (3 IPv4 + 3 IPv6)
- Fail2Ban jails: 11
- Detection filters: 11

---

## [v0.30] (2025-12-19) - "One-Click Production Installer"

### 🚀 First Fully Consolidated One-Click Release

Production release with universal installer for full Fail2Ban + nftables integration.

### Added

- **Universal Installer v0.30**
  - `INSTALL-ALL-v030.sh` orchestrates full install/upgrade
  - Auto-detects: fresh install / upgrade from v0.19–v0.24 / reinstall v0.30
  - Preserves existing bans during upgrade

- **Safe Pre-Cleanup**
  - `00-pre-cleanup-v030.sh`: Full backup + legacy cleanup
  - `--cleanup-only` mode for dry-run on production
  - FORCE mode with explicit warnings

- **Interactive Setup & Configuration**
  - Email configuration (admin/sender emails)
  - WAN/Server IP auto-detection
  - Prevents accidental self-blocking
  - Preserves localhost ranges

- **Metadata Framework v0.30**
  - Unified metadata header in all scripts
  - Consistent banners, logging functions, and colors
  - ShellCheck-clean scripts

### Infrastructure (v0.30)

- IPv4 sets: 11
- IPv6 sets: 11
- Total sets: 22
- INPUT rules: 22 (11 IPv4 + 11 IPv6)
- FORWARD rules: 6
- Fail2Ban jails: 11
- Detection filters: 11

---

## Version Comparison

| Feature               | v0.18 | v0.19 | v0.20 | v0.30 | v0.31 | v0.33 |
|-------|-------|-------|-------|-------|-------|-------|
| IPv4 Support          | ✅    | ✅    | ✅    | ✅    | ✅    | ✅    |
| IPv6 Support          | ❌    | ❌    | ✅    | ✅    | ✅    | ✅    |
| nftables Sets         | 10    | 10    | 20    | 22    | 22    | 24    |
| INPUT Rules           | 10    | 10    | 20    | 22    | 22    | 24    |
| FORWARD Rules         | 3     | 3     | 6     | 6     | 6     | 8     |
| Fail2Ban Jails        | 10    | 10    | 10    | 11    | 11    | 12    |
| Detection Filters     | 10    | 10    | 10    | 11    | 11    | 12    |
| F2B Wrapper Functions | 35    | 43    | 43    | 50+   | 50+   | 50+   |
| Lock Mechanism        | ❌    | ✅    | ✅    | ✅    | ✅    | ✅    |
| Docker Immediate Ban  | ❌    | ❌    | ❌    | ❌    | ✅    | ✅    |
| Universal Installer   | ❌    | ❌    | ✅    | ✅    | ✅    | ✅    |
| Auto-Upgrade Detect   | ❌    | ❌    | ✅    | ✅    | ✅    | ✅    |

---

**Latest Version:** v0.33 (2025-12-29)
