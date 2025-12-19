# Migration Guide: v0.19 → v0.20 → v0.30

Complete guide for upgrading from legacy v0.19/v0.20 to the consolidated **v0.30 one‑click** release.

---

## 1. Legacy Upgrade: v0.19 → v0.20 / v0.21

**v0.21** improves code quality and IPv6 support while maintaining complete backward compatibility with v0.19.

### What Changes?

| Component      | v0.20                  | v0.21                  | Change                |
|----------------|------------------------|------------------------|-----------------------|
| IPv4 Sets      | 10                     | 10                     | No change ✅          |
| IPv6 Sets      | 0                      | 10                     | **+10 new**           |
| INPUT Rules    | 10                     | 20                     | **+10 IPv6 rules**    |
| FORWARD Rules  | 3                      | 6                      | **+3 IPv6 rules**     |
| Fail2Ban Jails | 10                     | 10                     | No change ✅          |
| F2B Wrapper    | v0.19 (43 func)        | v0.20 (43 func)        | Version bump only     |

### What's Preserved?

✅ All banned IPv4 addresses  
✅ All jail configurations  
✅ All custom filter modifications  
✅ All Docker port blocks  
✅ All wrapper functionality  

---

## 2. Recommended Upgrade: v0.22 / v0.24 → v0.30

Most real‑world upgrades will go directly to **v0.30**, which is the first fully consolidated one‑click installer release (`INSTALL-ALL-v030.sh`).

### v0.22/v0.24 vs v0.30 – High Level

| Component      | v0.22 / v0.24              | v0.30                           | Change / Notes                           |
|----------------|----------------------------|---------------------------------|------------------------------------------|
| IPv4 Sets      | 11                         | 11                              | No change ✅                             |
| IPv6 Sets      | 11                         | 11                              | No change (structure preserved)          |
| INPUT Rules    | 22                         | 22                              | No change ✅                             |
| FORWARD Rules  | 6                          | 6                               | No change ✅                             |
| Fail2Ban Jails | 11                         | 11                              | Names/jails preserved                    |
| F2B Wrapper    | v0.23–v0.25 (~50 funcs)    | v0.30 (50+ funcs)               | Enhanced reporting & dashboards          |
| Docker-Block   | v0.4 (manual setup)        | v0.4 + auto‑sync + cron         | Auto‑sync job + service hardening        |
| Install Flow   | Multi-step scripts         | Single `INSTALL-ALL-v030.sh`    | **One‑click installer**                  |

If you are already on v0.22/v0.24, v0.30 **rebuilds and verifies** the same firewall structure, not changing IPv4/IPv6 semantics – it standardizes metadata, wrapper, and automation around it.

---

## 3. Pre‑Migration Checklist (Legacy v0.19 → v0.20)

This section remains valid for legacy installations still on v0.19.

### 3.1 Backup Current Configuration

```bash
# Create backup directory
sudo mkdir -p /root/f2b-backup-$(date +%Y%m%d)

# Backup fail2ban configuration
sudo tar czf /root/f2b-backup-$(date +%Y%m%d)/fail2ban-config.tar.gz \
    /etc/fail2ban/jail.local \
    /etc/fail2ban/jail.d/ \
    /etc/fail2ban/filter.d/f2b-*.conf \
    /etc/fail2ban/filter.d/nginx-recon-optimized.conf \
    /etc/fail2ban/filter.d/manualblock.conf \
    /etc/fail2ban/filter.d/recidive.conf

# Backup nftables rules
sudo nft list table inet fail2ban-filter > /root/f2b-backup-$(date +%Y%m%d)/nftables-rules.txt

# Export current bans
sudo fail2ban-client status | grep "Jail list" | \
    sed 's/.*://' | tr ',' '\n' | while read jail; do
    sudo fail2ban-client status "$jail" > "/root/f2b-backup-$(date +%Y%m%d)/jail-${jail}.txt"
done
```
### 3.2 Verify Current State (v0.19)
```bash
# Check v0.19 installation
sudo f2b version
# Should show: Version 0.19

# Count current sets and rules
echo "IPv4 sets:"
sudo nft list table inet fail2ban-filter | grep "^\s*set f2b-" | grep -v v6 | wc -l
# Should show: 10

echo "IPv6 sets:"
sudo nft list table inet fail2ban-filter | grep "^\s*set f2b-.*-v6" | wc -l
# Should show: 0

echo "INPUT rules:"
sudo nft list chain inet fail2ban-filter f2b-input | grep -c "drop"
# Should show: 10

# List active jails
sudo fail2ban-client status
```
### 3.3 Document Custom Modifications
```bash
# Custom filters
ls -la /etc/fail2ban/filter.d/f2b-*.conf

# Custom jail configs
cat /etc/fail2ban/jail.local

# Custom nftables rules
sudo nft list table inet fail2ban-filter
```
## 4. Migration Methods (Legacy → v0.20/v0.21)

### 4.1 Method 1: Automatic (Recommended for v0.19 → v0.20)
```bash
# Download v0.20
tar -xzf fail2ban-nftables-v020-production.tar.gz
cd fail2ban-nftables

# Run installer (auto-detects upgrade)
sudo bash INSTALL-ALL-v020.sh
```
**What the installer does:**

1. Detects v0.19 installation
2. Creates backup
3. Adds 10 IPv6 sets alongside existing IPv4 sets
4. Adds 10 IPv6 INPUT rules
5. Adds 3 IPv6 FORWARD rules
6. Updates F2B wrapper to v0.20
7. Preserves all banned IPs
8. Verifies upgrade success

### 4.2 Method 2: Manual (Production Servers)

Step‑by‑step v0.20 upgrade (01-install-nftables-v020.sh, filters, wrapper, diagnostics) remains unchanged – použij existujúci text, ak ešte tieto verzie podporuješ v repozitári.

## 5. Migration to v0.30 (One‑Click)

For installations already on v0.21/v0.22/v0.24, the recommended path now is to move to v0.30 with the universal installer INSTALL-ALL-v030.sh.

### 5.1 Automatic Upgrade (Recommended)
```bash
# Extract v0.30 bundle
tar -xzf f2b-hybrid-nftables-v030.tar.gz
cd v030

# Run universal installer (auto-detects fresh/upgrade/reinstall)
sudo bash INSTALL-ALL-v030.sh
```
**What the installer does:**
1. Detects v0.19 installation
2. Creates backup
3. Adds 10 IPv6 sets alongside existing IPv4 sets
4. Adds 10 IPv6 INPUT rules
5. Adds 3 IPv6 FORWARD rules
6. Updates F2B wrapper to v0.20
7. Preserves all banned IPs
8. Verifies upgrade success

### 4.2 Method 2: Manual (Production Servers)
Step‑by‑step v0.20 upgrade (01-install-nftables-v020.sh, filters, wrapper, diagnostics) remains unchanged – použij existujúci text, ak ešte tieto verzie podporuješ v repozitári.

## 5. Migration to v0.30 (One‑Click)
For installations already on v0.21/v0.22/v0.24, the recommended path now is to move to v0.30 with the universal installer INSTALL-ALL-v030.sh.

### 5.1 Automatic Upgrade (Recommended)
```bash
# Extract v0.30 bundle
tar -xzf f2b-hybrid-nftables-v030.tar.gz
cd v030

# Run universal installer (auto-detects fresh/upgrade/reinstall)
sudo bash INSTALL-ALL-v030.sh
```
Installer will:

1. Detect existing installation type (fresh / upgrade_old / reinstall / upgrade)
2. Run safe pre‑cleanup with full backup (00-pre-cleanup-v030.sh)
3. Rebuild nftables infrastructure (01-install-nftables-v030.sh)
4. Reinstall jails, filters, actions (02-install-jails-v030.sh)
5. Install/upgrade wrapper v0.30 (f2b-wrapper-v030.sh)
6. Install auto‑sync service and docker‑block cron (05/07)
7. Perform final verification (sets, rules, jails, docker‑block)

### 5.2 Safe Test Mode

```bash
sudo bash INSTALL-ALL-v030.sh --cleanup-only
```
• Runs 00-pre-cleanup-v030.sh (backups + legacy cleanup).
• Exits before any nftables/jail rebuild.

## 6. Post‑Migration Verification (v0.30)

### 6.1 Verify Infrastructure

```bash
# Check nftables structure
sudo nft list table inet fail2ban-filter

# Expected:
# - 11 IPv4 sets (f2b-..., recidive, manualblock, etc.)
# - 11 IPv6 sets (f2b-*-v6)
# - 22 INPUT rules (11 IPv4 + 11 IPv6)
# - 6 FORWARD rules
```
### 6.2 Verify Fail2Ban

```bash
# Check jails
sudo fail2ban-client status
# Should show 11 active jails

# Verify bans preserved
sudo f2b audit
```

### 6.3 Verify F2B Wrapper v0.30

```bash
sudo f2b version --human
sudo f2b version --short
sudo f2b status
sudo f2b sync check
sudo f2b docker dashboard
```
### 6.4 Optional Diagnostic
```bash
sudo bash scripts/02-verify-jails-v030.sh
```
## 7. Rollback (If Needed)

Reuse your existing rollback strategy:
• Restore from backup (fail2ban-config.tar.gz, nftables snapshot).
• Or reinstall previous bundle (v0.22/v0.24) if you still ship it.

## 8. FAQ (Updated for v0.30)

Will my IPv4/IPv6 bans be affected?
All IPv4 and IPv6 bans are preserved; v0.30 rebuilds the same nftables structure while keeping existing sets and elements.

Do I need to reconfigure jails?
No. Jail configurations remain unchanged; v0.30 re‑installs the expected 11 jails + filters and verifies banactions.

Will there be downtime?
Minimal. nftables and Fail2Ban are reloaded briefly; existing bans remain active.

---

Migration Guide Version: 2.0
Last Updated: December 2025
Covers: v0.19 → v0.20/v0.21 legacy upgrade and v0.22/v0.24 → v0.30 one‑click upgrade.
