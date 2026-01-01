# Migration Guide: v0.19 → v0.31 → v0.33

Complete guide for upgrading from legacy versions to the **v0.33 production** release with 12 jails and 24 nftables sets.

---

## Quick Migration Paths

### From v0.31 → v0.33 (Recommended)

```bash
tar -xzf f2b-hybrid-nftables-v033.tar.gz
cd v033
sudo bash INSTALL-ALL-v033.sh
```

**What happens:**
- Preserves all existing bans (IPv4 + IPv6)
- Adds 12th jail (nginx-php-errors) with corresponding nftables sets
- Updates wrapper from v0.32 to v0.33
- Creates 2 additional nftables sets and 2 INPUT rules
- Verifies final state: 12 jails, 24 sets, 24 INPUT rules

**Jail counts after upgrade:**
- Before: 11 jails (sshd, exploit, DoS, web, recon, fuzzing, botnet, anomaly, manualblock, recidive, +sshd-slowattack)
- After: 12 jails (+ nginx-php-errors)

**Set counts after upgrade:**
- Before: 22 sets (11 IPv4 + 11 IPv6)
- After: 24 sets (12 IPv4 + 12 IPv6)

---

### From v0.30 → v0.33 (Direct Path)

```bash
tar -xzf f2b-hybrid-nftables-v033.tar.gz
cd v033
sudo bash INSTALL-ALL-v033.sh
```

**Auto-detection:** Installer detects v0.30 installation and upgrades:
1. Preserves nftables structure (11 → 12 sets)
2. Adds nginx-php-errors filter and jail
3. Updates wrapper v0.30 → v0.33
4. Rebuilds docker-block with 8 FORWARD rules (was 6)
5. Verifies full sync

---

### From v0.22 / v0.24 → v0.33 (Via v0.31)

**Recommended:** Upgrade v0.22/v0.24 → v0.30 first, then v0.30 → v0.33 (same installer).

```bash
# Extract v0.33 bundle
tar -xzf f2b-hybrid-nftables-v033.tar.gz
cd v033

# Run installer (auto-detects v0.22/v0.24)
sudo bash INSTALL-ALL-v033.sh
```

---

## Detailed Upgrade: v0.31 → v0.33

### Step-by-Step

#### 1. Backup Current State (Recommended)

```bash
# Backup fail2ban
sudo mkdir -p /root/f2b-backup-$(date +%Y%m%d)
sudo tar czf /root/f2b-backup-$(date +%Y%m%d)/fail2ban-v031.tar.gz \
    /etc/fail2ban/jail.local \
    /etc/fail2ban/filter.d/f2b-*.conf \
    /etc/fail2ban/filter.d/nginx-*.conf

# Backup nftables
sudo nft list table inet fail2ban-filter > /root/f2b-backup-$(date +%Y%m%d)/nftables-v031.txt

# Export current bans
sudo fail2ban-client status | tee /root/f2b-backup-$(date +%Y%m%d)/jails-v031.txt
```

#### 2. Pre-Upgrade Verification

```bash
# Check current version
sudo f2b version --short
# Expected: 0.31 or 0.32 (wrapper)

# Count current infrastructure
echo "IPv4 sets:" && sudo nft list table inet fail2ban-filter | grep "^\\s*set f2b-" | grep -v v6 | wc -l
echo "IPv6 sets:" && sudo nft list table inet fail2ban-filter | grep "^\\s*set f2b-.*-v6" | wc -l
echo "INPUT rules:" && sudo nft list chain inet fail2ban-filter f2b-input | grep -c "drop"

# List active jails
sudo fail2ban-client status
# Expected: 11 jails
```

#### 3. Run v0.33 Installer

```bash
tar -xzf f2b-hybrid-nftables-v033.tar.gz
cd v033

# Test mode (optional)
sudo bash INSTALL-ALL-v033.sh --cleanup-only

# Full upgrade
sudo bash INSTALL-ALL-v033.sh
```

#### 4. Post-Upgrade Verification

```bash
# Check new version
sudo f2b version --short
# Expected: 0.33 (wrapper)

# Verify infrastructure
echo "IPv4 sets:" && sudo nft list table inet fail2ban-filter | grep "^\\s*set f2b-" | grep -v v6 | wc -l
# Expected: 12

echo "IPv6 sets:" && sudo nft list table inet fail2ban-filter | grep "^\\s*set f2b-.*-v6" | wc -l
# Expected: 12

echo "INPUT rules:" && sudo nft list chain inet fail2ban-filter f2b-input | grep -c "drop"
# Expected: 24

# Verify 12 jails
sudo fail2ban-client status | grep "^Jail list:" | wc -w
# Expected: 12 (or 13 with "Jail" prefix)

# Verify PHP jail specifically
sudo fail2ban-client status nginx-php-errors

# Run full diagnostic
sudo bash 02-verify-jails-v033.sh
```

#### 5. Confirm Bans Preserved

```bash
# Check if bans still exist in PHP jail (should be empty initially)
sudo fail2ban-client status nginx-php-errors

# Check other jails remain intact
sudo f2b find <known-banned-IP>
# Should show original jail + new jail if applicable
```

---

## What Changes in v0.33 vs v0.31

### New Components

| Component | v0.31 | v0.33 | Change |
|-----------|-------|-------|--------|
| Jails | 11 | 12 | +nginx-php-errors |
| Filters | 11 | 12 | +nginx-php-errors.conf |
| Local configs | 2 | 3 | +nginx-php-errors.local |
| IPv4 sets | 11 | 12 | +f2b-nginx-php-errors |
| IPv6 sets | 11 | 12 | +f2b-nginx-php-errors-v6 |
| Total sets | 22 | 24 | +2 |
| INPUT rules | 22 | 24 | +2 |
| FORWARD rules | 6 | 8 | +2 (PHP jail) |
| Wrapper | v0.32 | v0.33 | Updated for 12 jails |

### Behavior Changes

- **nginx-php-errors jail** is now active after upgrade
- **Backward compatible:** All existing jails (11) work unchanged
- **Bans preserved:** IPv4/IPv6 bans in existing jails remain active
- **nftables persistence:** All new sets and rules survive reboot

---

## Safe Test Mode (Recommended on Production)

```bash
# Run pre-cleanup only (no modifications to system)
sudo bash INSTALL-ALL-v033.sh --cleanup-only

# Examine backup
ls -la /root/f2b-backup-v033*/
sudo cat /root/f2b-backup-v033*/nftables-backup.txt | head -20

# Then run full install
sudo bash INSTALL-ALL-v033.sh
```

---

## Rollback (If Needed)

### Manual Rollback to v0.31

```bash
# Restore from backup
sudo tar xzf /root/f2b-backup-$(date +%Y%m%d)/fail2ban-v031.tar.gz -C /

# Restore nftables (requires v0.31 scripts)
cd /path/to/v031
sudo bash 01-install-nftables-v031.sh

# Verify
sudo f2b sync check
sudo f2b status
```

---

## Compatibility Matrix

| From | To | Path | Preserve Bans | Downtime |
|------|-----|------|---------------|----------|
| v0.31 | v0.33 | Direct | ✅ Yes | Minimal (~10s) |
| v0.30 | v0.33 | Direct | ✅ Yes | Minimal (~10s) |
| v0.24 | v0.33 | Direct | ✅ Yes | Minimal (~10s) |
| v0.22 | v0.33 | Direct | ✅ Yes | Minimal (~10s) |
| v0.20 | v0.33 | Direct | ✅ Yes | Minimal (~10s) |
| v0.19 | v0.33 | Direct | ✅ Yes | Minimal (~10s) |

---

## FAQ (Updated for v0.33)

### Q: Will my existing bans be lost?

**A:** No. v0.33 preserves all IPv4 and IPv6 bans in all existing jails. New bans go into the 12th jail (nginx-php-errors).

### Q: Do I need to reconfigure jails?

**A:** No. Existing 11 jails keep their configurations. The 12th jail (nginx-php-errors) is installed automatically.

### Q: Will there be downtime?

**A:** Minimal. nftables and Fail2Ban are reloaded briefly (~10 seconds). SSH sessions may be interrupted if on filtered port (rare).

### Q: Can I skip nginx-php-errors?

**A:** The installer will activate it. If you don't need it, you can disable the jail:
```bash
sudo fail2ban-client set nginx-php-errors bantime -1
sudo fail2ban-client set nginx-php-errors findtime 0
```

Or remove it post-install (not recommended).

### Q: What if the installer fails?

**A:** Use `--cleanup-only` mode first to test, then check logs:
```bash
sudo bash INSTALL-ALL-v033.sh --cleanup-only
sudo cat /root/f2b-backup-v033*/INSTALL-LOG.txt
```

### Q: Can I downgrade back to v0.31?

**A:** Yes, restore from backup. See **Rollback** section above.

### Q: What about docker-block?

**A:** Docker-block (v0.4) remains unchanged. The 2 new sets (php IPv4 + IPv6) are added to docker-block automatically during sync.

---

## Infrastructure Summary (v0.33)

### nftables

- **Table:** inet fail2ban-filter
- **IPv4 sets:** 12 (f2b-sshd, f2b-exploit-critical, f2b-dos-high, f2b-web-medium, f2b-nginx-recon-optimized, f2b-fuzzing-payloads, f2b-botnet-signatures, f2b-anomaly-detection, f2b-nginx-php-errors, manualblock, recidive, + 1 placeholder)
- **IPv6 sets:** 12 (same names with `-v6` suffix)
- **INPUT rules:** 24 (11 IPv4 + 11 IPv6 from v0.31, +2 for PHP jail)
- **FORWARD rules:** 8 (4 IPv4 + 4 IPv6, including docker-block rules for PHP)

### Fail2Ban

- **Jails:** 12
  1. sshd
  2. sshd-slowattack
  3. f2b-exploit-critical
  4. f2b-dos-high
  5. f2b-web-medium
  6. nginx-recon-optimized
  7. f2b-fuzzing-payloads
  8. f2b-botnet-signatures
  9. f2b-anomaly-detection
  10. nginx-php-errors ⭐ NEW
  11. manualblock
  12. recidive

- **Default timeouts:**
  - Most jails: 7 days (604800s)
  - Recidive: 30 days (2592000s)

### Wrapper

- **Version:** v0.33
- **Functions:** 50+
- **Commands:** status, audit, find, version, sync (check/enhanced/force/silent), manage (ports/IPs), monitor (watch/trends/top-attackers/show-bans/jail-log), report (json/csv/daily/attack-analysis), docker (dashboard/info/sync validate)

---

**Migration Guide Version:** 3.0
**Last Updated:** December 29, 2025
**Covers:** v0.19 → v0.30 → v0.31 → v0.33 upgrade paths with v0.33 as current stable release.
