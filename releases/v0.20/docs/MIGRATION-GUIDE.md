# Migration Guide: v0.19 → v0.20

Complete guide for upgrading from v0.19 (IPv4 only) to v0.20 (IPv4 + IPv6 dual-stack).

## Overview

**v0.20** adds full IPv6 support while maintaining complete backward compatibility with v0.19.

### What Changes?

| Component | v0.19 | v0.20 | Change |
|-----------|-------|-------|--------|
| IPv4 Sets | 10 | 10 | No change ✅ |
| IPv6 Sets | 0 | 10 | **+10 new** |
| INPUT Rules | 10 | 20 | **+10 IPv6 rules** |
| FORWARD Rules | 3 | 6 | **+3 IPv6 rules** |
| Fail2Ban Jails | 10 | 10 | No change ✅ |
| F2B Wrapper | v0.19 (43 func) | v0.20 (43 func) | Version bump only |

### What's Preserved?

✅ All banned IPv4 addresses  
✅ All jail configurations  
✅ All custom filter modifications  
✅ All Docker port blocks  
✅ All wrapper functionality  

---

## Pre-Migration Checklist

### 1. Backup Current Configuration

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

### 2. Verify Current State

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

### 3. Document Custom Modifications

If you've customized any files, document changes:
```bash
# Check for custom filters
ls -la /etc/fail2ban/filter.d/f2b-*.conf

# Check for custom jail configs
cat /etc/fail2ban/jail.local

# Check for custom nftables rules
sudo nft list table inet fail2ban-filter
```

---

## Migration Methods

### Method 1: Automatic (Recommended)

The universal installer auto-detects v0.19 and performs intelligent upgrade.

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

**Expected output:**
```
UPGRADE from v0.19 (IPv4 only) to v0.20 (IPv4+IPv6)

Current state:
  • IPv4 sets: 10
  • IPv6 sets: 0 (missing)

Will upgrade to:
  • Add IPv6 support (10 sets + 10 rules)
  • Upgrade INPUT rules: 10 → 20
  • Upgrade FORWARD rules: 3 → 6
  • Update F2B wrapper to v0.20
  • Add new filters if missing
  • Preserve all banned IPs
```

### Method 2: Manual (Production Servers)

For production environments requiring granular control:

#### Step 1: Update nftables Structure

```bash
cd fail2ban-nftables
sudo bash scripts/01-install-nftables-v020.sh
```

This adds IPv6 sets and rules without touching existing IPv4 configuration.

#### Step 2: Verify nftables

```bash
# Count IPv4 sets (should still be 10)
sudo nft list table inet fail2ban-filter | grep "^\s*set f2b-" | grep -v v6 | wc -l

# Count IPv6 sets (should now be 10)
sudo nft list table inet fail2ban-filter | grep "^\s*set f2b-.*-v6" | wc -l

# Count INPUT rules (should be 20)
sudo nft list chain inet fail2ban-filter f2b-input | grep -c "drop"

# Count FORWARD rules (should be 6)
sudo nft list chain inet fail2ban-filter f2b-forward | grep -c "drop"
```

#### Step 3: Update Filters (if needed)

```bash
# Copy new/updated filters
sudo cp filters/*.conf /etc/fail2ban/filter.d/

# Verify syntax
sudo fail2ban-client reload
```

#### Step 4: Update F2B Wrapper

```bash
sudo cp scripts/f2b-wrapper-v020.sh /usr/local/bin/f2b
sudo chmod +x /usr/local/bin/f2b

# Verify
sudo f2b version
# Should show: Version 0.20
```

#### Step 5: Run Diagnostic Verification

```bash
sudo bash scripts/02-verify-jails-v020.sh
```

---

## Post-Migration Verification

### 1. Verify Infrastructure

```bash
# Check nftables table
sudo nft list table inet fail2ban-filter

# Expected structure:
# - 10 IPv4 sets (f2b-sshd, f2b-exploit-critical, etc.)
# - 10 IPv6 sets (f2b-sshd-v6, f2b-exploit-critical-v6, etc.)
# - 20 INPUT rules (10 IPv4 + 10 IPv6)
# - 6 FORWARD rules (3 IPv4 + 3 IPv6)
```

### 2. Verify Fail2Ban

```bash
# Check jail status
sudo fail2ban-client status
# Should show 10 active jails

# Verify banned IPs preserved
sudo f2b audit
# All previous bans should still be present
```

### 3. Verify F2B Wrapper

```bash
# Check version
sudo f2b version
# Should show: F2B Wrapper v0.20

# Test core functions
sudo f2b status
sudo f2b audit
sudo f2b sync check

# All 43 functions should work
```

### 4. Quick Diagnostic

```bash
sudo bash scripts/02-verify-jails-v020.sh
```

This diagnostic script provides complete system validation.

---

## Rollback (If Needed)

If migration fails or you need to rollback:

### Option 1: Restore from Backup

```bash
BACKUP_DIR="/root/f2b-backup-YYYYMMDD"  # Your backup directory

# Stop services
sudo systemctl stop fail2ban
sudo systemctl stop nftables

# Restore fail2ban configuration
sudo tar xzf $BACKUP_DIR/fail2ban-config.tar.gz -C /

# Restore nftables
sudo nft -f $BACKUP_DIR/nftables-rules.txt

# Restart services
sudo systemctl start nftables
sudo systemctl start fail2ban
```

### Option 2: Reinstall v0.19

```bash
# Download v0.19 package
tar -xzf fail2ban-nftables-v019-production.tar.gz
cd fail2ban-nftables

# Run v0.19 installer
sudo bash INSTALL-ALL-v019.sh
```

---

## Troubleshooting

### Issue: IPv6 sets not created

**Symptoms:**
```bash
sudo nft list table inet fail2ban-filter | grep "v6" | wc -l
# Returns: 0 (expected: 10)
```

**Solution:**
```bash
# Re-run nftables installer
sudo bash scripts/01-install-nftables-v020.sh

# Verify
sudo nft list table inet fail2ban-filter | grep "set.*-v6"
```

### Issue: Banned IPs missing after upgrade

**Symptoms:**
```bash
sudo f2b audit
# Shows 0 bans (but you had bans before)
```

**Solution:**
```bash
# Force re-sync from fail2ban to nftables
sudo f2b sync force

# Or restore from backup
sudo fail2ban-client reload
```

### Issue: Wrapper shows old version

**Symptoms:**
```bash
sudo f2b version
# Still shows: 0.19
```

**Solution:**
```bash
# Manually update wrapper
sudo cp scripts/f2b-wrapper-v020.sh /usr/local/bin/f2b
sudo chmod +x /usr/local/bin/f2b

# Verify
sudo f2b version
```

### Issue: Jails not working after upgrade

**Symptoms:**
```bash
sudo fail2ban-client status
# Shows fewer than 10 jails
```

**Solution:**
```bash
# Check fail2ban logs
sudo tail -50 /var/log/fail2ban.log

# Common issues:
# - Missing filter file → copy from filters/ directory
# - Wrong logpath → edit jail.local
# - Syntax error → validate with fail2ban-regex

# Re-copy filters
sudo cp filters/*.conf /etc/fail2ban/filter.d/
sudo systemctl restart fail2ban

# Verify with diagnostic tool
sudo bash scripts/02-verify-jails-v020.sh
```

---

## FAQ

### Q: Will my IPv4 bans be affected?
**A:** No. All IPv4 bans are preserved during upgrade. IPv6 support is added alongside IPv4, not replacing it.

### Q: Do I need to reconfigure jails?
**A:** No. Jail configurations remain unchanged. IPv6 blocking is handled automatically by nftables rules.

### Q: Will there be downtime?
**A:** Minimal. The upgrade adds IPv6 infrastructure without stopping IPv4 protection. Fail2Ban restart takes 2-3 seconds.

### Q: Can I upgrade during an active attack?
**A:** Yes. Existing bans remain active during upgrade. However, for production systems, schedule during maintenance window if possible.

### Q: What if I don't need IPv6?
**A:** The IPv6 infrastructure is lightweight and doesn't impact performance. You can safely upgrade even if you don't use IPv6. The IPv6 rules simply won't match any traffic.

### Q: Can I revert to v0.19?
**A:** Yes. See the Rollback section above.

---

## Best Practices

### For Development/Test Servers
- Use automatic migration method
- Test all functionality after upgrade
- Monitor logs for 24-48 hours

### For Production Servers
- Schedule during maintenance window
- Create complete backup first
- Use manual migration method for control
- Test on staging server first if available
- Have rollback plan ready
- Monitor closely after upgrade

### Post-Upgrade
- Run `sudo f2b audit` regularly
- Check `sudo f2b monitor trends` for attack patterns
- Verify `sudo f2b sync check` daily
- Review `/var/log/fail2ban.log` for anomalies

---

## Support

If you encounter issues during migration:

1. **Run diagnostic tool:**
   ```bash
   sudo bash scripts/02-verify-jails-v020.sh
   ```

2. **Check logs:**
   ```bash
   sudo tail -100 /var/log/fail2ban.log
   sudo journalctl -u nftables -n 50
   ```

3. **GitHub Issues:**
   Report detailed information including:
   - Migration method used (automatic/manual)
   - Error messages
   - Output of diagnostic tool
   - System info (Ubuntu version, kernel, etc.)

---

**Migration Guide Version:** 1.0  
**Last Updated:** December 2025  
**Covers:** v0.19 → v0.20 migration
