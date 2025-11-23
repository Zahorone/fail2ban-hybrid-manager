# Migration Guide: v0.7.3 → v0.8

## Automatic Migration

The v0.8 setup script automatically handles migration:

1. Detects v0.7.3 configuration
2. Creates backup
3. Maps old jails to new hierarchy
4. Updates nftables sets
5. Validates new setup
6. Offers rollback if needed

## Step-by-Step

### 1. Prepare

```bash
sudo bash fail2ban_v0.8-setup-final.sh --dry-run
```

### 2. Migrate

```bash
sudo bash fail2ban_v0.8-setup-final.sh
```

### 3. Verify

```bash
sudo fail2ban-client status
sudo nft list set inet fail2ban-filter f2b-exploit
```

### 4. Rollback (if needed)

```bash
sudo bash fail2ban_v0.8-setup-final.sh --rollback
```

## What Changes

✅ Preserved:
- sshd jail
- recidive jail
- manualblock jail
- UFW integration
- Docker protection

🔄 Changed:
- 11 web jails → 3 web jails
- 8 nftables sets → 3 sets
- Setup script improved

## Backup Location

Backups are stored in: `/var/backups/fail2ban-v0.8/`

Latest backup link: `/var/backups/fail2ban-v0.8/latest`

