# Canary update: v0.34-dev to changeset 227c393

This is a narrow canary workflow for an existing `v0.34-dev` installation. It
installs the updated critical filter, webshell-sweep filter and jail, wrapper,
shared-ban synchronizer, Docker hook and runtime verifier (seven targets).
It can update an existing host that already applied changeset 227c393; the
historical script filename and backup label do not identify the package HEAD.
Use a package built from an explicitly recorded Git commit. It is not the
v0.33 migration workflow and does not install a release.

It never overwrites `jail.local`, filter `*.local` overrides, the Fail2Ban
database, nftables configuration, or local RCE/high-risk settings. It never
restarts Docker or nftables and never loads or globally flushes a ruleset.

## Read-only preflight

```bash
cd f2b-v034-canary-227c393
sudo python3 scripts/upgrade-v034dev-canary-227c393.py
```

The preflight validates the current v0.34-dev host and a temporary merged
Fail2Ban configuration, tests attack and benign fixtures, and captures active
bans and the nftables state in memory. It does not alter the installed system;
it creates and removes a temporary candidate directory. Custom Fail2Ban database
paths are refused because this workflow only backs up `/var/lib/fail2ban`.

## Apply

Keep two SSH sessions open and run only in the approved canary window:

```bash
sudo python3 scripts/upgrade-v034dev-canary-227c393.py --apply
```

Before installation, the script creates a timestamped backup of `/etc/fail2ban`,
`/var/lib/fail2ban` and the managed wrapper/helpers below
`/var/backups/f2b-v034-canary/`. SQLite uses an online backup, not a raw copy of
an active WAL database. It atomically replaces each of the seven managed files,
reloads Fail2Ban, restores any missing active bans, checks the hello-world IOC,
the new jail policy, effective IPv4/IPv6 nft action definitions, and the
Docker-block sync. Fail2Ban starts nft actions on demand, so a newly loaded jail
with zero bans may legitimately have no runtime set yet. In that state the
updater resolves the `actionstart` and `actionban` templates and family-specific
properties from the effective configuration, then compares the ban template
with the loaded runtime action. One action may handle both address families;
set names are not assumed. A runtime set and its chain reference are required
for each family with an active ban. No synthetic ban is created.
The Docker hook must have the expected executable ban command. After wrapper
synchronization, every live ban from a jail using that hook is checked in the
corresponding Docker set; missing real bans are reconciled through the hook.
Any failed step automatically restores the backup.

## Manual rollback

Use the exact path printed by the apply command:

```bash
sudo python3 scripts/upgrade-v034dev-canary-227c393.py \
  --rollback /var/backups/f2b-v034-canary/v034dev-to-227c393-YYYYMMDD-HHMMSS
```

Rollback stops Fail2Ban before restoring its configuration/database and previous
wrapper/helper state, removes stale SQLite WAL/SHM files, validates the restored
configuration, starts Fail2Ban and restores captured bans. It also snapshots
new bans before stopping when the daemon is responsive. Bans from a newly
introduced jail are transferred to an existing `manualblock`, otherwise
`recidive`; if neither exists, there is no fallback for that jail. Docker and
nftables are never restarted. This is a brief Fail2Ban interruption, not an
uninterrupted-firewall guarantee.

## Deployment limits

The synchronizer owns shared Docker/recidive membership, not native per-jail
sets. Unban is deferred until the next scheduled/manual sync to avoid removing
an address still banned by another jail. Permanent shared bans use renewable
30-day leases: the sync schedule must remain operational. Legacy interval sets
are split atomically within the owned set; ranges larger than 65,536 addresses
are rejected without changing that set.

Green namespace CI does not prove a complete VM installation, reboot recovery,
real Docker NAT traffic, or remote IPv6 client connectivity. Do not call this
workflow a final v0.34 release or a completed production validation.
