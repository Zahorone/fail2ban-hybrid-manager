# Canary update: v0.34-dev to changeset 227c393

This is a narrow canary workflow for an existing `v0.34-dev` installation. It
installs only the updated critical filter, the webshell-sweep filter and jail,
and the wrapper that knows about that jail. It does not install a release.

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
bans and the nftables state in memory. It writes nothing.

## Apply

Keep two SSH sessions open and run only in the approved canary window:

```bash
sudo python3 scripts/upgrade-v034dev-canary-227c393.py --apply
```

Before installation, the script creates a complete timestamped backup below
`/var/backups/f2b-v034-canary/`. It atomically installs the four managed files,
reloads Fail2Ban, restores any missing active bans, checks the hello-world IOC,
the new jail policy, IPv4/IPv6 nft sets and rules, and the Docker-block sync.
Any failed step automatically restores the backup.

## Manual rollback

Use the exact path printed by the apply command:

```bash
sudo python3 scripts/upgrade-v034dev-canary-227c393.py \
  --rollback /var/backups/f2b-v034-canary/v034dev-to-227c393-YYYYMMDD-HHMMSS
```

Rollback restores the complete Fail2Ban configuration and database plus the
previous wrapper/helper state, reloads Fail2Ban, and restores every captured
ban. Only if Fail2Ban itself cannot reload may it restart Fail2Ban; Docker and
nftables are never restarted.
