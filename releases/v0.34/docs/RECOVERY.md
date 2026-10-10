# v0.33 upgrade and recovery workflow

This workflow is still a development candidate. Test it on a disposable clone
of a v0.33 server before any canary deployment.

## 1. Read-only preflight

```bash
cd releases/v0.34
sudo python3 scripts/upgrade-v033-v034.py
```

Preflight validates the package, the effective Fail2Ban configuration, the
upstream family-aware multiport action, required IPv4/IPv6 nftables sets and
rules, and captures every active jail ban. It makes no changes.

## 2. Apply in an approved maintenance window

Keep two independent SSH sessions open, then run:

```bash
sudo python3 scripts/upgrade-v033-v034.py --apply
```

Before changing files, the tool creates a timestamped backup under
`/var/backups/f2b-v034/`. It includes:

- `/etc/fail2ban`, `/var/lib/fail2ban` and Fail2Ban's effective dump;
- nftables configuration files plus JSON and text runtime snapshots;
- installed wrapper/helper files and applicable systemd drop-in directories;
- active bans, service state and root crontab output.

The upgrade preserves `jail.local`, all action `*.local` files, nftables schema
files, site reporting configuration and systemd overrides. It never reloads
nftables or Docker and never uses `flush ruleset`.

After an atomic file install it validates and reloads Fail2Ban, restores any
previously active address missing after reload, checks every original ban, and
verifies that nftables tables outside `fail2ban-filter` and `docker-block` did
not change. Restored missing bans may receive the jail's full current bantime;
they are never shortened.

Any failed verification triggers automatic rollback.

The standard upgrade now shares the runtime verifier used by the successful
development canary. It parses Fail2Ban 1.0.2 comma-separated action names,
resolves IPv4/IPv6 properties on a single nftables action, and permits lazy
runtime sets only for families without active bans. It checks the exact
Docker hook command, reconciles actual live bans and verifies Docker set
membership. These checks remain inside the backup/rollback transaction.

For a separate read-only check after deployment:

```bash
sudo python3 scripts/upgrade-v034dev-canary-227c393.py --verify-only
```

This mode does not reload services, run synchronization, restore bans or
repair Docker membership. The shell jail verifier uses this same mode rather
than treating a fixed total of 26 runtime sets as a requirement.

See `CANARY-VALIDATION.md` for the precise scope of live and fixture evidence.

## 3. Manual rollback

Use the exact backup path printed by the apply command:

```bash
sudo python3 scripts/upgrade-v033-v034.py \
  --rollback /var/backups/f2b-v034/v033-to-v034-YYYYMMDD-HHMMSS
```

Rollback restores the archived files and ownership, validates and reloads
Fail2Ban, then restores and verifies the captured bans. It does not apply the
saved full nftables ruleset because doing so could overwrite live Docker or UFW
state; runtime nft snapshots are retained for diagnosis. If Fail2Ban cannot
reload during rollback, the tool may restart Fail2Ban itself. It never restarts
Docker or nftables.
