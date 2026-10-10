# Complete v0.33 -> v0.34-dev upgrade package

This is a controlled canary candidate, NOT a final release/RC or a clean-install
installer. Supported scope: existing Debian/Ubuntu v0.33 project installations
with systemd, an active `cron` service, both managed nft tables and distribution
Fail2Ban (tested in CI with the 1.0.2-style client). Existing v0.34-dev can also
be checked/reapplied. A custom database path is refused, not silently ignored.

## Stage and verify

Extract into a new unprivileged directory; do not extract over the installed
system. Check the archive SHA-256 against the separately supplied build result,
then run `sha256sum -c SHA256SUMS` inside the extracted package. The versioned
`UPGRADE-MANIFEST.json` records the Git commit, exact payload checksums, static
target map, generated targets and recognized previous-file checksums. Integrity
checks are not a digital signature: trust the package's source independently.

```sh
sudo /usr/bin/python3 scripts/upgrade-v033-v034.py
```

This performs read-only checks of the installed system and uses temporary files
for the merged configuration/persistence candidates. It does not install files,
reload services, mutate the firewall or acquire an on-disk upgrade lock. It checks
effective IPv4/IPv6 actions, new jail settings/IOC, Docker hook, binary-safe mail,
DB location/access, active cron, legacy persistence includes and root crontab.
Every preserved `.local` path is listed; effective conflicts identify jail/key
or action. Unknown modified managed targets report the exact path and SHA-256.
Do not bypass a conflict: review and merge the site's configuration explicitly.
Recognized repository v0.33/v0.34 fixes are accepted by checksum. Arbitrary local
changes are intentionally NOT assumed compatible.

`jail.local`, whitelist values and unrelated `.local` overrides are never
deployed. The four managed jail.d snippets are installed only if absent or
recognized. They intentionally add the new webshell jail/RCE policy/mail fixes;
custom changes at those same paths stop preflight instead of being overwritten.
No Apache, Easy!Appointments, WordPress `.htaccess` or server-root hardening is
included or executed. App-specific hardening requires a separate explicit task.

## Apply in an approved maintenance window

Keep two SSH sessions plus independent console access available. Freeze other
configuration edits, keep the package and record the printed backup path.

```sh
sudo /usr/bin/python3 scripts/upgrade-v033-v034.py --apply
```

The tool repeats preflight, backs up every managed target/root with ownership,
ACLs/xattrs, online-consistent SQLite files, active jail-ban addresses and raw
timed ban records, effective config, firewall and crontab diagnostics/checksums.
It replaces individual files atomically (the complete deployment is NOT one
atomic operation). Config/DB backup files contain sensitive local data: backups
are root-only and must not be shared. No production data is in this package.

The only generated site files are `/etc/nftables.conf` (remove the old top-level
global flush command while preserving other statements) and live snapshots of
`inet fail2ban-filter` / `inet docker-block` in `/etc/nftables.d`. Foreign tables
and Docker NAT are neither copied into persistence nor loaded/replaced. Nftables
systemd stop flushing is disabled and global reload is refused; no Docker or
nftables restart/reload is executed. Fail2Ban alone is config-tested/reloaded.

`/etc/cron.d/f2b-v034-sync` reconciles both families and saves only managed tables
every minute. Root's existing crontab is unchanged; known old wrapper sync jobs
remain compatible but can duplicate work. The upgrade lock excludes new cron
during apply/rollback; the runtime lock serializes helpers/hooks. Existing custom
automation remains the operator's responsibility. A shell command hidden in an
external script is not exhaustively audited by this tool.

Runtime checks include real active members and zero-ban lazy action lifecycle.
Missing bans are restored; records already present retain their DB timings.
When a missing ban must be re-added through Fail2Ban's public API, its jail's
current bantime is reapplied (expiry may be extended). Original timed records
are retained as evidence; exact per-IP remaining-time restoration is NOT claimed.
Permanent shared bans use renewable 30-day leases. Unban waits for union sync,
so scheduling must remain healthy. Huge legacy intervals (>65,536 addresses)
are rejected rather than silently erased. Cumulative huge sets may be expensive.

## Rollback

Any post-backup apply failure attempts automatic rollback. A rollback failure
prints `AUTOMATIC ROLLBACK ALSO FAILED` and the exact backup path; do not assume
recovery succeeded. Inspect the error and use console access as needed.

```sh
sudo /usr/bin/python3 scripts/upgrade-v033-v034.py --rollback /EXACT/PRINTED/BACKUP
```

Rollback verifies backup checksums, snapshots new bans when the daemon responds,
stops Fail2Ban, removes only newly introduced managed files, restores original
config/DB/helpers/persistence/systemd files, removes stale SQLite WAL/SHM files,
daemon-reloads systemd, tests configuration, atomically restores ONLY the two
owned live tables from the backup, starts Fail2Ban and restores missing bans. No
full-ruleset backup is ever loaded. Original IPv6 elements and blocked ports are
included in this scoped firewall recovery. Bans from
a removed new jail move to an original `manualblock`, otherwise `recidive`.
If the daemon cannot respond, only the saved snapshot/DB is recoverable; bans
acquired later may be unavailable. Fail2Ban is briefly stopped. This is not an
uninterrupted-firewall guarantee. Foreign firewall changes cause a visible
failure, never an automatic rewrite of the foreign ruleset.

## Validation limits / release gates

Unit and namespace integration tests are not a full VM boot/reboot or a real
Docker NAT/client-traffic test. No final release is authorized by green CI.
Existing v0.34-dev live canary is separate evidence; IPv6 was not active
there. Keep its 24-48 hour observation window. No other production host is in
scope for this package preparation. A representative disposable v0.33 VM upgrade/rollback,
reboot persistence and external IPv6 test remain mandatory before broad rollout.
