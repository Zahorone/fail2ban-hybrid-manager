# Complete v0.33 -> v0.34-dev upgrade package

This is a controlled canary candidate, NOT a final release/RC or a clean-install
installer. Supported scope: existing Debian/Ubuntu v0.33 project installations
with systemd, an active `cron` service, both managed nft tables and distribution
Fail2Ban (tested in CI with the 1.0.2-style client). Existing v0.34-dev can also
be checked/reapplied. A custom database path is refused, not silently ignored.

Architecture and module boundaries: see `MODULE-ARCHITECTURE.md` in this package.
Before replacing locally repaired filters, read `ACCESS-FILTER-SAFETY.md`.
The earlier a684ca7 archive contains historical broad access rules and must not
be applied over those repairs. This candidate bounds the four access filters,
checks their effective/live behavior. Unknown wrapper/action/helper contents
still stop preflight. Server-specific compatibility review/adaptation is private,
outside this generic package and repository.
v0.34 is the planned common baseline for both servers, not evidence that both
have already been upgraded. The unified install/update/module-management tool
is reserved for local-only v0.40 development, not this upgrade's scope. A roadmap
does not authorize a production apply; the maintenance-window approval remains
separate from preparation and read-only preflight.
The manifest's `filter_override_policy` specifies preserve-and-validate-effective
coexistence for scan-review `.local` repairs. Their marker/SHA-256 is reported,
but neither the marker nor a guessed historical hash authorizes replacement.
Both `.local` files remain byte-identical through apply/reapply; conflicts in
effective critical/sweep behavior stop preflight with the relevant path and
request. Typed live-daemon expressions are checked again after reload, inside
the automatic rollback transaction. The original `.local` files are part of
the existing complete Fail2Ban backup and restored by rollback.

## Scan review, 2026-10-11

The sweep excludes exact WordPress core entry points (`index.php`, `wp-login.php`,
`wp-admin/admin-ajax.php`, `wp-cron.php`) in the root and nested installations.
Its final-404 requirement and three hits / 30 seconds / 365 days policy are
unchanged. Existing bans are not automatically withdrawn by this filter change.

Critical detection adds exact credential filenames (including AWS backup
suffixes) and traversal only in `path`, `file`, `filename` or `download`
parameters with parent-directory segments targeting `.env` variants or
`proc/self/environ` / `cmdline`. Percent-encoded dots and separators are covered.
Exact hellopress and hello-world IOCs count at 301, 404 and 444; critical remains
one hit / 365 days, independent of HTTP status. Ordinary WordPress core URLs,
generic JSON/GraphQL and user agents are not new critical evidence. A credential
filename probe is not proof of disclosure; a Solr 444 or a
`trust_forwarded_proto` warning does not establish a firewall bypass or attack.

Application note: a reported Easy!Appointments `/config.php` response of HTTP 200
with zero length does not by itself establish source/credential disclosure.
Any Apache access restriction for that application must be reviewed and deployed
separately; this manager upgrade does not install or execute such protection.

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

Unknown locally edited managed targets still require a separate private content
review. An operator may explicitly pass `--local-review /PRIVATE/REVIEW.json` to
both preflight and apply. The root-only file is bound to this package's exact
commit and exact prior file bytes; it is not generated from unknown files by
the upgrader, embedded in the manifest, or bundled for other installations.
Preserved `.local` files do not need adoption, and all effective/runtime safety
checks still apply. See `ACCESS-FILTER-SAFETY.md` for its generic schema. Keep
that private file alongside deployment records, never in Git/CI or the package.

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
During the STANDARD UPGRADE RELOAD path, missing bans are restored; records already present retain their DB timings.
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

Rollback verifies backup checksums and refuses differing active native DB tickets before stop,
stops Fail2Ban, removes only newly introduced managed files, restores original
config/DB/helpers/persistence/systemd files, removes stale SQLite WAL/SHM files,
daemon-reloads systemd, tests configuration, atomically restores ONLY the two
owned live tables from the backup, starts Fail2Ban and waits for full native DB restoration. No
full-ruleset backup is ever loaded. Original IPv6 elements and blocked ports are
included in this scoped firewall recovery. Active bans from a removed new jail
require separately reviewed DB migration; no implicit fallback/re-add is performed.
If the daemon cannot respond, only the saved snapshot/DB is recoverable; bans
acquired later may be unavailable. Fail2Ban is briefly stopped. This is not an
uninterrupted-firewall guarantee. Foreign firewall changes cause a visible
failure, never an automatic rewrite of the foreign ruleset.

## Validation limits / release gates

Historical pristine v0.33 (`a88bacb`) has an unescaped-percent PHP filter that
fails Fail2Ban 1.0.2 configuration parsing. That baseline is tested for safe
refusal and validity of the merged candidate, NOT a successful runtime upgrade.
Repair the current configuration explicitly before upgrading: a non-restartable
original cannot be a safe rollback target. The full runtime transaction test
uses v0.33 with the repository's recognized repairs (`0.33-ipv6.1`).

Unit and namespace integration tests are not a full VM boot/reboot or a real
Docker NAT/client-traffic test. No final release is authorized by green CI.
Existing v0.34-dev live canary is separate evidence; IPv6 was not active
there. Keep its 24-48 hour observation window. No other production host is in
scope for this package preparation. A representative disposable v0.33 VM upgrade/rollback,
reboot persistence and external IPv6 test remain mandatory before broad rollout.
# Boot prerequisite (fail closed)

Current preflight also requires persistently enabled, active nftables/Fail2Ban/cron,
no pending daemon-reload, both Requires= and After=nftables.service for consumers,
and all four timed family infra sets. It refuses without enabling/starting/loading
any firewall. Custom boot arrangements require explicit review; do not blindly
enable nftables. New backups record/restore exact enabled states without --now or
firewall restart. Legacy backups without that metadata are explicitly identified.
Namespace systemd simulations are not reboot acceptance. The immutable 1964009
artifact has not been modified to add this gate.
# Bounded native rollback readiness and read-only audit

The old immediate post-start ping can fail before the socket exists. That skips
the old missing-ban restoration/assertion and final foreign-firewall check, even
if systemd later becomes active and the daemon restores its DB tickets. File/DB
restoration, sidecar cleanup, daemon-reload, owned-table restoration and the start
request precede that ping. There was no rollback-complete marker: a lab boot marker
records boot preparation, NOT rollback success. A later pong/reboot is evidence
of runtime recovery, not proof that the failed CLI completed all verification.

New explicit and automatic rollback share a 60-second readiness deadline, with
bounded child commands. They wait for socket/pong, the EXACT original jail set,
and native DB restoration of still-valid tickets with their original absolute
expiry (one-second display tolerance). Natural expiry during waiting is allowed;
missing/permanent/retimed tickets are never re-added to make the test pass.
Timeout propagates as failure, including automatic rollback double-failure
reporting. Foreign rules are checked after full readiness; Docker/nftables are
never restarted or globally loaded. This fixes readiness, not boot/packet acceptance.

This is deliberately conservative, not a new ticket-migration mechanism. A
read-only schema-4 native DB check compares current active tickets to the rollback
backup BEFORE stopping Fail2Ban. New/revoked/retimed/new-jail tickets cause refusal
without file/DB/firewall restore. The old re-add/new-jail fallback could reset or
shorten TTL and is NOT retained. A second check after stop catches a shutdown race;
on mismatch the service is stopped but the live DB/files are not overwritten:
retain state/backup for reviewed recovery, never blindly retry. Unknown/missing DB
schemas likewise require review. Original backup/history remains intact; no SQL
ticket insert/migration or control-plane banip write is performed by rollback.

For the historical early-ping failure, use the NEW verified product archive,
not the immutable 1964009 script, and the exact old backup path locally:

```sh
sudo /usr/bin/python3 "$F2B_PRODUCT_ROOT/scripts/upgrade-v033-v034.py" --audit-rollback /EXACT/PRIVATE/BACKUP
```

Audit verifies backup checksums, original config/managed bytes, absence of introduced
targets, exact jails/native expiry, infrastructure/boot prerequisites, foreign rules
and recorded enabled states. It does not stop/start/reload, restore files, create a
transaction lock or re-add bans. Legacy backups without enabled-state metadata are
explicitly NOT verified for those original states; inspect locally. Timeout or any
mismatch is not permission to repair/re-run. Keep all logs, backup paths, DB/config
and audit detail private. Two asynchronous namespace lifecycle tests do not replace
real VM tests. Ubuntu 26 ARM64 runtime/reboot recovery observed with the old tool
still has failed rollback CLI acceptance; Ubuntu 24 amd64 and post-upgrade/rollback
packet acceptance remain open. No immutable 1964009 archive/release is changed.
