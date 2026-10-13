# Block/unblock persistence hotfix — separate from upgrades/CrowdSec

## Confirmed cause

Historical v0.33 and v0.34 wrapper functions used a `sed` range from
`set docker-blocked-ports {` to the first `}`. For an inline `elements = { ... }`,
that range ends at the **inner** brace. Replacing it leaves the original set close
behind, prematurely closes `table inet docker-block`, and leaves later sets and
the chain outside the table. Empty and multiline layouts can fail too. Runtime
may continue working, but next boot can reject the file and prevent dependent
Fail2Ban startup. Both block and unblock were affected. This is a manager product
bug, not evidence of a CrowdSec problem or an Ubuntu package upgrade failure.

**Stop using old block/unblock commands. Do not reboot a suspected-corrupt host
just to test this.** Preserve console access. This document contains no operator
host identifiers, addresses, exports, private backup names or live configuration.

## Canonical operation after the hotfix

The wrapper delegates only these two operations to the installed owned-table
helper. The helper serializes against the existing upgrade/runtime-sync locks,
backs up root-privately, checks the existing configuration before runtime changes,
changes only `docker-blocked-ports` in one atomic nft batch, snapshots the two
owned tables, validates staged persistence and commits files atomically. Existing
IP bans and foreign rules are neither flushed nor restored from a stale snapshot.

The scoped port-set replacement supports empty sets and auto-merged intervals.
It is **not** a global flush and does not flush any IP ban set. Full syntax/load
validation runs only in a new private mount/network namespace, including a
private compatibility `docker0` for old `iif` snapshots. Runtime and cold-load
port memberships must agree. Success is printed only after all checks pass.
Failure propagates nonzero and verifies rollback of original ports/files; a
failed rollback explicitly requires private operator review.

Cron-owned-table saving also stages and validates all snapshots before replacing
any file, restoring replaced files on failure. It keeps its existing runtime lock
without recursively taking the outer upgrade lock already held by cron.

## Read-only preflight on an existing host

Use the exact reviewed Git commit supplied with successful CI, from its repository
root. Do not reinstall the manager or apply a full release upgrade for this fix.
The scoped installer needs repository history to recognize published old function
bodies; the installed runtime helper itself does not need Git.

```sh
cd releases/v0.34
sudo python3 scripts/install-port-hotfix.py
```

Preflight creates only private temporary candidates/advisory locks; it does not
change configuration, services, packages, runtime rules or database. It validates
the installed wrapper's two port functions against known v0.33/v0.34 definitions
(or the already fixed definitions), and the old/new canonical snapshot helper.
It preserves **every other wrapper byte**, including local fixes elsewhere.
Unknown modifications to those functions/helper are refused for manual review.

If persistence is already valid, it is not changed. If invalid, the tool accepts
only the known extra closing brace(s) between the port set and
`set docker-banned-ipv4`; comments, strings and nested element braces are tokenized.
The proposed correction must pass the full isolated configuration check. Unknown
damage, unsafe paths/permissions, missing includes, missing tools or namespace
restrictions are refused; do not weaken those guards or install packages blindly.

## Explicit apply, only after PASS and operator approval

```sh
sudo python3 scripts/install-port-hotfix.py --apply
```

This backs up original code/file targets with metadata and checksums under a new
root-private directory, replaces only the two recognized wrapper functions and
snapshot helper, and repairs the known brace corruption if present. It does not
start/restart nftables, Fail2Ban or Docker; it does not load host firewall rules,
change CrowdSec configuration, install packages, edit whitelist/jail policy or
restore a live database. Already-installed hotfix preflight is repeatable.

If apply fails, original target bytes are restored. **If the original file was
already corrupt, restoring it is not a healthy-service rollback.** The result
explicitly says prior corruption may remain. Keep the backup and console. Startup
recovery of an already rebooted host is a separate operator-controlled action;
do not blindly `restart nftables` over live tables or assume this tool restarted
dependent Fail2Ban. Verify service/dependency state privately before deciding.

## File-only known-corruption repair (no code installation)

For a host whose live table is absent after failed boot, the same known syntax
repair can be preflighted directly from reviewed source:

```sh
sudo python3 scripts/f2b-save-owned-tables.py --repair-port-file
# Only after PASS:
sudo python3 scripts/f2b-save-owned-tables.py --repair-port-file --apply
```

This changes only the recognized extra brace(s), preserving other file bytes,
including ports, ban elements and operator rules. It works without live managed
tables and **does not load them into host runtime**. It does not repair the old
wrapper; do not use old block/unblock again before the scoped code hotfix.

For a healthy host after hotfix, `f2b manage block-port PORT` and `unblock-port`
use the new transaction. Test only an explicitly approved disposable port/client
with a management path that will not be blocked. No production port number is
embedded here. Inspect runtime membership and isolated persistence results; a
service status or success string alone is not reboot validation.

## Regression evidence boundary

Tests reproduce empty, inline and multiline port elements and auto-merged ranges;
exercise actual nft block/unblock and load persisted configuration in a **new**
private network namespace; preserve synthetic IPv4/IPv6 bans, foreign tables and
foreign persistence; inject second-file failure and verify exact-file/runtime
rollback; test known repair with and without a live Docker table; and verify a
scoped v0.33/v0.34 wrapper hotfix preserves all unrelated bytes. No actual operator
server reboot, packet capture or production recovery is claimed by CI.
