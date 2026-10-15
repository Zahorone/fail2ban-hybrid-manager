# Synthetic recognized v0.33-family baseline for the pinned upgrade

**Disposable VM only. No production, no release, no old INSTALL-ALL.** Preserve
the successful ARM64 evidence VM. Select a separate clean pre-manager snapshot
or clone before apply. This prepares a runtime baseline, not a new product install
or full Docker/NPM/OS certification. Keep VM console access.

## What baseline this actually is

Canonical source is exactly `196400970b669f8fd43eebadad3b971125de857e` under
`releases/v0.33`, with wrapper version **0.33-ipv6.1**. This is a recognized v0.33
family snapshot, NOT the pristine original `a88bacb` release. Original PHP-CGI
`%AD|%ad` literals fail Fail2Ban interpolation; canonical commit `6950809` changed
them to `%%AD|%%ad`. The selected canonical file already has that fix. We do not
rewrite managed `.conf`, wrapper, jail.local or hook files, and do not introduce
a PHP `.local` override that would mask the upgraded PHP filter. Every deployed
managed source is checked against the pinned upgrade's offline known-target list.

The lab payload contains only canonical filters/actions/jail.local/wrapper/hook/
reconciler plus this bootstrap and guide; no Git repository, old installers, logs,
DB, real hosts/IP/email/credentials or private hash reviews. SHA256SUMS and
LAB-MANIFEST identify both canonical baseline and bootstrap commits. Canonical
example email strings remain unchanged. Non-PHP mail actions are disabled;
the genuine PHP binary-safe mail action is retained, but its transport is an
explicit local file sink and external whois is replaced with synthetic text.
No SMTP/MTA command or external whois query is used. No package installation is hidden in the bootstrap.

`/etc/fail2ban/jail.d/zz-v033-lab.local` documents the lab policy:
SSH jails disabled (no real authentication log input); other canonical jails use
synthetic application files; nft+Docker hooks retained, non-PHP mail removed; manualblock
has a 7200s bantime and the whitelist adds only documentation addresses. This is
not a detection-filter repair or permission to ignore real attacks. The override
must remain compatible with both baseline and upgrade candidate; the test invokes
real preflight before and after upgrade/rollback and restarts the restored baseline.
`/etc/fail2ban/action.d/sendmail-whois-lines.local` changes only the lab transport
and whois helper; it does not replace actionban/evidence grep or any detection
filter. PHP retains actual `grepopts=-a -m <grepmax>`, as required by the pinned
upgrade validator. The root-private local sink is `/var/lib/f2b-v033-lab/logs/mail.log`
(both private directories are root-owned 0700, sink 0600).
It is never archived/uploaded. Both explicit local files survive upgrade/rollback.

### System log trust boundary

The generic strict path validator is unchanged in scope: root ownership, no
symlinks and no group/world writes. Only canonical log handling separately accepts
the exact distro `/var/log` directory as root:syslog 0775 (or strict root-owned
non-writable layout). No chmod/chown of system `/var/log` is performed. Unexpected
owners/groups, world writes, symlink parents and non-regular/multiply-linked log
files are refused with the offending path and reason. Existing root-owned,
non-group/world-writable distribution `fail2ban.log` is opened without following
symlinks, inode-checked, and preserved without reading, truncating or changing its
metadata. Other canonical output files must be absent. New files are created 0600
through the pinned directory descriptor with O_NOFOLLOW and O_EXCL; a file planted
between check and creation causes refusal, never truncation or symlink traversal.

This explicitly trusts the system syslog principal, not arbitrary writable
parents. Syslog can replace entries in a non-sticky 0775 directory even when files
are root-owned. Canonical wrapper/hook and Fail2Ban continue opening their standard
log paths at runtime; these managed bytes cannot be changed while testing the
pinned upgrade. This lab is NOT isolation against a compromised syslog account or
concurrent hostile writers. Do not apply if that system principal is untrusted;
use the clean VM snapshot instead. The lab-only mail sink avoids that boundary
entirely under strict `/var/lib` ancestors. CI exercises the syslog layout plus
owner/mode/symlink/hardlink and insertion-race refusals, then the same real daemon
upgrade/rollback sequence; it does not certify real ARM64/Ubuntu26 execution.

## Transfer two independently verified artifacts

1. The lab archive and checksum from the reviewed handoff.
2. The existing **unchanged integrated 1964009** archive, whose SHA256 is:

```text
271ca3d229bbe5cacebba2c48bb6fb0069d1ff9d52aaedaf7adaffd949635bbb
```

Use a new VM working directory outside either extracted payload. Verify the lab
SHA against the handoff, not merely an adjacent untrusted checksum. Then:

```sh
sha256sum -c f2b-v033-lab.tar.gz.sha256 &&
printf '%s  %s\n' 271ca3d229bbe5cacebba2c48bb6fb0069d1ff9d52aaedaf7adaffd949635bbb f2b-complete-upgrade.tar.gz | sha256sum -c - &&
tar -xzf f2b-v033-lab.tar.gz &&
tar -xzf f2b-complete-upgrade.tar.gz
```

Stop on failure. The lab root is `f2b-v033-lab-BOOTSTRAP_COMMIT7`; the upgrade root
is `f2b-integrated-v034-dev-1964009`. Keep outputs/evidence outside these folders.
Set the lab root from the exact reviewed bootstrap commit in the handoff:

```sh
read -r -p 'Exact extracted lab directory from handoff: ' F2B_LAB_ROOT
F2B_UPGRADE_ROOT="$PWD/f2b-integrated-v034-dev-1964009"
/usr/bin/python3 "$F2B_UPGRADE_ROOT/scripts/verify-integrated-bundle.py" --expected-commit 196400970b669f8fd43eebadad3b971125de857e
```

## Prerequisites are a separate explicit operator action

First run the read-only command below. If it reports missing prerequisites, this
is a refusal, not permission for hidden changes. On the clean Ubuntu 26.04 ARM64
clone (not the existing configured VM), explicitly install them, then repeat check:

```sh
sudo /usr/bin/python3 "$F2B_LAB_ROOT/scripts/bootstrap-v033-lab.py" --upgrade-bundle "$F2B_UPGRADE_ROOT" --check
```

```sh
sudo apt-get update &&
sudo apt-get install -y python3 fail2ban nftables cron iproute2 util-linux sudo acl attr tar gzip coreutils grep sed gawk
```

This installs dependencies, not the lab payload. Do not disable UFW/Docker or flush
their rules. Actual Ubuntu/architecture/systemd and installed prerequisites are
checked locally; namespace CI substitutes only platform/lifecycle checks. Existing
manager, ban history, custom `.local` files, symlink targets, non-stock persistence
or existing synthetic traffic directories cause refusal rather than cleanup.

## Read-only preflight, then separate apply

```sh
sudo /usr/bin/python3 "$F2B_LAB_ROOT/scripts/bootstrap-v033-lab.py" --upgrade-bundle "$F2B_UPGRADE_ROOT" --check
```

Preflight checks payload inventory, pinned upgrade provenance, canonical hashes,
clean-host guards, prerequisites, foreign rules and a shadow Fail2Ban candidate.
Only private temporary shadow log files are created; no live fake logs/config or
firewall changes occur. Do not apply after refusal. After PASS, confirm a separate
clean VM snapshot exists and manually approve this command:

```sh
sudo /usr/bin/python3 "$F2B_LAB_ROOT/scripts/bootstrap-v033-lab.py" --upgrade-bundle "$F2B_UPGRADE_ROOT" --apply --snapshot-confirmed
```

Apply makes a private original-config backup, copies exact canonical files,
installs the explicit lab override and **synthetic** empty application/manual
input files, creates only two previously absent owned nft tables, and writes scoped
persistence includes over the verified stock file. It never loads `/etc/nftables.conf`,
flushes a ruleset, changes foreign tables or stops/restarts Docker/UFW/nftables.
Fail2Ban alone is started/restarted; cron is enabled. It checks ping + exact active
jails, canonical file fingerprints, unchanged foreign rules and the pinned upgrade
preflight, then adds only documentation IPv4/IPv6 manual bans. Lab failure is not
silently cleaned up: preserve backup, do not rerun, restore the clean VM snapshot.

This is not the fresh production installer: synthetic placeholders are intentional
test fixtures, not evidence of real NPM traffic. SSH auth logs are not fabricated
or read. Old PHP/action packet semantics are not certified by this lab policy.

## Mandatory boot preparation and real baseline reboot

### Runtime preservation and partial preparation

Raw nft JSON is NOT compared: expiry values decrease and packet counters increase
without a policy mutation. The lab guard checks endpoint rule/expression order,
set schema, unordered membership and element timeout metadata. Known kernel handles
and metainfo are not policy. Counters may only increase, never reset/decrease.
Remaining expiry is converted to absolute monotonic-time intervals bounded by each
snapshot's start/end and nft JSON precision (one second for integer output, one
millisecond for fractional output, plus 20ms kernel allowance). Sampling windows
over two seconds are refused. Retiming outside overlapping intervals is refused;
sub-resolution differences cannot be proven absent and are not claimed detectable.
A disappearing timed member is accepted only if its latest possible original
expiry precedes the second sampling window. Permanent/early removals and additions
are refused. Rule order is never sorted away. Private before/after semantic evidence
stays only in the root-private preparation backup, never in an archive/CI upload.

Preparation holds upgrade then runtime-sync locks nonblockingly. It never queries
the Fail2Ban socket under these locks. Cooperative cron/hook writers are excluded;
legacy direct nft writers and Fail2Ban are not assumed paused or lock-aware. An
observed concurrent membership/rule change therefore fails closed, without blaming
preparation or undoing someone else's firewall. Two endpoint snapshots cannot
prove that no transient writer ran and restored the same state between them. Use
the quiet disposable baseline; do not weaken the guard for a busy host.

A durable 0600 schema-2 marker is written BEFORE drop-ins/enable operations with
status `preparing`, original enabled states and the private backup path. Completion
sets `prepared`; failure sets `failed`; a crash may leave `preparing`. Neither is
boot acceptance. Check-boot refuses failed/incomplete/legacy state; reruns do not
adopt or overwrite partial preparation. No automatic unflush/undo/foreign-service
operation is attempted. Retain the marker and backup privately, do not reboot or
rerun, and restore a separate clean snapshot. In the older af0bc5a false-failure
case there may be NO marker despite written drop-ins/enabled states: absence does
not mean clean. Preserve that evidence VM and repeat from a clean snapshot with
the new pinned archive; never reconstruct a success marker manually.

Earlier bootstrap prepared runtime only. Disabled nftables loses infrastructure
after reboot; After= alone does not request its start. Syntax checks and daemon
restarts are not boot acceptance. Preserve the failed evidence VM and its backup;
do not blindly start nftables/load the global config. Repeat on a clean snapshot.

After baseline apply, BEFORE upgrade, explicitly authorize disposable-lab-only
preparation. It refuses upgraded baselines, custom units/drop-ins, non-stock vendor
loaders and anything except the exact two-owned-includes synthetic configuration:

```sh
sudo /usr/bin/python3 "$F2B_LAB_ROOT/scripts/bootstrap-v033-lab.py" --upgrade-bundle "$F2B_UPGRADE_ROOT" --prepare-boot --snapshot-confirmed
```

Preparation privately records original unit enabled states, syntax-checks in a
private net namespace, installs LAB-ONLY no-flush/no-reload nftables stop semantics
and Requires= plus After=nftables.service for Fail2Ban and cron, runs daemon-reload
and enables the three lab units WITHOUT --now. No live firewall load/start/restart
or reload occurs. At boot, the stock loader reads only the two explicitly owned
includes: no global flush or foreign table declarations. This is not authorization
to enable a foreign firewall on an existing host.

```sh
sudo reboot
# Reconnect and restore variables for the same verified extracted directories.
sudo /usr/bin/python3 "$F2B_LAB_ROOT/scripts/bootstrap-v033-lab.py" --upgrade-bundle "$F2B_UPGRADE_ROOT" --check-boot
sudo systemctl is-enabled nftables fail2ban cron
sudo systemctl is-active nftables fail2ban cron
sudo journalctl -b -u nftables.service --no-pager
sudo fail2ban-client get manualblock banip
```

The gate refuses the preparation boot ID, pending daemon-reload, disabled/inactive
units, missing dependencies/order and missing/mistyped timed family infra sets.
Also inspect the real boot journal, exact jails, documentation bans after bounded
DB restore, and sync/Docker-union checks; keep evidence local, never upload journals.
Do not upgrade until all checks pass. This is not packet acceptance.

The boot-preparation backup records ORIGINAL pre-preparation enabled states. To
restore the pre-manager machine, restore the clean snapshot including those states;
do not disable dependencies beneath a running lab. Upgrade rollback instead restores
the PREPARED v0.33 baseline: its enabled units/drop-ins must remain. New product
backups record/restore original enabled states without --now or firewall restart.
Immutable 1964009 predates that recording and changes no enabled states: compare the
prepared states independently after its rollback. Do not call that legacy metadata
a verified restoration of previously unrecorded state.

## Upgrade and rollback with independent checks

After upgrade perform a SECOND REAL reboot, repeat --check-boot and the boot journal,
verify 0.34-dev, exact 11-jail profile, both bans and sync/Docker-union checks. Any
missing table/set is failure, not permission for manual recreation. Only then roll
back. After rollback perform a THIRD REAL reboot and repeat the gate, journal,
0.33-ipv6.1, exact 10-jail profile and both bans. Namespace lifecycle simulations
are never reboot acceptance. The pinned upgrade artifact/SHA remain unchanged.

```sh
sudo fail2ban-client -t
sudo fail2ban-client ping
sudo f2b version --short
sudo /usr/bin/python3 "$F2B_UPGRADE_ROOT/scripts/upgrade-v033-v034.py"
sudo /usr/bin/python3 "$F2B_UPGRADE_ROOT/scripts/upgrade-v033-v034.py" --apply
sudo f2b version --short
sudo f2b sync check
sudo f2b docker verify
```

Record the exact upgrade backup path privately (not the bootstrap backup). Verify
the lab `.local` bytes unchanged, both manual bans present and their absolute
expiry not reset. Then use the exact printed path, replacing the placeholder:

```sh
sudo /usr/bin/python3 "$F2B_UPGRADE_ROOT/scripts/upgrade-v033-v034.py" --rollback /var/backups/EXACT-UPGRADE-BACKUP-DIRECTORY
sudo fail2ban-client -t
sudo systemctl restart fail2ban
sudo fail2ban-client ping
sudo f2b version --short
sudo fail2ban-client get manualblock banip
sudo /usr/bin/python3 "$F2B_UPGRADE_ROOT/scripts/upgrade-v033-v034.py"
```

Require restored version 0.33-ipv6.1, canonical bytes and local override unchanged,
documentation bans retained, valid config, live ping and fresh upgrade preflight
success. The original broken percent filter is never reintroduced by rollback.
Keep output/backup/config/VM addresses local; share generic pass/fail only.

## Coverage and remaining gates

CI rebuilds the integrated artifact from exact 1964009 canonical Git history and
requires the pinned archive SHA above. It then tests the **lab archive itself**
with real Fail2Ban/nft: preflight nonmutation, bootstrap/restart, pinned upgrade,
rollback/restart/repreflight, canonical/local bytes, both-family timed bans and a
foreign sentinel. Platform/systemd/cron are simulated; these are not VM results.

A real Ubuntu 26 ARM64 run adds current-distribution/ARM package and daemon API
compatibility, upgrade and rollback restart evidence. It does NOT replace the
planned Ubuntu 24 amd64 representative valid-v0.33/Docker/UFW clone, exercise an
Ubuntu OS upgrade, certify pristine a88bacb, test genuine NPM traffic/packet drops,
or prove boot/reboot persistence. Those existing acceptance gates remain separate.
No RC/stable promotion or v0.40 changes are authorized by this bootstrap.
