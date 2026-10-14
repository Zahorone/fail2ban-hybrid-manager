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
example email strings remain unchanged, but **all mail actions are disabled** by
the explicit lab jail policy. No package installation is hidden in the bootstrap.

One local file, `/etc/fail2ban/jail.d/zz-v033-lab.local`, documents the lab policy:
SSH jails disabled (no real authentication log input); other canonical jails use
synthetic application files; nft+Docker hooks retained, mail removed; manualblock
has a 7200s bantime and the whitelist adds only documentation addresses. This is
not a detection-filter repair or permission to ignore real attacks. The override
must remain compatible with both baseline and upgrade candidate; the test invokes
real preflight before and after upgrade/rollback and restarts the restored baseline.

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

On the clean Ubuntu 26.04 ARM64 clone (not the existing configured VM):

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
or read. Baseline boot ordering/persistence and old PHP/action packet semantics
are not claimed fixed by this lab policy.

## Upgrade and rollback with independent checks

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
