# One integrated 0.34-dev validation bundle

This is a development artifact, **not RC/final/stable**. It contains separate
fresh and transactional upgrade entrypoints, complete current wrapper/reporting,
filters, actions, exact dual-family verifier, reconciler and scoped persistence.
Do not apply every included script manually. Optional application hardening and
the local v0.40 work are outside this bundle. No production files are required.

## Provenance and reproducibility

Build from a clean committed checkout with full canonical source history:

```sh
/usr/bin/python3 releases/v0.34/scripts/build-upgrade-package.py --integrated /tmp/f2b-complete-upgrade.tar.gz
```

The archive has one `f2b-integrated-v034-dev-COMMIT/` directory, exact
`UPGRADE-MANIFEST.json`, `SHA256SUMS`, source commit and offline known-target
digests derived only from canonical component history. No `.git`, private review,
backup, log, database, credentials, production IP/domain/email or hostname is
included. Only allowlisted product files are copied. Tar ownership/mode/mtime and
gzip metadata are deterministic; CI builds twice and compares archive bytes.
The adjacent `.sha256` and `.json` receipt identify the exact archive and commit.
CI uploads only these three generic files, never test logs/backups or VM evidence.
Archive consumers need no Git or separate hotfix directories. Prerequisite OS
packages/container images are NOT embedded: this is an offline-capable product
payload, not an air-gapped apt/image mirror. Fresh dependency installation remains
explicit. The verifier is read-only and does not certify runtime or networking.

## Evidence ledger (do not conflate layers)

Historical operator evidence includes ARM64 core fresh/reboot and Docker/NPM
manual/automatic IPv4+IPv6 checks accumulated across successive hotfixes. Reporting
presentation and port/diagnostic fixes were separately deployed and checked.
That is **not** acceptance of this newly assembled archive on one clean VM.

New archive namespace CI exercises real Fail2Ban/nftables with synthetic fixtures:
core fresh, log-backed NPM fresh, exact diagnostics/report CLI, scoped ports and
cold include load; v0.33 recognized/restartable baseline upgrade, reapply, injected
deployment failure/auto rollback and explicit rollback; local overrides, whitelist,
timed bans, SQLite data and foreign tables. systemd/cron are simulated. NPM logs
are synthetic; no Docker containers/network packets/reboots are tested there.
Artifact syntax, inventory/dependency omissions, symlinks, tampering and commit
mismatches are tested offline. Results are attached to the exact CI run/receipt;
no namespace result can satisfy the VM/boot/packet gates below.

The original pristine v0.33 has a known invalid percent-format filter on the
tested Fail2Ban baseline: CI confirms refusal, NOT a successful pristine runtime
upgrade. Use a valid recognized v0.33 clone; never weaken rollback restart checks.

| Gate | Target/evidence | Required result |
|---|---|---|
| Offline bundle | exact receipt commit/SHA, inventory, deterministic rebuild | CI + local pass |
| Core fresh | clean Ubuntu 26 ARM64 Parallels pre-manager snapshot | pending VM |
| Docker/NPM fresh | separate pre-manager Ubuntu 26 ARM64 clone, real traffic | pending VM |
| Upgrade/reapply | isolated Ubuntu 24 amd64 clone, valid v0.33 + Docker/UFW fixtures | pending VM |
| Rollback/fault | same clone + new timed bans after apply | pending VM |
| Boot persistence | normal reboot after apply and rollback | pending VM |
| IPv4/IPv6 packets | two independently observed clients, real NPM/Docker traffic | pending VM |

No verified VM connection is assumed. Keep the successful historical VM/snapshots
intact. Do not use production or copy its logs/config/DB. Ubuntu 24 -> 26 OS
upgrade is a different project: this tests manager v0.33 -> 0.34-dev only.

## Receive and verify on the disposable VM

Download the CI artifact (three files) on your workstation and transfer it to
the test VM using your private local connection. The handoff gives the **literal
source commit and archive SHA256**; compare those independently, not only against
a checksum downloaded beside an untrusted file. No token/SSH key belongs in Git.
In a new empty VM working directory, using Bash:

```sh
read -r -p 'Expected archive SHA256 from reviewed handoff: ' F2B_EXPECTED_SHA
read -r -p 'Expected full source commit from reviewed handoff: ' F2B_EXPECTED_COMMIT
printf '%s  %s\n' "$F2B_EXPECTED_SHA" f2b-complete-upgrade.tar.gz | sha256sum -c - &&
sha256sum -c f2b-complete-upgrade.tar.gz.sha256 &&
tar -xzf f2b-complete-upgrade.tar.gz &&
cd "f2b-integrated-v034-dev-${F2B_EXPECTED_COMMIT:0:7}" &&
/usr/bin/python3 scripts/verify-integrated-bundle.py --expected-commit "$F2B_EXPECTED_COMMIT"
```

Stop on ANY failure. Missing Python on fresh Ubuntu must be explicitly bootstrapped
with `sudo apt-get update && sudo apt-get install -y python3 ca-certificates`.
Keep the archive immutable; do not place outputs/cache/evidence inside its folder.

## A. Core fresh (one clean snapshot)

Console access and a pre-manager VM snapshot are mandatory. No Docker/NPM/SSH/mail
profile is implied. On clean Ubuntu 26 ARM64:

```sh
sudo bash INSTALL-ALL-v034.sh --install-prerequisites
sudo bash INSTALL-ALL-v034.sh --check
sudo bash INSTALL-ALL-v034.sh --apply --bootstrap-stock-nft
sudo fail2ban-client ping
sudo fail2ban-client status
sudo f2b sync check
sudo f2b docker verify
sudo f2b report attack-analysis
sudo f2b report attack-analysis short
sudo f2b report json | /usr/bin/python3 -m json.tool >/dev/null
```

Require exact active profile `manualblock, recidive`, successful ping and a complete
fresh marker, not merely an active systemd unit. Core has no HTTP logs: unavailable
HTTP is expected, not a failed security claim. Fresh rerun must refuse. Incomplete
fresh install is not automatically converted to an upgrade: preserve backup and
restore the disposable pre-manager VM snapshot for the next clean attempt.

## B. Docker/NPM fresh (different pre-manager snapshot)

Use bundled [Docker/NPM recipe](DOCKER-NPM-LAB.md), starting from its isolated
network, pinned Compose files under `examples/docker-npm-lab`, two test/control
clients and real NPM traffic. Substitute this extracted bundle for its checkout
instructions. Do not add a profile by rerunning fresh on the successful core VM.
Docker/image pull, console setup, real access/error files and source-IP fidelity
must pass before installing. Then use the SAME flags for prerequisites/check/apply:

```sh
sudo bash INSTALL-ALL-v034.sh --install-prerequisites --docker --npm-log-dir /opt/f2b-npm-lab/data/logs
sudo bash INSTALL-ALL-v034.sh --check --docker --npm-log-dir /opt/f2b-npm-lab/data/logs
sudo bash INSTALL-ALL-v034.sh --apply --bootstrap-stock-nft --docker --npm-log-dir /opt/f2b-npm-lab/data/logs
sudo /usr/bin/python3 /usr/local/libexec/f2b-runtime-verify.py --npm-coverage
sudo fail2ban-client status
```

Compare actual active jails against the preflight's selected/log-backed profile.
Do not require a fixed maximum count. Configure private reporting paths/probe rules
locally as needed; never copy real values into the artifact. Fresh's `--npm-log-dir`
selects jail inputs; reporting keeps its separate explicit local configuration.
For this lab, create or edit `/etc/f2b/reporting.ini` privately with a `[reporting]`
section and `npm_log_dir = /opt/f2b-npm-lab/data/logs`. Do not overwrite an existing
file or install blanket probe rules. CI supplies this synthetic local input and
verifies both its preservation and an actual parsed HTTP record. Full/short scope flags
and JSON/CSV must work; unknown analysis arguments must fail.

## C. Manager upgrade, reapply, rollback (Ubuntu 24 amd64 clone)

Create an isolated representative VM or authorized sanitized clone with a valid
restartable recognized v0.33 baseline, synthetic overrides/whitelist/timed bans,
working Docker/NPM and UFW, foreign Docker/UFW/nft tables, and a different
management/client path. Do not clone production secrets or public networking.
Snapshot before tests. Preserve baseline checks privately outside the bundle.

```sh
sudo /usr/bin/python3 scripts/upgrade-v033-v034.py
sudo /usr/bin/python3 scripts/upgrade-v033-v034.py --apply
sudo fail2ban-client ping
sudo f2b sync check
sudo f2b docker verify
sudo /usr/bin/python3 scripts/upgrade-v033-v034.py
sudo /usr/bin/python3 scripts/upgrade-v033-v034.py --apply
```

Record the EXACT first backup path printed by apply. Verify site overrides,
whitelist, reporting.ini and unrelated services/foreign rules unchanged; SQLite
integrity and remaining ban times persist without being reset to a fresh duration.
Allow naturally elapsed TTL and genuinely new bans, not silent loss. Unknown local
managed code or a suppressing filter override must refuse before mutation. A
managed-target symlink must refuse. Restore each test fixture before the next gate.
Use the exact backup for explicit rollback (the example path is a placeholder):

```sh
sudo /usr/bin/python3 scripts/upgrade-v033-v034.py --rollback /var/backups/EXACT-PRINTED-BACKUP-DIRECTORY
sudo fail2ban-client ping
```

Add a short timed synthetic ban after apply, before rollback. Check it remains
protected, including the documented fallback when its new jail does not exist in
v0.33. Fault injection is implemented in artifact namespace CI by failing the third
atomic replacement, then verifying actual automatic recovery. Do not corrupt a VM
payload or kill services to imitate this on a shared system; VM fault testing needs
an isolated snapshot/explicit test harness. Namespace fault evidence is not boot
acceptance. No rollback may globally load/flush Docker/UFW rules.

## Independent reboot and packet acceptance (operator, NOT run by CI)

After fresh/upgrade and again after rollback, keep private baselines and reboot
normally from the VM console. Check `systemctl is-active fail2ban cron nftables`,
`systemctl is-enabled fail2ban cron nftables`, `fail2ban-client ping/status`, actual
`nft list ruleset`, `fail2ban-client get JAIL banip`, and SQLite `PRAGMA integrity_check`.
Compare exact selected profiles, foreign rules structurally (exclude changing
counters), block-port membership in both live nft set and persisted include, ban
expiry, and reporting CLI. Reboot is a separate observed event, not an nft syntax
or namespace cold-load check. Never load global persistence over a live daemon.

For each family independently, from a separate test client require HTTP 200 via
real Docker/NPM, verify its actual source in NPM, manually ban that source for a
short bounded period, observe new connections fail while an independent control
client still receives 200, then unban/expire and require 200 again. Do not ban the
admin source, NAT gateway, VM host or Docker bridge. Observe drop counters and
client result, not just membership. Next send the bounded benign synthetic probe
sequence in the Docker/NPM recipe to exercise actual detector auto-ban and recovery.
Never infer automatic IPv6 success from manual bans or IPv4. If the isolated
topology lacks independently reachable IPv6, record NOT TESTED; promotion gate is
still open, not waived. Repeat relevant packet checks after reboot and rollback.

Keep all real VM addresses, outputs, configs, backups, review hashes and logs local.
Share only generic pass/fail, architecture/OS, artifact commit/SHA, exact gate and
whether systemd/cron/reboot/packets were real. **No RC/final tag until VM gates pass.**
