# Fresh installation preflight — v0.34-dev

This is a development source workflow, not proof of successful VM installation,
reboot or external traffic enforcement. The original `v0.34-dev` tag's installer
rejects distro stock flush configuration; its upgrade asset is not a clean-install
bundle. Use current reviewed source for this fix. The old tag/assets are unchanged.

## Known partial-install recovery (core profile only)

The first VM trial of source `06d730b` found a startup race: systemd returned
before the Fail2Ban socket was ready. Subsequent source waits for `ping` **and**
the exact selected active jail list, with a 60-second deadline. The VM trial did
not validate a completed fresh install or reboot. Do not rerun the fresh installer
over an `incomplete` marker, and do not delete configuration/database to bypass it.

Follow-up user-reported VM testing confirmed recovery and reboot with the two
core jails: documentation-only IPv4/IPv6 manual bans survived reboot, and unban
removed both addresses from the jail and all four relevant nft sets. This is
recovery/reboot evidence, **not** a clean installation without recovery or an
external packet-drop test. A second genuinely clean Ubuntu 26.04 ARM64 VM trial
at `393abab` subsequently completed core installation **without recovery**,
reported two active jails and a complete marker, then after reboot reported
Fail2Ban/nftables/cron active and both-family synchronization PASS. These are
user-reported core-profile results, not Docker/NPM or external IPv6 enforcement
validation. See [validation scope](CANARY-VALIDATION.md).

For that specific partial **core-only** transaction, use the separate root-only
`scripts/recover-fresh.py` from the reviewed fix. Keep the repository Git history
available (`git fetch origin`); recovery derives generic target fingerprints from
the immutable original commit. Supply your actual private backup directory locally:

```sh
read -r -p 'Exact /var/backups/f2b-fresh-* directory: ' F2B_RECOVERY_BACKUP
sudo /usr/bin/python3 scripts/recover-fresh.py --backup "$F2B_RECOVERY_BACKUP"
# Only after PASS, using the identical reviewed checkout and backup:
sudo /usr/bin/python3 scripts/recover-fresh.py --backup "$F2B_RECOVERY_BACKUP" --apply
sudo fail2ban-client ping
sudo fail2ban-client status
sudo f2b sync check
sudo f2b docker verify
sudo cat /etc/f2b/fresh-install.state
```

The original backup has **no transaction manifest**. Recovery does not pretend
otherwise: it requires verified stock archived configuration, exact legacy target
bytes, the known incomplete marker, the core profile, enabled services, isolated
persistence syntax validation, and an unchanged foreign-firewall digest. Unknown
files, modified targets, unsafe permissions, mismatched backup, or another profile
are refused. Apply creates a private recovery manifest and copies of replaced
diagnostic helpers; it does not replace jail configuration, stop the daemon,
restore the database, or load/flush the global firewall. A failed completion keeps
the incomplete marker. No automatic rollback of unknown state is attempted.

`nftables` being **inactive/dead but enabled/success** is expected immediately
after the scoped install: owned tables were loaded individually, not by starting
the systemd unit. The unit is enabled for boot; the drop-in disables the stock
stop flush and rejects reload. Do not `start`/`restart` it over live tables just
to make status green. Enabled state plus an isolated syntax check is not proof
of successful boot persistence; test reboot separately on the disposable VM.

## Copy/paste: disposable Ubuntu 26.04 ARM64 VM, core profile

Run in a fresh booted VM with console access, not on an existing managed host:

```sh
sudo apt-get update &&
sudo apt-get install -y git ca-certificates python3 &&
command -v git &&
git --version &&
git clone https://github.com/Zahorone/fail2ban-hybrid-manager.git &&
cd fail2ban-hybrid-manager &&
git switch --detach origin/main &&
git rev-parse HEAD &&
cd releases/v0.34 &&
sudo bash INSTALL-ALL-v034.sh --check
```

The first check may intentionally exit nonzero and list missing packages. Then:

```sh
sudo bash INSTALL-ALL-v034.sh --install-prerequisites
sudo bash INSTALL-ALL-v034.sh --check
sudo bash INSTALL-ALL-v034.sh --apply --bootstrap-stock-nft
sudo fail2ban-client status
sudo nft list tables
```

The snapshot commit must include this workflow; a moving branch is not a final
release. No placeholder commit hash is required in these commands. Do not add
`--check` to mutating flag combinations. Defaults enable only `recidive` and
`manualblock`, not SSH/web protection or a claimed fixed 13 active jails.

## Download without Git

Download dependencies are needed before the installer can even be obtained.
For Git download these are `git` and `ca-certificates`; `python3` is the minimal
local preflight bootstrap. Install them explicitly as above. The installer cannot
diagnose a missing Git executable when it has not yet been downloaded.

An already extracted source tree does not need Git for fresh installation.
Alternatively, obtain a source archive of the reviewed readiness-fix commit:

```sh
sudo apt-get update &&
sudo apt-get install -y ca-certificates curl tar gzip python3 &&
F2B_SOURCE_DIR="$(mktemp -d)" &&
curl --fail --location \
  https://github.com/Zahorone/fail2ban-hybrid-manager/archive/393abab6c0285826c56f2e39b07608288c21318a.tar.gz \
  --output "$F2B_SOURCE_DIR/source.tar.gz" &&
tar -xzf "$F2B_SOURCE_DIR/source.tar.gz" -C "$F2B_SOURCE_DIR" --strip-components=1 &&
cd "$F2B_SOURCE_DIR/releases/v0.34" &&
sudo bash INSTALL-ALL-v034.sh --check
```

This uses a new temporary directory and stops on download/extraction failure.
Review the pinned source before apply; HTTPS transport is not an independent
signature/checksum verification. Do not pipe downloads into a privileged shell.
The existing **v0.34-dev release asset is upgrade-only**, not a fresh-install
bundle; do not substitute it for this source archive. Legacy partial-install
recovery is a separate workflow that requires repository Git history.

Runtime prerequisites are checked only once the local installer is available.
Git, curl and download certificates are not added to its runtime dependency list.

## Dependencies and optional profiles

Core packages: `nftables fail2ban python3 cron iproute2 util-linux sudo acl attr
tar gzip coreutils grep sed gawk`. Git is needed only to clone the source
(or for the separate legacy recovery workflow), not for fresh installation.
The checker verifies installed dpkg status, required commands, Bash 4+, the
distribution Fail2Ban Python module, systemd PID 1 and supported OS/architecture.
Missing Python bootstrap is diagnosed before calling Python. Package installation
is opt-in; apt errors or still-missing prerequisites stop the workflow.

- `--ssh`: select `openssh-server python3-systemd`, verify SSH configuration,
  enable the two SSH jails using the journal. Default port is 22; explicitly use
  `--ssh-port` if different. This installs SSH only when selected; do not change
  an existing listener configuration blindly.
- `--docker`: select `docker.io` only if no Docker executable exists, then require
  a responding daemon. Existing alternative Docker packages are not replaced.
  NPM itself is never installed by this script.
- `--npm-log-dir`: select web jails only when actual matching access/error files
  exist. Missing files disable the affected jail and are not created. No selected
  path is inferred from a VM hostname or copied into the repository.
- `--mail-to`: select `mailutils whois`, and `default-mta` only if sendmail is absent.
  Configure and test the selected MTA separately; binary presence is not delivery
  proof. Without mail selection, all profile actions omit notification commands.

Repeat the **same** optional profile arguments for prerequisite setup, read-only
check and apply. Two owned nft tables are always created for helper compatibility,
but that does not mean Docker is installed or external Docker traffic was tested.
The new table uses interface-name matching, so a missing `docker0` does not
prevent stock bootstrap; see the [nftables interface semantics](https://netfilter.org/projects/nftables/manpage.html).
Canonical filters and regexes are unchanged; selection is a local jail override.

## Stock bootstrap and foreign state

The existing `/etc/nftables.conf` must be a regular file matching the installed
nftables package conffile MD5 **and** an empty accept-chain template (or empty
stock body). This is provenance/shape checking, not a cryptographic trust claim.
Distribution Fail2Ban conffiles must also match package records; modified base
files are not silently treated as fresh just because no `.local` file exists.
Unknown/edited configuration, custom persistence/drop-ins, local Fail2Ban
overrides, managed tables, symlinked installation paths or existing database ban
history require manual review. Fresh installation never adopts/erases those bans.
Never remove a flush or delete tables just to bypass a refusal.

Apply requires `--bootstrap-stock-nft`. It makes a root-only private backup of
existing Fail2Ban and nft configuration, records the live firewall, stops the
distribution Fail2Ban service and creates only the manager's owned tables.
It **does not execute `/etc/nftables.conf`, globally flush, restart Docker or
reload nftables**. Persistence references only owned snapshots; nftables stop/
reload overrides prevent a subsequent global service flush. Foreign live rules
are compared before/after and never automatically rewritten. Their own boot
persistence remains the operator's responsibility.

## Failure and rerun

A failure after backup is a visible **incomplete** installation, not success.
Keep the printed private backup path and console access; inspect the failing
step before a reviewed recovery. Package installations are not rolled back.
There is no automatic fresh-install rollback guarantee. Existing/incomplete
state is refused on rerun rather than cleaned or rebuilt, preserving bans/rules.
The transactional upgrade/rollback workflow is separate; do not use it to blindly
adopt an incomplete fresh install or to change a selected profile.

To test Docker/NPM after a successful core test, preserve that VM snapshot and
use a **different pre-manager VM** with Docker/NPM already serving real traffic.
There is no supported fresh-rerun profile-add operation. Follow the separate
[Docker/NPM lab and packet-test recipe](DOCKER-NPM-LAB.md).

## Validation limits

Unit fixtures cover stock vs unknown configurations, missing dependencies,
explicit apt consent/result checks, Ubuntu ARM64 detection, optional profiles,
real-log selection and rerun refusal. Linux namespace CI uses real Fail2Ban/
nftables, dual-family bans and foreign-rule preservation with **simulated
systemd/cron**. It is not an apt download test or real Ubuntu ARM64 VM/reboot test.
Complete VM, reboot, external IPv4/IPv6/Docker and canary release gates separately.
