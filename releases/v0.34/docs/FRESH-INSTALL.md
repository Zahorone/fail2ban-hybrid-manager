# Fresh installation preflight — v0.34-dev

This is a development source workflow, not proof of successful VM installation,
reboot or external traffic enforcement. The original `v0.34-dev` tag's installer
rejects distro stock flush configuration; its upgrade asset is not a clean-install
bundle. Use current reviewed source for this fix. The old tag/assets are unchanged.

## Copy/paste: disposable Ubuntu 26.04 ARM64 VM, core profile

Run in a fresh booted VM with console access, not on an existing managed host:

```sh
sudo apt-get update
sudo apt-get install -y git python3
git clone https://github.com/Zahorone/fail2ban-hybrid-manager.git
cd fail2ban-hybrid-manager
git switch --detach origin/main
git rev-parse HEAD
cd releases/v0.34
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

## Dependencies and optional profiles

Core packages: `nftables fail2ban python3 cron iproute2 util-linux sudo acl attr
tar gzip coreutils grep sed gawk`. Git is needed only to clone the source.
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
Canonical filters and regexes are unchanged; selection is a local jail override.

## Stock bootstrap and foreign state

The existing `/etc/nftables.conf` must be a regular file matching the installed
nftables package conffile MD5 **and** an empty accept-chain template (or empty
stock body). This is provenance/shape checking, not a cryptographic trust claim.
Unknown/edited configuration, custom persistence/drop-ins, local Fail2Ban
overrides, managed tables or active pre-existing bans require manual review.
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

## Validation limits

Unit fixtures cover stock vs unknown configurations, missing dependencies,
explicit apt consent/result checks, Ubuntu ARM64 detection, optional profiles,
real-log selection and rerun refusal. Linux namespace CI uses real Fail2Ban/
nftables, dual-family bans and foreign-rule preservation with **simulated
systemd/cron**. It is not an apt download test or real Ubuntu ARM64 VM/reboot test.
Complete VM, reboot, external IPv4/IPv6/Docker and canary release gates separately.
