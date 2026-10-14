# 🚀 Fail2Ban Hybrid Manager

Fail2Ban Hybrid Manager integrates Fail2Ban with nftables **IPv4 + IPv6** and
Docker, with detection filters, ban synchronization, reporting and recovery tools.

The current source baseline is **v0.34-dev — Transactional Upgrade & Publication
Safety Edition**. It is a development candidate, **not an RC or final production
release**. Historical v0.33 downloads do not contain the current source fixes.

## What this project provides

- 🌐 **Dual-stack actions** — family-aware nftables actions and separate recidive sets.
- 🐋 **Docker protection** — synchronization of the union of active jail bans;
  an address shared by another jail must not disappear prematurely on unban.
- 🛡️ **Precise web detection** — critical PHP-CGI/RCE, credential-path and traversal
  indicators, plus missing-webshell probes with WordPress-safe exceptions.
- 📧 **Evidence mail** — nginx error-log evidence remains readable with binary
  bytes. Ordinary PHP warnings, fatals and generic HTTP 5xx alone are not attacks.
- 📊 **Reporting** — configurable health-probe exclusions affect reports,
  not filters, whitelists or enforcement.
- 🛠️ **Management wrapper** — jail/ban inspection, manual bans, synchronization,
  Docker diagnostics and reports.
- 📦 **Controlled upgrade package** — preflight, private backup, verification,
  automatic recovery on apply failure and explicit manual rollback.
- 🔒 **Publication safeguards** — checks for staged files, source and built packages.

See the [v0.34 guide](releases/v0.34/docs/README.md) and
[access-filter safety contract](releases/v0.34/docs/ACCESS-FILTER-SAFETY.md).
Canonical filters, actions and product scripts are intentionally public.

## Terminal reporting

```sh
sudo f2b report attack-analysis                    # graphical 24h report
sudo f2b report attack-analysis short              # compact summary
sudo f2b report attack-analysis short --npm-only    # scope and short in either order
sudo f2b report attack-analysis --ssh-only short
sudo f2b report json                               # pure schema-2 JSON
sudo f2b report csv                                # current per-jail ban snapshot
```

Full and short reports use the same schema-2 observations, explicit probe rules
and chronological sample. Terminal colors are disabled for redirected output,
`TERM=dumb`, or `NO_COLOR`; JSON/CSV never contain terminal formatting.
For already installed reporting code, use the scoped
[reporting-only preflight/apply/rollback](releases/v0.34/docs/REPORTING-ONLY-HOTFIX.md),
not a full reinstall. This does not change filters, bans or local reporting.ini.

## Releases

- **v0.34-dev** — current development baseline: transactional upgrade/rollback,
  dual-stack/Docker regressions, conservative filters, reporting and mail fixes.
- **v0.33** — historical PHP Error Detection & Docker Auto-Sync package.
- **v0.31 / v0.30** — earlier immediate-ban and one-click bundles.
- **v0.22 / v0.21 / v0.20** — earlier Docker, HTTP/HTTPS and IPv6 work.

Green CI does not promote a development candidate to a release. Disposable-host
clean install, representative upgrade/rollback, reboot persistence, external
IPv4/IPv6 Docker traffic and canary observation remain release gates. See
[validation scope](releases/v0.34/docs/CANARY-VALIDATION.md).

## Repository layout

```text
.github/workflows/       # Regression and publication checks
scripts/                # Generic publication gate and optional Git hook
docs/                   # Repository-wide publication policy
releases/
├── v0.34/               # Current development candidate
│   ├── VERSION
│   ├── INSTALL-ALL-v034.sh
│   ├── scripts/         # Installers, wrapper, helpers, builder/upgrader
│   ├── filters/
│   ├── actions/
│   ├── config/
│   ├── tests/           # Synthetic fixtures and Linux namespace tests
│   └── docs/            # README, upgrade, safety and validation guides
├── v0.33/               # Historical package and migration documentation
├── v0.31/
├── v0.30/
└── ...
```

## Usage

For the current development snapshot, these commands need no commit placeholder.
Record the printed commit and review it before applying; `main` is a moving
development branch, not an immutable final release.

On a minimal Debian/Ubuntu VM, install the download prerequisites **before**
cloning. `git` and `ca-certificates` provide HTTPS source download; `python3`
bootstraps the local preflight. The `&&` chain stops on any failure, so a failed
clone cannot run later commands from the wrong directory.

```sh
sudo apt-get update &&
sudo apt-get install -y git ca-certificates python3 &&
command -v git &&
git --version &&
git clone https://github.com/Zahorone/fail2ban-hybrid-manager.git &&
cd fail2ban-hybrid-manager &&
git switch --detach origin/main &&
git rev-parse HEAD
```

Do not continue to installation unless this chain succeeds. Download prerequisites
are separate from the installer's runtime package checks; Git is not required by
fresh installation from an already extracted source tree. See the
[no-Git source archive alternative](releases/v0.34/docs/FRESH-INSTALL.md#download-without-git).

### 🧪 Clean install — disposable host only

Use a fresh booted systemd Debian/Ubuntu amd64/arm64 test host. Ubuntu 26.04 ARM64
has user-reported core clean-install and reboot success; Docker/NPM and external
IPv4/IPv6 packet-drop validation remain pending. The default command checks prerequisites
without changing the host. Shipped whitelists contain loopback only.

```sh
cd releases/v0.34
sudo bash INSTALL-ALL-v034.sh --check
# Explicitly allow missing core packages to be installed; no manager install yet:
sudo bash INSTALL-ALL-v034.sh --install-prerequisites
# Check again, then explicitly back up/bootstrap verified stock persistence:
sudo bash INSTALL-ALL-v034.sh --check
sudo bash INSTALL-ALL-v034.sh --apply --bootstrap-stock-nft
```

Only `--install-prerequisites` and `--apply` authorize changes. Missing packages
are listed exactly; stock nftables configuration must match the installed distro
conffile and contain only harmless empty chains. Apply backs it up privately and
replaces persistence with owned includes **without executing its global flush**.
Unknown/custom configuration and existing/partial manager installs are refused.
Foreign live tables/rules are preserved, not copied into manager persistence.

The default core profile activates `recidive` and `manualblock`, not 13 jails.
Add `--ssh` (optionally `--ssh-port 22`) to **each** command to select SSH journal
jails/dependencies. `--docker` explicitly selects a Docker engine dependency and
requires a working daemon; it is not installed otherwise. Two owned nft tables
exist even without Docker to support the synchronization helper contract.
`--npm-log-dir /path/to/real/logs` selects only log-backed web jails; NPM is not
installed and missing traffic logs are never fabricated. `--mail-to` explicitly
selects mail dependencies/actions; configure/test the MTA separately. Do not copy
these optional placeholder paths/addresses literally. Keep profile values private.

See [fresh-install safety and dependencies](releases/v0.34/docs/FRESH-INSTALL.md).
Cleanup flags are unsupported. Broader profile/upgrade validation is still required.
For a separate pre-manager VM, see the [Docker/NPM lab](releases/v0.34/docs/DOCKER-NPM-LAB.md).
Do not rerun fresh install to add profiles to a complete core installation.

### 🔄 Existing v0.33 / v0.34-dev — staged upgrade package

From a clean committed repository checkout, build the candidate outside it:

```sh
python3 releases/v0.34/scripts/build-upgrade-package.py /tmp/f2b-upgrade.tar.gz
python3 scripts/check-publication-safety.py --archive /tmp/f2b-upgrade.tar.gz
```

The builder refuses to overwrite an existing archive. Verify its SHA-256
against the separately trusted build result, extract into a new directory and
run `sha256sum -c SHA256SUMS` inside the extracted package. Then:

```sh
sudo /usr/bin/python3 scripts/upgrade-v033-v034.py
# Only after successful preflight and maintenance-window approval:
sudo /usr/bin/python3 scripts/upgrade-v033-v034.py --apply
# If recovery is needed, use the exact backup path printed during apply:
sudo /usr/bin/python3 scripts/upgrade-v033-v034.py --rollback /EXACT/PRINTED/BACKUP
```

The default command is read-only preflight with temporary candidate files.
Unknown managed-file edits, incompatible effective overrides and an original
configuration that cannot restart safely stop the upgrade. Historical pristine
v0.33 has a PHP filter parsing defect: CI checks safe refusal, not a successful
runtime upgrade of that broken baseline.

Apply backs up configuration, helpers, consistent database data and active bans
before replacement. It preserves local `jail.local`/whitelists and validates
preserved overrides, without a global firewall flush or Docker/nftables restart.
Post-backup failures attempt rollback; rollback can also fail. Keep independent
console access and private backups. Exact remaining ban-time restoration and
uninterrupted service are not guaranteed.

Read the complete [upgrade and rollback contract](releases/v0.34/docs/UPGRADE-v033-v034.md)
before apply. Do not substitute the clean installer for this workflow.

## ✅ Tests and publication safety

```sh
python3 scripts/test-publication-safety.py
python3 scripts/check-publication-safety.py
python3 scripts/check-publication-safety.py --staged
python3 releases/v0.34/tests/test_release_static.py
```

An optional local hook can be installed with
`sh scripts/install-publication-hook.sh`; existing hooks are not replaced.
The [CI workflow](.github/workflows/ipv6-tests.yml) also exercises real Fail2Ban
and nftables in Linux namespaces, upgrade/reapply/rollback, synthetic local
overrides, filters and binary-safe evidence mail. Upgrade fixtures simulate
systemd and cron; they do not prove a real reboot or external Docker traffic.

The [publication policy](docs/PUBLICATION-SAFETY.md) explains the heuristic gate
and its limits. It reports locations/types without matched values. A clean HEAD
is not a historical purge. Keep production logs, credentials, configurations,
backups and private compatibility reviews outside Git, CI and packages.

## License

MIT License — see [LICENSE](releases/v0.34/docs/LICENSE).

## 👤 Author

**Peter Bakič**  
vibes coder · self-hosted infra & security

Current maintenance, documentation and regression work: **Codex (OpenAI)**.
Earlier versions credited **Claude Sonnet 4.5 Thinking**; that historical
contribution remains acknowledged.

## ☕ Support

- [Buy me a coffee](https://www.buymeacoffee.com/peterdelac)
- Star this repository ⭐
- Report issues and contribute synthetic reproductions — never private exports.

---

**v0.34-dev — tested development baseline, not a final release.**
