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

Review and pin a trusted source commit before testing. Replace `REVIEWED_COMMIT`
with that commit; a moving branch is not an immutable release.

```sh
git clone https://github.com/Zahorone/fail2ban-hybrid-manager.git
cd fail2ban-hybrid-manager
git checkout --detach REVIEWED_COMMIT
```

### 🧪 Clean install — disposable host only

Use a fresh supported Debian/Ubuntu test host with required dependencies/services.
Review local mail, log paths, Docker networking and whitelists.
Shipped whitelists contain loopback only; do not commit site-specific settings.

```sh
cd releases/v0.34
sudo bash INSTALL-ALL-v034.sh
```

This **changes the host**. The installer refuses existing managed installations
and unsafe global nftables flush configuration. Do not use cleanup flags as a
dry run or upgrade path. Full clean-install/reboot validation is still required.

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
