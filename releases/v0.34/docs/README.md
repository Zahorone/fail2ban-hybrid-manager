# 🚀 Fail2Ban Hybrid Manager v0.34-dev

**Transactional Upgrade & Publication Safety Edition — development candidate.**
This baseline is not `v0.34-rc1` or final v0.34. Test installation and recovery
on disposable supported Linux hosts before any approved canary apply.
Green namespace CI is not a production or reboot certification.

## 📊 Terminal report styles

`sudo f2b report attack-analysis` displays the graphical schema-2 report with
sections, bounded-sample top paths/candidates, typed ban events and a UTC timeline.
`sudo f2b report attack-analysis short` retains the compact summary. Both accept
one `--npm-only` or `--ssh-only` flag; `short` and the scope may occur in either
order. Unknown or duplicate arguments fail, rather than silently changing scope.

```sh
sudo f2b report attack-analysis --npm-only
sudo f2b report attack-analysis short --ssh-only
```

The current ban snapshot and explicitly labelled all-jail event/timeline sections
remain global in either scope; the scope selects the HTTP/SSH-specific sections.
Query values are omitted from top paths, terminal controls are escaped, and ANSI
colors are TTY-only (`NO_COLOR` and `TERM=dumb` disable them). JSON/CSV remain pure
machine output. See [scoped reporting upgrade](REPORTING-ONLY-HOTFIX.md).

## 🛡️ What's new

- Fail2Ban's upstream family-aware `nftables-multiport` shim selects IPv4/IPv6
  actions; local overrides map them to `f2b-<jail>` and `f2b-<jail>-v6`.
- Recidive has separate family sets. Docker synchronization uses active-ban union
  membership so another jail's shared ban is not removed prematurely.
- Normal updates reject global `flush ruleset` and do not delete live nftables
  tables. The transactional upgrader changes only owned firewall state.
- Binary-safe evidence mail reads nginx error logs containing NUL or other bytes.
- `nginx-php-errors` detects explicit PHP-CGI injection, command execution,
  backdoors, inclusion and SQL injection — not ordinary warnings/fatals or 5xx.
- `f2b-exploit-critical` detects precise CGI traversal-to-shell, PHP-CGI
  `allow_url_include` plus `auto_prepend_file=php://input`, exact credential paths,
  known webshell basenames and executable writes in upload-like request paths.
  One match receives a 365-day ban; error logs use `tail` to avoid historical replay.
- `f2b-webshell-sweep` detects repeated final-404 missing executable probes,
  excluding legitimate root/nested WordPress core endpoints, redirects and
  duplicate error-log evidence. See [webshell sweep](WEBSHELL-SWEEP.md).
- Botnet, fuzzing, recon and medium-access rules remain bounded to relevant NPM
  fields/evidence, not generic words in URLs or routine service errors.
- Health-probe exclusions affect reporting only, never bans or enforcement.
- Upgrade packages include checksums, commit provenance, preflight, private
  backups, runtime verification and automatic/manual rollback.

Canonical [filters](../filters), [actions](../actions) and [scripts](../scripts)
are public product components. Deployment exports and private reviews are not.

## 📦 Clean installation

On a **fresh disposable Debian/Ubuntu systemd host** (amd64/arm64), run read-only
checks first. Ubuntu 26.04 ARM64 detection is not VM/reboot certification.
From a trusted current source checkout:

```sh
cd releases/v0.34
sudo bash INSTALL-ALL-v034.sh --check
sudo bash INSTALL-ALL-v034.sh --install-prerequisites
sudo bash INSTALL-ALL-v034.sh --check
sudo bash INSTALL-ALL-v034.sh --apply --bootstrap-stock-nft
```

Default/`--check` is read-only. Package installation and manager apply require
their explicit flags. Apply backs up verified stock nftables configuration and
writes owned persistence without executing a global flush. Unknown configuration,
existing managed state and incomplete reruns are refused; no cleanup is performed.
Only core `recidive`/`manualblock` jails are enabled by default. Select SSH, Docker,
NPM real-log and mail options explicitly and repeat them during setup/check/apply.
Missing traffic logs are never fabricated and disabled jails are listed honestly.
Shipped `ignoreip` defaults contain loopback only. See the full
[fresh-install dependency/profile/recovery contract](FRESH-INSTALL.md).

## 🔄 Upgrade and rollback

Supported existing v0.33 / v0.34-dev installations use the **package workflow**,
not the clean installer. From a clean committed repository checkout:

```sh
python3 releases/v0.34/scripts/build-upgrade-package.py /tmp/f2b-upgrade.tar.gz
python3 scripts/check-publication-safety.py --archive /tmp/f2b-upgrade.tar.gz
```

Use a new archive path. Verify its SHA-256 against the trusted build result,
extract into a new directory and run `sha256sum -c SHA256SUMS`. From that package:

```sh
sudo /usr/bin/python3 scripts/upgrade-v033-v034.py
# Approved maintenance window only:
sudo /usr/bin/python3 scripts/upgrade-v033-v034.py --apply
# Exact backup path printed by apply:
sudo /usr/bin/python3 scripts/upgrade-v033-v034.py --rollback /EXACT/PRINTED/BACKUP
```

- **Preflight:** read-only checks with temporary candidates. Unknown managed-file
  edits, effective filter conflicts, custom DB paths or an unsafe restart baseline
  stop progress instead of being silently overwritten.
- **Backup:** root-only configuration/helpers, ownership/ACLs/xattrs, consistent
  SQLite data, active bans/timed records, firewall and scheduler diagnostics.
- **Apply:** preserve local `jail.local`, whitelist and unrelated overrides;
  validate managed `.local` coexistence, replace individual files, test/reload
  Fail2Ban and verify bans, Docker membership and foreign firewall invariants.
  No global flush, Docker restart or nftables reload is performed.
- **Recovery:** any post-backup apply failure attempts scoped automatic rollback.
  If that also fails, use the printed backup and console access. Manual rollback
  verifies checksums and restores owned files/tables, not the full ruleset.

Missing restored bans may receive the current jail's full bantime. Exact remaining
expiry preservation and uninterrupted service are not guaranteed. Keep two SSH
sessions, independent console access and private backups.

The complete [upgrade contract](UPGRADE-v033-v034.md) is authoritative. Private
`--local-review` approvals must stay outside the checkout/archive and be bound
to exact package/prior-file bytes; they do not bypass runtime validation.

## 📊 Reporting and optional application hardening

Copy [reporting.ini.example](../config/reporting.ini.example) to
`/etc/f2b/reporting.ini` and replace only the local deployment copy. Trusted probe
rules require source CIDR, method, host, status and exact path; path or User-Agent
alone is insufficient. They change reporting, not Fail2Ban filters or bans.

The optional [Easy!Appointments Apache hardening](EASYAPPOINTMENTS-APACHE-HARDENING.md)
module is separately reviewed/invoked, never enabled by the installer or upgrade
automatically. See [module boundaries](MODULE-ARCHITECTURE.md).

## ✅ Tests, publication checks and release gates

From the repository root:

```sh
python3 scripts/test-publication-safety.py
python3 scripts/check-publication-safety.py
python3 scripts/check-publication-safety.py --staged
python3 releases/v0.34/tests/test_release_static.py
```

[CI](../../../.github/workflows/ipv6-tests.yml) covers syntax/static checks,
precise attack and benign fixtures, real Fail2Ban actions/nftables in Linux
namespaces, package integrity, repeated apply and fault-injected recovery.
Full transaction fixtures simulate systemd and cron. Historical pristine
v0.33 has an unescaped-percent PHP filter defect: its test proves safe refusal
and merged-candidate validity, not a successful runtime upgrade of that baseline.

The [publication gate](../../../docs/PUBLICATION-SAFETY.md) scans staged/tracked
text and archives, reporting only locations/types. Its synthetic tests contain
no production denylist. It is heuristic, does not inspect every binary secret
and does not erase history. Keep deployment records, logs, configurations,
credentials and private reviews outside Git/CI/packages.

Before RC/final promotion, still complete:

1. Green CI for the integrated commit.
2. Disposable-host clean install and representative v0.33 upgrade/rollback.
3. Reboot persistence and end-to-end IPv4/IPv6 Docker enforcement tests.
4. Approved canary observation and false-positive/mail/report review.
5. Immutable `v0.34-rc1`, then final v0.34 only after release criteria pass.

See [validation scope](CANARY-VALIDATION.md). No deployment or release promotion
is implied by these commands or documentation.

## 👤 Credits and license

Project author: **Peter Bakič**. Current maintenance, documentation and regression
work: **Codex (OpenAI)**. Earlier Claude Sonnet 4.5 Thinking contributions remain
acknowledged as historical work. [MIT License](LICENSE).
