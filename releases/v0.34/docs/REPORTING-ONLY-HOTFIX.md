# Reporting-only hotfix for existing v0.33/v0.34 wrappers

This changes reporting code, not enforcement. No production files/logs/addresses
are needed to develop or test it; public tests use synthetic examples only.

## Findings

- Trusted-probe filtering was wired into only part of attack reporting. HTTP
  status matching could read upstream rather than final status in proxy logs.
- `cat ... | tail` selected by file/rotation order before timestamps were sorted;
  some sections labelled 24h read all records or calendar-day approximations.
- Whole-line pattern searches counted ordinary `curl` User-Agent text as RCE and
  normal application/WordPress paths as exploits. Overlapping categories were
  added together as if they were independent attempts.
- Ban grep/sample logic mixed new, restored and extended bans and omitted IPv6.
- Summing jail counts was labelled unique IPs; shared addresses were counted
  repeatedly. Active bans and event volume were used for unsupported health or
  defence-effectiveness claims. Audit API errors could become empty/clean output.
- JSON/CSV reports included display headers. Legacy report routing could overwrite
  a failed report's exit status when releasing its lock. Version/help still claimed
  IPv4-only Docker verification after the dual-family diagnostic hotfix.

## Schema 2 semantics

The existing `f2b-report-filter.py` now also provides the canonical report engine;
its original stdin filtering interface remains compatible. Report entrypoints call
it directly, so raw HTTP counts, exclusions and security views use one parser.
Unified commands: `report attack-analysis` (including existing scope flags),
`report timeline`, `report daily`, `monitor trends`, `report json`, `report csv`,
`audit`, `audit-silent`, `stats-quick`, and version metadata. CSV intentionally
represents a current per-jail active-ban snapshot, not a 24h event export. Timeline
and trends are pure JSON with typed event counts; trends separates Found, new,
restored, extended and unban events for 1h/6h/24h, without intensity verdicts.
Existing CLI command names/flags remain; legacy JSON keys and human report layout
are intentionally replaced by schema 2. Consumers must adapt to these documented
keys. Other monitor commands (top-attackers, jail-log, watch, show-bans, status)
retain their existing implementation and are outside this reporting hotfix.

Known HTTP plain and gzip rotations are streamed, parsed and compared in UTC;
only the latest chronological records inside `[now-24h, now]` enter the bounded
sample. Selection happens **before** trusted-probe exclusions. File-name order
does not define chronology. Same-timestamp ties use file/line order deterministically,
not a claimed causal sequence. Records are not heuristically deduplicated across
rotations: repeated lines can be real repeated requests. Stream/backend logs are
not HTTP sources. Missing, unparsed, invalid, old and future coverage is explicit.
Missing matching files are marked unavailable; window event counters/timeline
values are null. An empty sample size remains zero (nothing selected), not a
claim of zero traffic. Log presence does not prove complete 24h coverage. Duplicate
record identities are unavailable: repeated identical events are not deduplicated.

NPM timestamps carry their offsets. Naive Fail2Ban times use the configured IANA
zone or system `/etc/localtime` TZif data, including historical DST. Ambiguous or
nonexistent naive local times are counted as coverage gaps, not silently guessed;
explicit-offset timestamps remain distinguishable. Configure the actual daemon
log timezone if it differs from the system timezone; the tool never changes it.

`http_window` describes all observed parsed records in the exact window.
`http_sample.raw_records` is the **unexcluded parsed sample**, not all traffic or
all raw lines. Raw HTTP errors remain visible even for explicitly trusted probes.
Included error fractions and candidate fractions have their own explicit sample
denominators; an empty denominator gives null, not an invented zero rate.
Candidate categories inspect request targets only, never ordinary UA/referer text.
Overlapping category hits are not summed as distinct attempts. HTTP errors,
candidate indicators, Fail2Ban Found signals and Ban records are separate measures,
not additive independent attacks and not proof of compromise or successful blocking.

Fail2Ban new Ban, Restore Ban, Increase Ban and Unban records are counted separately.
The recent-ban sample is selected after chronological sorting and by ban-event kind,
so later Found lines cannot displace all recent bans. Found timeline bins cover
exactly 24 rolling UTC hours; average is observed Found records / 24, not integer
truncation or an inferred traffic/defence metric. SSH summaries use configured
Fail2Ban SSH jail signals, not a claimed count of every raw authentication attempt.

Current state distinguishes `ban_records_across_jails`, `unique_ipv4`,
`unique_ipv6`, and `unique_union`. The same address in multiple jails contributes
multiple records but one union member. Active bans alone never make audit fail.
Audit success means runtime reads succeeded, **not** that enforcement is verified.
API/report/config failures return nonzero and do not emit ALL CLEAN/success data.
JSON/CSV are machine-readable without display headers. Installed release/version
metadata is retained; reporting schema 2 is not a release upgrade. Diagnostic
labels describe the installed route/capability, without claiming packet enforcement.

## Explicit, private reporting configuration

Review `config/reporting.ini.example` and configure `/etc/f2b/reporting.ini`
locally if needed. The hotfix never overwrites that file, installs example rules,
changes a whitelist, or modifies filter/mail/reconciler settings.

`[reporting]` supports absolute `npm_log_dir`, absolute `fail2ban_log` prefix,
`fail2ban_timezone = system` or an IANA name, `sample_limit` (1..100000), and
`ssh_jails`. Configured NPM path overrides the wrapper's existing fallback path.
Missing config means defaults and **no probe exclusions**. Reporting API paths
are not automatically benign and trusted sources alone do not suppress records.
Malformed, unreadable, unknown-section and unknown-option configurations fail
preflight/reporting rather than silently falling back. Validate private changes:

```sh
sudo /usr/bin/python3 scripts/f2b-report-filter.py --validate-config --config /etc/f2b/reporting.ini
```

Each `[trusted-probe ...]` exclusion requires all five exact conditions:
source network, method, host, final HTTP status and configured full request target.
Use separate explicit IPv4/IPv6 rules as appropriate. Heartbeat/sysinfo/audit paths
are merely examples, not built-in exemptions. Query strings are part of the exact
target. Dangerous/candidate targets remain visible even if a rule was misconfigured
to include them. Nothing affects Fail2Ban detection, notifications, bans or nft rules.
Keep real values/logs/generated reports private and outside the repository.

## Scoped deployment

From the exact reviewed checkout, enter `releases/v0.34` and first run:

```sh
sudo python3 scripts/install-reporting-hotfix.py
```

This stages private temporary code, compiles the helper, validates the actual static
report config path and wrapper Bash syntax, and checks patch scope. It does not
collect production logs or mutate installed code/config/runtime. A dynamic config
path, unknown local report helper or unrecognized routing is refused for review.
Dependencies are system Python 3.9+ with zoneinfo/timezone data and the distro
Fail2Ban CSocket module, plus Bash; no packages are installed. Git history is used
only to recognize the published old helper during deployment, not by runtime reports.

Only after preflight PASS and operator approval:

```sh
sudo python3 scripts/install-reporting-hotfix.py --apply
sudo f2b version --short
sudo f2b version --json
sudo f2b help
sudo f2b audit
sudo f2b report json
sudo f2b report daily
```

Apply creates a root-private code backup/checksum manifest through the existing
scoped code-transaction utility, installs the report helper before redirecting
report entrypoints, and restores original code on failure. It modifies only ten
report/audit/version entrypoints, exact help labels, and narrowly scoped report
error-routing/cache handling. Every other wrapper function/constant is preserved,
including port and diagnostic hotfixes and local changes. The existing installed
verifier, standalone diagnostic checker, reconciler, filters, jail/whitelist config,
mail actions, persistence, cron and database are not changed. No services restart,
package installation, forced sync, orphan cleanup or full release upgrade occurs.
The shared backup utility currently prints `Private diagnostic-code backup:`;
for this installer that directory contains only the two reporting targets.
To explicitly roll back, use the exact private path printed by your apply:

```sh
sudo python3 scripts/install-reporting-hotfix.py --rollback /var/backups/EXACT-PRINTED-BACKUP-DIRECTORY
```

Rollback verifies the two-target manifest and before/after checksums and refuses
intervening local code edits; wrapper is restored before the old helper. Neither
apply nor rollback overwrites reporting.ini. Separate fresh/recovery/canary source
flows now stage the compatible report helper when installing the newer wrapper;
the reporting-only command does not invoke those workflows or replace their verifier.

`audit-silent` appends only a successful runtime-count report to its existing audit
output log; a failed runtime read does not append a fake clean result. Report
runtime failures remain nonzero after wrapper lock cleanup. An installed legacy
IPv4 diagnostic is labelled legacy rather than advertising a not-installed checker.

## Verification scope

Synthetic tests cover rotated plain/gzip ordering, offsets/DST/cutoffs, latest-N
denominators, explicit probe fields, API endpoints with actual suspicious targets,
curl UA neutrality, restored/new/extended records, ban-record versus union counts,
machine-readable output and legacy wrapper error routing. Private Linux fixtures
exercise code deployment/rollback against real Fail2Ban, preserving other wrapper
functions and enforcement files. This is not production-data or packet-test evidence.
