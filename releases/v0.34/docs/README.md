# Fail2Ban Hybrid Manager v0.34-dev (development candidate)

This directory is the working candidate for v0.34. It is not approved for
production or canary deployment until the clean-install and v0.33-upgrade
test gates have passed.

## Security changes

- Fail2Ban's upstream `nftables-multiport` shim selects IPv4 or IPv6 actions;
  local family overrides map them to `f2b-<jail>` and `f2b-<jail>-v6`.
- Recidive uses separate IPv4 and IPv6 sets.
- Installers reject a global `flush ruleset` and do not delete live nftables
  tables as part of a normal component update.
- PHP evidence mail treats nginx error logs as text, including logs containing
  NUL or other binary bytes.
- `nginx-php-errors` bans explicit PHP-CGI injection, command execution,
  backdoor, inclusion and SQL-injection indicators. Ordinary PHP fatal errors,
  warnings and generic HTTP 5xx responses are intentionally not ban reasons.
- Attack reporting can omit configured service health probes. Reporting rules
  require source CIDR, method, host, status and exact path; they do not change
  Fail2Ban filters or bans.
- An optional, separately invoked Easy!Appointments Apache module can deny the
  private Composer vendor tree, protect storage directories and constrain
  script-like uploads. The main installer never enables it automatically; see
  `docs/EASYAPPOINTMENTS-APACHE-HARDENING.md`.
- `f2b-exploit-critical` recognizes precise CGI traversal-to-shell and PHP-CGI
  `allow_url_include` plus `auto_prepend_file=php://input` requests in both NPM
  access logs and nginx error logs. One match receives a 365-day ban; historical
  error logs are registered with `tail` to prevent replay.
- The same critical jail detects exact private credential paths, known webshell
  basenames, and executable-file writes below upload-like path segments. These
  signatures remain scoped to the NPM request target.

## Trusted reporting probes

Copy `config/reporting.ini.example` to `/etc/f2b/reporting.ini` and replace the
documentation-only values. Never commit production addresses or allow a probe
only by path or User-Agent.

## Release gates

1. Unit and namespace CI.
2. Clean Ubuntu 24.04 installation test.
3. Upgrade and rollback test from an unchanged v0.33 fixture.
4. Canary with external IPv4 and IPv6 verification.
5. Immutable `v0.34-rc1` candidate, followed by final v0.34 only if unchanged.

The main installer and migration workflow remain under development. Do not run
them on a production server from this branch.

The preflight, apply and rollback command reference is in `docs/RECOVERY.md`.
