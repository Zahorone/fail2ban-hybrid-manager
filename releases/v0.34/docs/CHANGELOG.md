# Changelog

## [0.34-dev] - Unreleased

Development candidate; not approved for production deployment.

### Corrected

- Restored the upstream `nftables-multiport` family-selection shim and mapped
  IPv6 actions to `f2b-<name>-v6`.
- Kept recidive IPv4 and IPv6 actions separate.
- Removed global ruleset flushes from generated v0.34 configuration.
- Refused destructive rebuilds when a live Fail2Ban table already exists.
- Preserved existing Docker-block tables during component installation.
- Added binary-safe PHP error evidence mail using `grep -a`.
- Limited `nginx-php-errors` to explicit exploit indicators and supported both
  common nginx client/PHP-message field orders.
- Added reporting-only service-probe exclusions requiring source CIDR, method,
  host, status and exact path. These exclusions never modify bans.
- Removed site-specific public addresses from release defaults.
- Added an opt-in transactional Apache hardening workflow for confirmed
  Easy!Appointments installations. It preserves existing managed-file and
  symlink state, rejects unknown configuration, verifies the loopback backend,
  and rolls back automatically on failure.
- Added request-target-scoped CGI traversal and PHP-CGI argument-injection RCE
  detection to `f2b-exploit-critical` for NPM access logs and nginx warning/error
  logs. The managed jail override applies a one-year ban on the first match and
  tails newly added error logs without replaying historical entries.
- Added high-confidence credential-file reads, exact known webshell basenames,
  and executable upload-tree writes to the same critical jail without matching
  ordinary application POSTs or non-executable uploads.
- Added the exact `/this_is_a_new_hello_world.php` critical IOC and a separate
  WordPress-safe `f2b-webshell-sweep` jail. The sweep requires three missing
  executable GET/HEAD targets returning final 404 within 30 seconds; redirects,
  successful PHP endpoints and error-log duplicates do not count.

### Tests

- IPv6 synchronization parser and disposable nftables namespace tests.
- Wrapper IPv4/IPv6 set resolution tests.
- Trusted-probe positive and negative scope tests.
- Binary nginx log mail evidence and benign PHP-error tests.
- Static checks forbidding global `flush ruleset`.
- Optional Easy!Appointments scope, refusal and backup/restore tests.
- Twenty malicious access/error fixtures across IPv4 and IPv6 plus thirteen
  benign cases, including payload text present only in the referrer.
- Twenty-four credential, webshell and executable-upload attack fixtures plus
  thirteen benign access-log cases.
- Real missing-webshell sweep targets, IPv4/IPv6 threshold behavior, WordPress
  2xx/3xx endpoints, redirects, Referer/User-Agent and access/error duplication.
- Added a narrow transactional canary updater for existing v0.34-dev hosts at
  changeset `227c393`, including full backup, ban preservation, verification,
  and automatic rollback without restarting Docker or nftables.

The historical v0.33 changelog remains in `releases/v0.33/docs/CHANGELOG.md`.
