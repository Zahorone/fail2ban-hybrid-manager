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

### Tests

- IPv6 synchronization parser and disposable nftables namespace tests.
- Wrapper IPv4/IPv6 set resolution tests.
- Trusted-probe positive and negative scope tests.
- Binary nginx log mail evidence and benign PHP-error tests.
- Static checks forbidding global `flush ruleset`.
- Optional Easy!Appointments scope, refusal and backup/restore tests.

The historical v0.33 changelog remains in `releases/v0.33/docs/CHANGELOG.md`.
