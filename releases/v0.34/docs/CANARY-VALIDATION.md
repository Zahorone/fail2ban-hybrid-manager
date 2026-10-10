# v0.34 development validation

## Live canary evidence

The operator reported a successful deployment on `objednavky` on 2026-10-10
using commit `63f8f90ebd390a36f6923a664c1a138965d63c89`.
The reported output was:

```text
PASS preflight: 12 jails / 209 active bans
Backup: /var/backups/f2b-v034-canary/v034dev-to-227c393-20261010-150806-296436
PASS canary updated through 227c393
Docker and nftables were not restarted; no ruleset was loaded or flushed.
```

This is evidence for the narrow existing-v0.34-dev canary workflow with that
host's Fail2Ban 1.0.2 configuration. It does not establish clean-install or
v0.33-to-v0.34 upgrade success. No synthetic IPv6 attack or ban was generated;
the pass verifies effective family properties and membership of actual live
bans, not a new IPv6 end-to-end client attack.

## Automated fixture evidence

The regression suite covers the server's comma-separated action format, one
nft action with IPv4/IPv6 properties (including `addr6-set-<name>`), zero-ban
lazy sets, and rejection of missing sets for a family with a real ban.
It verifies the Docker hook command and read-only Docker membership failure
versus apply-only reconciliation of real bans.

The minimal-package fixture runs preflight, apply and rollback with local
configuration, a local filter override, database content and IPv4/IPv6 ban
snapshots. These are filesystem/mocked-command tests, not running Fail2Ban or
nftables services. Standard-upgrade transaction tests exercise verifier
success, read-only preflight and automatic rollback after verifier failure.

## Conditions still required before rc1

- Green CI for the integrated commit, including Linux Fail2Ban configuration
  tests and nftables tests in a disposable network namespace.
- Clean install on a disposable supported Linux host.
- Full v0.33 upgrade and rollback on a disposable representative clone,
  preserving local overrides, database and active bans.
- End-to-end IPv4 and IPv6 enforcement and Docker forwarding checks in that
  disposable environment, including both families starting with zero bans.
- Review of canary logs and operational behavior after the observation window,
  including absence of WordPress false positives and mail/reporting regressions.

The package remains `0.34-dev`. No rc1 or final release is declared by this
validation record.
