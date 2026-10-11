# v0.34 development validation

## Live canary evidence

Operator deployment records, counts, host identifiers, backup locations and
runtime evidence are private and maintained outside the repository. Public CI
uses synthetic configurations only. A successful operator report does not by
itself establish clean-install, reboot or external IPv6 packet-test success.

## Automated fixture evidence

The regression suite covers Fail2Ban's comma-separated action format, one
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
