# v0.34 development validation

## Live canary evidence

Operator deployment records, counts, host identifiers, backup locations and
runtime evidence are private and maintained outside the repository. Public CI
uses synthetic configurations only. A successful operator report does not by
itself establish success outside the exact tested profile and steps.

## User-reported disposable ARM64 VM evidence

Ubuntu 26.04 ARM64, source commit `393abab`, core profile only:

- A genuinely clean install completed **without recovery**, with `manualblock`
  and `recidive` active and the fresh state marked complete.
- After reboot, Fail2Ban/nftables/cron were active and strict synchronization
  passed for the two jails and both address families.
- A separate earlier recovery VM test retained documentation-only IPv4/IPv6
  manual bans across reboot; unban removed both from the jail and the four
  corresponding jail/shared nft sets.

These are operator-reported results, not a reproduced CI boot test. They do not
establish Docker/NPM installation, external IPv6 reachability, actual packet
drops, all profiles, or upgrade/canary success. Preserve the core VM evidence;
use a separate pre-manager VM for the [Docker/NPM lab](DOCKER-NPM-LAB.md).

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
- Clean install on representative profiles; the core ARM64 profile above has
  user-reported clean/reboot evidence, not a full profile/platform matrix.
- Full v0.33 upgrade and rollback on a disposable representative clone,
  preserving local overrides, database and active bans.
- End-to-end IPv4 and IPv6 enforcement and Docker forwarding checks in that
  disposable environment, including both families starting with zero bans.
- Review of canary logs and operational behavior after the observation window,
  including absence of WordPress false positives and mail/reporting regressions.

The package remains `0.34-dev`. No rc1 or final release is declared by this
validation record.
