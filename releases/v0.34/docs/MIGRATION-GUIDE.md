# v0.33 to v0.34 migration status

The v0.34 migration workflow is not yet approved for use on production
servers. Running the clean-install component scripts over a live v0.33 system
is not a supported upgrade path.

## Required upgrade properties

- Preflight must validate Fail2Ban, nftables, Docker and all local overrides.
- Backups must include `/etc/fail2ban`, project-owned nftables schemas,
  installed helpers and systemd drop-ins.
- Site-specific mail, `ignoreip`, ports, log paths and reporting rules must not
  be replaced by public defaults.
- Existing IPv4 and IPv6 bans must remain effective throughout the migration,
  or be restored in the same validated nftables transaction.
- Docker and unrelated firewall tables must not be flushed or restarted.
- Configuration must pass `fail2ban-client -t` and `nft -c` before activation.
- A tested rollback must return the complete v0.33 state.

## Test gate

The upgrade is releasable only after a disposable Ubuntu 24.04 v0.33 fixture
passes upgrade, service restart, reboot and rollback tests while preserving a
known set of IPv4/IPv6 bans. Until then, stop after preflight and use no v0.34
script on a production host.
