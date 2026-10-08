# IPv6 maintenance patch for v0.33

The original Docker synchronization read only the legacy `f2b-*-v6` sets.
Fail2Ban's stock nftables action can instead use `addr6-set-<jail>`.
Consequently, synchronization could remove an active IPv6 Docker ban.
The original recidive action also wrote IPv6 addresses into an IPv4 set.

This patch:

- takes the IPv6 ban union from Fail2Ban's runtime, using the longest remaining
  ban when multiple jails ban the same address;
- reconciles the shared Docker set and the dedicated IPv6 recidive set;
- uses explicit remaining timeouts, with renewable 30-day leases for permanent
  Fail2Ban bans (regular synchronization must remain enabled);
- defers IPv6 hook unbans to synchronization so one jail cannot clear another's ban;
- resolves stock IPv6 set names in wrapper diagnostics and canonicalizes exact IP
  searches; IP validation no longer adds/removes addresses on loopback;
- sends recidive evidence from the Fail2Ban log instead of unrelated web logs.

An unreadable runtime snapshot or unsupported nft interval representation aborts
synchronization rather than treating it as an empty ban list. Network namespace
tests cover finite expiry extension, repeated synchronization, a newly active ban,
unban, and permanent leases. This does not prove external IPv6 reachability or
that every exposed service has a working drop rule.

## Existing v0.33 installations

Use `sudo python3 scripts/upgrade-ipv6.py` from this release directory. It checks
configuration and runs isolated nftables tests before changing files. It backs up
the wrapper, helper, hook, and recidive action, reloads only recidive, then runs
IPv6 synchronization twice. Docker is not restarted. Existing local recidive action
overrides must be reviewed before using this updater.

Do not rerun the full installer just to apply this patch: its historical firewall
rebuild steps have a wider scope. Published v0.33 tarballs are not changed by a
source commit; use this checkout until a new release is published.

After applying, check a known active address with `sudo f2b find <IPv6>`, then
repeat after the scheduled sync and after reboot. Test blocked traffic from a
separate IPv6 host before claiming end-to-end enforcement.
