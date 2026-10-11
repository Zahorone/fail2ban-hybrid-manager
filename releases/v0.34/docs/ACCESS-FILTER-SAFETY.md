# Conservative access filters before the shared v0.34 baseline

The previous v0.34 bundle retained historical blanket rules. They are unsafe
to deploy over locally repaired filters: words in URLs were treated as scanner
UAs, normal paths/encoding as fuzzing, and generic status/HEAD as reconnaissance.
Do not apply the earlier a684ca7 archive to replace these repaired filters.

## Managed behavior

- `f2b-botnet-signatures`: explicit offensive tool tokens only in the NPM UA
  field AFTER Client/Length/Gzip and optional Sent-to. URL, host and referer text
  cannot substitute for that field. Generic bot/crawler/spider and monitoring
  agents are not attack evidence.
- `f2b-fuzzing-payloads`: NUL, concrete repeated/encoded traversal, double encoded
  traversal and encoded double backslashes. Ordinary admin/test/hello/random,
  foo/bar and percent-encoded characters/slashes do not count. Application-wide
  blanket ignores are unnecessary with these bounded signatures.
- `nginx-recon-optimized` (jail `nginx-recon-bonus`): bounded private metadata,
  credential/backup files and executable probe basenames. No generic HEAD,
  all-404, wp-admin/wp-json/wp-login or ACME-challenge bans. A HEAD of a precise
  sensitive path can still be a probe; normal HEAD monitoring is allowed.
- `f2b-web-medium`: matches bounded sensitive/exploit request targets in NPM
  access records. The stock jail reads `fallback_access.log`, so nginx error-log
  rate-limit lines are not relevant. No status alone, including 404/429/444, is
enough to count; generic admin/application routes are allowed.

Effective contracts cover these four access jails only when enabled. They do not
enable a deliberately disabled optional jail or change its installed logpaths.

Both standard and proxy access layouts follow the
[upstream NPM format](https://github.com/NginxProxyManager/nginx-proxy-manager/blob/develop/docker/rootfs/etc/nginx/conf.d/include/log-proxy.conf).
Custom or missing UA fields deliberately do not match the UA-only filter.
Supporting another format requires explicit fixtures, not a greedy fallback.
Jail thresholds, ban durations and installed logpaths are unchanged. This does
not fix or assert safety of every other historical filter in the project.

## Upgrade compatibility and evidence

`REVIEWED_PREVIOUS_SHA256` lists ten target-specific, content-reviewed prior
repairs: these four filters, two action variants, binary-safe mail, the old
IPv6 sync/hook and wrapper. The builder incorporates only those exact hashes
into `known_targets`. It does not normalize comments/whitespace on arbitrary
files, approve any file with similar keywords, or bypass unknown-file refusal.
The wrapper diff is formatting plus reporting selection, not firewall behavior.
Old hook/sync semantics are superseded by the existing v0.34 shared-family union
and locking. Locally supplied critical `.local` remains outside the install map
and is backed up/preserved; no live ban is automatically withdrawn.

The manifest declares `access_contract: npm-access-v1`. Both merged candidate
configuration and typed regexes from the live daemon are checked for required
probes and benign application/monitoring cases. A broad `.local` that restores
blanket matching fails with the jail, sample and relevant override path.

CI uses anonymized requests and nine byte-exact reviewed prior file variants
(including a wrapper reconstructed from its reviewed diff), not a full server
snapshot. The old sync helper is checksum-approved from its reviewed source;
the namespace baseline uses its repository IPv6 semantic equivalent. Critical
`.local` byte-preservation is exercised with a minimal structural/rule fixture,
not a published copy of the full production file. Apply/reapply/manual and
automatic rollback check restored file bytes, active bans and foreign NAT.

Real fail2ban-regex/Fail2Ban/nftables are tested in Linux namespaces; systemd/cron
are simulated. This is not proof of a full server configuration, external IPv6
or reboot. Actual read-only server preflight and explicit user apply remain
required. No production deployment is performed by this change.
