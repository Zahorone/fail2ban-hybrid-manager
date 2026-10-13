# Existing complete fresh NPM profile: scoped HTTP repair

Do not reinstall, rerun fresh apply, enable disabled jails, flush nftables, or
restart Docker. Preserve a VM snapshot and console access. This tool repairs the
already active web profile; it is not the missing core-to-NPM profile migration.

## Identified causes and policy boundary

- Old fresh selection used `fallback_access.log` for critical access coverage.
  NPM 2.16 creates `fallback_http_access.log`; matching only error logs could
  nevertheless enable critical and misleadingly pass ban-count synchronization.
- NPM's standard access format has one final status (`404 - GET ...`) and no
  `Sent-to` field. The old sweep expression required proxy-style extra fields.
- A direct `/.env?f2b-lab=1` request is **not** a canonical critical IOC. It belongs
  to `f2b-web-medium` (threshold six in the shipped configuration). A locally
  modified earlier server policy must not be mistaken for the fresh defaults.
  This repair does not change critical severity, thresholds or benign exceptions.

New selection includes known HTTP fallback, proxy, redirection and dead-host
access/error files only; streams, backend logs and rotations are excluded. Critical
requires both access and error sources. The dedicated runtime coverage check and
strict sync diagnostics reject an error-only active critical jail. PHP-error jails
remain intentionally error-only. New source registration uses `tail` to avoid
replaying historical requests; generate a new request after a successful repair.

## Reviewed checkout and preflight

From the repository root, fetch and select the exact reviewed repair commit supplied
with the test result, then enter `releases/v0.34`. Git history is required for this
specific repair's canonical legacy fingerprint checks, not for fresh runtime.

```sh
sudo python3 scripts/repair-npm-http.py --npm-log-dir /opt/f2b-npm-lab/data/logs
```

Default is preflight only: a private temporary merged candidate is tested and
removed, and an advisory transaction lock is used; no configuration/daemon change
or persistent backup is made. It checks complete fresh state, known managed targets,
existing active profile, real HTTP files in the original instance directory,
loaded/disk filter agreement, merged `fail2ban-client -t`, unchanged unrelated
effective settings, intended log coverage and real `fail2ban-regex` attack/benign
fixtures. Site overrides are preserved; a suppressing override is refused, not
deleted. Missing access/error files are not fabricated.

Only after preflight PASS, repeat against the identical reviewed checkout:

```sh
sudo python3 scripts/repair-npm-http.py --npm-log-dir /opt/f2b-npm-lab/data/logs --apply
sudo fail2ban-client status
sudo fail2ban-client get f2b-exploit-critical logpath
sudo python3 /usr/local/libexec/f2b-runtime-verify.py --npm-coverage
sudo f2b sync check
sudo f2b docker verify
```

Apply creates a root-private backup containing configuration with ACL/xattrs,
consistent SQLite backup, timed bans, foreign-firewall snapshot, original target
bytes and a checksum manifest. It changes only the existing fresh selection's
active-web logpaths, canonical sweep filter and runtime verifier. It tests again
and reloads **only affected active jails**, without restart. Whitelists, other
settings/jails, active jail set, timed bans and foreign rules are checked. A failure
restores the original target bytes and verifies the reload/ban/whitelist state;
if rollback verification fails, retain the private backup and VM console for
diagnosis. No blind live database restore or foreign-firewall rewrite is attempted.
Natural ban expiry during the short transaction can conservatively fail timed-ban
verification; do not delete the database or force a reinstall in response.

## New harmless critical request, after repair only

Use a dedicated disposable test client, separate from management. Establish a
successful HTTP baseline first. For one reachable family, from that client:

```sh
printf 'Disposable VM IPv4 address: '
IFS= read -r F2B_SERVER4
curl -4 --noproxy '*' --connect-timeout 3 --max-time 5 \
  "http://$F2B_SERVER4:8088/this_is_a_new_hello_world.php?f2b-lab=1"
```

Or, separately for IPv6 with an already verified reachable baseline:

```sh
printf 'Disposable VM IPv6 address: '
IFS= read -r F2B_SERVER6
curl -6 --noproxy '*' --connect-timeout 3 --max-time 5 \
  "http://[$F2B_SERVER6]:8088/this_is_a_new_hello_world.php?f2b-lab=1"
```

This is one harmless GET of an existing exact critical indicator, with no exploit
body or execution. The missing fallback path should log 404; do not assume the
first request will time out, since its log entry triggers the later ban. Check on
the VM console: new real access entry → critical Found/Ban → actual client's ban
membership → shared nft set → a **subsequent new connection** timing out while a
separate control client still succeeds. Do not spoof forwarded headers. Record
stage timestamps to distinguish Nginx buffering, polling and action latency.

Unban only the dedicated test client from every jail that actually banned it,
run `sudo f2b sync enhanced`, then strict checks and a fresh successful curl.
Shared unban is deferred until reconciliation; no manual nft element deletion.
Keep addresses, private config/backup, credentials, logs and packet captures out
of the repository. See [lab packet methodology](DOCKER-NPM-LAB.md).

## Evidence boundary

The reported Docker/NPM-profile fresh install completed with five jails, sync PASS
and HTTP 200. Manual IPv4/IPv6 bans blocked and unbans restored actual client HTTP.
The IPv6 bridge change then preserved the real IPv6 source in NPM logs. The first
automatic test exposed missing access coverage and the wrong `/.env` critical
expectation; it **did not validate automatic critical detection**. Real automatic
ban success remains pending this repair and a new exact-IOC request.

Format and filenames are based on the pinned
[NPM 2.16 log formats](https://github.com/NginxProxyManager/nginx-proxy-manager/blob/v2.16.0/docker/rootfs/etc/nginx/conf.d/include/log-proxy.conf),
[fallback configuration](https://github.com/NginxProxyManager/nginx-proxy-manager/blob/v2.16.0/docker/rootfs/etc/nginx/conf.d/default.conf)
and [dead-host template](https://github.com/NginxProxyManager/nginx-proxy-manager/blob/v2.16.0/backend/templates/dead_host.conf).
