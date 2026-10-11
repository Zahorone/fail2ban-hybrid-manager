# v0.34 managed core and optional modules

This is the interface/design boundary for a later modular installer, not an
implementation of a new installer UI or an automatic discovery/apply engine.

## Version boundary agreed 2026-10-11

v0.34 is the intended shared "point 0" baseline for supported installations.
Finish its current fixes and compatible, backed-up upgrade first. The public
plan does not record private deployment state or claim a final release.
Preparing this plan does not authorize a remote production deployment.
Evaluate each installation's preflight and rollback readiness before a separately
approved maintenance-window apply. Between v0.34 and v0.40, refine the existing
base rather than incorporating a large installer redesign into v0.34.

The unified tool belongs to v0.40, with exactly three entry choices:

1. Install.
2. Update.
3. Manage modules (add/remove).

Module selection, including optional hardening, is manual. Only simple
prerequisite/compatibility checks of selected modules are required; automatic
discovery of every application is not a requirement. A persistent inventory
records installed core/module versions, settings and managed files. Update
changes only installed components, not every available module. Backup, tests
and rollback are shared infrastructure across all three operations.

v0.40 development is LOCAL ONLY until it is final AND publication is explicitly
authorized. When that work starts, use a separate local working copy, preserve
local work safely, disable automatic pushing and do not mix its implementation
into this pushed v0.34 branch. No remote v0.40 branch, PR, tag, release, CI upload
or remotely published archive containing its development code is permitted.
This document publishes only the v0.34 boundary/roadmap, not v0.40 code. There is
no need to create or implement the v0.40 working copy now.

## Independent selection axes

| Axis | Responsibilities | Current scope |
| --- | --- | --- |
| Core | Fail2Ban policies, managed filters, nft family actions, ban lifecycle, reporting, upgrade/rollback | v0.34 manager |
| Application | Application-specific private files and legitimate routes | Optional Easy!Appointments recipe; WordPress fixtures, no automatic WordPress mutation |
| Webserver/proxy | Enforcement for a selected Apache/Nginx/NPM backend and real filesystem/vhost layout | Explicit Easy!Appointments + Apache module only |
| Deployment | Docker ports, networks and ban enforcement | Existing manager Docker hooks; not an application selector |

An application can run behind NPM with an Apache backend in Docker. These are
combinable axes, not mutually exclusive installer choices. Manual selection and
checks of selected modules must never silently enable application changes.

## Managed filter interface and override coexistence

`filters/f2b-exploit-critical.conf` owns precise credential/traversal probes and
exact IOCs. `filters/f2b-webshell-sweep.conf` owns executable-file final-404
matching and nested WordPress core exceptions. Their jail policies remain one
hit / 365 days and three hits / 30 seconds / 365 days respectively. Existing
bans are not removed when a classification changes.

The upgrade manifest declares `filter_override_policy` with the versioned
`scan-review-20261011-v1` semantic contract. A local comment marker is provenance
information, NOT authentication or permission to rewrite arbitrary contents.
Both scan-review `.local` paths are outside the install map. Coexistence is the
explicit idempotent migration strategy: retain exact local bytes, install the
managed `.conf`, and validate the combined Fail2Ban interpretation before apply.
After reload, validate both the config dump and typed expressions read from the
live daemon. Stale overrides that replace new failregex, suppress a required
probe or broaden WordPress exclusions fail with jail, request, family and
override path. Never bypass this failure by deleting a site override blindly.

All `/etc/fail2ban` contents are in the transaction backup; rollback restores
original `.conf` and `.local` bytes and original DB/runtime bans. No Apache files
are in the manager target map or restore roots. This keeps an existing separate
Apache guard intact through manager apply and rollback.

CI covers structural representatives of the reported server `.local` layout:
`%(known/failregex)s` plus marked probes and `%(known/ignoreregex)s` plus nested
WordPress exceptions. Without an actual server file export, these fixtures are
not a claim of byte-exact reproduction of either server's custom overrides.
The real server's read-only preflight is the authority for compatibility.

## Optional module contract (v0.40 installer interface, not implemented here)

Each selectable module must declare:

- Stable id/version, application scope, webserver/deployment compatibility and
  prerequisites (including Apache modules, filesystem layout and backend URL).
- Exact owned files/symlinks, preservation/conflict policy and a concrete preview
  of rendered changes before apply; no secret/domain/IP/whitelist inheritance.
- Read-only preflight and explicit apply, backup manifest, automatic failure
  rollback and an independent manual rollback command.
- Positive security tests and legitimate home/login/assets/API tests, with
  evidence distinguishing static/unit, real-service, external IPv6 and reboot.

Current opt-in recipe: `scripts/easyappointments-apache-hardening.py`, selected
explicitly for Easy!Appointments on Apache. It owns only
`easyappointments-private-{vendor,storage,config}.conf` in the chosen
`conf-available` directory and their three `conf-enabled` symlinks. It requires
an absolute safe app root, `config.php`, vendor/storage layout, a loopback HTTP
backend and a valid Apache configuration. Unknown owned files, symlink conflicts
and a pre-existing uploads `.htaccess` require manual review. It previews exact
rendered snippets, backs up those six entries, config-tests/reloads only Apache,
verifies private routes and unchanged public home/login/assets, and rolls back
on failure. It is NOT included/executed in the universal upgrade archive.

An existing scan-review config.php guard is preserved by the manager. The
optional module refuses an unknown differently rendered guard rather than
silently adopting/replacing it; explicit operator review is required.

## Evidence lifecycle

Convert observed probes to synthetic domains and documentation IP addresses,
then pair each signature with supported-application benign regressions. Keep
real client IPs, local whitelists, secrets and operator filesystem paths out of
universal defaults. A credential probe is not proof of a leak; HTTP 444 and
`trust_forwarded_proto` diagnostics are not evidence of firewall bypass.
Namespace CI uses real Fail2Ban/nftables but simulated systemd/cron; it does not
prove external IPv6 connectivity, real Apache behavior or reboot persistence.
