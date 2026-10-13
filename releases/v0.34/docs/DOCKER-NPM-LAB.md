# Disposable ARM64 Docker + NPM validation

This is a manual test recipe, not a profile migration tool. Preserve the successful
core VM snapshot. **Do not rerun fresh install on its complete core profile.**
Adding web/Docker profiles to an existing manager is not currently implemented as
a reviewed transactional operation. Use a separate clean Ubuntu 26.04 ARM64 VM,
or a clone of a snapshot taken **before** installing the manager. Do not restore
an old snapshot over the successful evidence VM or run this on production.

The existing core clean-install/reboot evidence does not establish Docker/NPM,
external IPv6, or packet-drop success. Neither does this recipe passing static CI.

## 1. Isolated topology and Docker prerequisites

Keep a VM console available. Use a host-only network (preferred), or an explicitly
isolated shared VM network, with a **separate client** and management path. No
bridged/public interface, router port forwarding, public DNS, TLS/DNS credentials
or copied production database. Banning a client address blocks its other traffic
too; never ban the console/SSH/admin client, NAT gateway, VM host or Docker bridge.
The control client must have a different server-observed source address.

On the new VM, install Ubuntu's packages, not a second Docker CE/snap stack:

```sh
sudo apt-get update &&
sudo apt-get install -y docker.io docker-compose-v2 git ca-certificates python3 curl tcpdump &&
sudo systemctl enable --now docker &&
sudo docker version &&
sudo docker compose version &&
sudo docker info --format '{{.ServerVersion}} {{.Architecture}}'
```

Stop on package/daemon errors. If packages have no candidate, inspect `apt-cache
policy docker.io docker-compose-v2` and repository configuration; do not silently
replace the daemon or disable its packet filtering. Keep package versions and
firewall baseline privately. Docker can create its own iptables/nft NAT rules;
do not flush them or run global nft persistence over the live daemon. Require
Docker **28 or newer** for the documented localhost publish isolation; older
engines have a same-L2 localhost-publish exposure caveat.

Obtain the reviewed repository using the guarded download procedure in
[FRESH-INSTALL](FRESH-INSTALL.md), record its commit, and enter
`releases/v0.34/examples/docker-npm-lab`. These Compose files are JSON (supported
Compose syntax), so their safety contracts can be tested without a YAML library.
Both image tags and multi-architecture index digests are pinned. ARM64 availability
and public registry digests were checked on 2026-10-13; a pull is still required.

```sh
read -r -p 'VM host-only/shared IPv4 address: ' F2B_LAB_BIND4
export F2B_LAB_BIND4
ip -br address
sudo ss -lntp
sudo install -d -m 0700 /opt/f2b-npm-lab
sudo --preserve-env=F2B_LAB_BIND4 docker compose -f compose.json config
sudo --preserve-env=F2B_LAB_BIND4 docker compose -f compose.json pull
sudo --preserve-env=F2B_LAB_BIND4 docker compose -f compose.json up -d
sudo --preserve-env=F2B_LAB_BIND4 docker compose -f compose.json ps
```

Review the resolved bindings **before** `up`. The address must belong to the test
interface, not a wildcard/public address. Abort on any command failure. Port 81
is loopback-only; HTTP 8088 binds only the selected VM address; backend has no
published ports. There is no TLS listener or mounted Docker socket.

Open NPM from the VM itself at `http://127.0.0.1:81`, or use a private SSH tunnel
from the management machine to VM loopback port 81. Do not publish admin to the
test network. Complete initial admin setup locally; do not commit credentials,
NPM `/data`, certificates, logs or resolved Compose output. Confirm the client
cannot connect directly to VM port 81 before proceeding.

## 2. Create real NPM traffic before manager installation

In NPM create a Proxy Host:

- Domain: `test.example` (reserved test name; no DNS changes).
- Scheme `http`, Forward Hostname `backend`, Forward Port `80`.
- Public access, no TLS, no cache, no access list or exploit blocking for this
  disposable baseline. No custom forwarded-IP headers or trusted-proxy overrides.

From the **separate test client**, enter the VM test IPv4 address locally:

```sh
read -r -p 'VM test IPv4 address: ' F2B_SERVER4
curl -4 --noproxy '*' --connect-timeout 3 --max-time 5 \
  -H 'Host: test.example' "http://$F2B_SERVER4:8088/"
```

Require HTTP 200. From a different control client, require HTTP 200 too. On the VM:

```sh
sudo find /opt/f2b-npm-lab/data/logs -maxdepth 1 -type f -name '*access.log'
sudo tail -n 5 /opt/f2b-npm-lab/data/logs/proxy-host-*_access.log
```

Confirm a real `proxy-host-*_access.log` contains the test client's **actual
server-observed source**, not loopback, a shared NAT gateway or Docker proxy IP.
Do not fabricate log files to activate jails. NPM 2.16 default traffic uses
`fallback_http_access.log`, not necessarily `fallback_access.log`; proxy-host
logs avoid assuming the old fallback filename. Only log-backed jails will be
selected. Do not require 13 jails or claim every web jail was covered.

For IPv6, first establish a reachable non-link-local VM/client IPv6 pair on the
isolated network. If unavailable, record IPv6 **not tested**; do not treat a
loopback curl or IPv6 set membership as external connectivity. On the VM:

```sh
read -r -p 'VM test IPv6 address: ' F2B_LAB_BIND6
export F2B_LAB_BIND6
sudo --preserve-env=F2B_LAB_BIND4,F2B_LAB_BIND6 docker compose \
  -f compose.json -f compose.ipv6.json config
sudo --preserve-env=F2B_LAB_BIND4,F2B_LAB_BIND6 docker compose \
  -f compose.json -f compose.ipv6.json up -d
```

The override enables a dual-stack user-defined bridge and adds only the explicit
IPv6 HTTP bind. Do not edit global Docker daemon configuration for this recipe.
Use the same two-file command for later stack inspection. From the test client:

```sh
read -r -p 'VM test IPv6 address: ' F2B_SERVER6
curl -6 --noproxy '*' --connect-timeout 3 --max-time 5 \
  -H 'Host: test.example' "http://[$F2B_SERVER6]:8088/"
```

Require HTTP 200, repeat from the control client, and check that NPM logged the
real IPv6 source. If userland proxy/NAT hides it, stop automatic-detection tests
for that family and diagnose the topology; never spoof X-Forwarded-For to pass.

## 3. Install the complete selected profile once

Take a new **pre-manager** snapshot with NPM traffic working. From the reviewed
checkout's `releases/v0.34`, repeat exactly the same profile flags each time:

```sh
sudo bash INSTALL-ALL-v034.sh --docker --npm-log-dir /opt/f2b-npm-lab/data/logs --check
# If missing runtime packages were listed, explicitly install them first:
sudo bash INSTALL-ALL-v034.sh --docker --npm-log-dir /opt/f2b-npm-lab/data/logs --install-prerequisites
sudo bash INSTALL-ALL-v034.sh --docker --npm-log-dir /opt/f2b-npm-lab/data/logs --check &&
sudo bash INSTALL-ALL-v034.sh --docker --npm-log-dir /opt/f2b-npm-lab/data/logs --apply --bootstrap-stock-nft
```

Require complete state, the exact printed active log-backed profile, `ping` and
both strict checks; also reconfirm both clients' HTTP baseline:

```sh
sudo cat /etc/f2b/fresh-install.state
sudo fail2ban-client ping
sudo fail2ban-client status
sudo f2b sync check
sudo f2b docker verify
```

Any incomplete apply or foreign-firewall change stops the test. Do not bypass the
fresh guard, change the marker, rerun as an upgrade, or use the core-only legacy
recovery tool for this different profile. Preserve the failed VM for diagnosis.

## 4. Packet enforcement, separately from automatic detection

For each reachable family, start with zero bans and a new TCP connection that
returns HTTP 200. On the VM console/management path, enter **only** the dedicated
test client's source as observed in the packet/log baseline:

```sh
read -r -p 'Dedicated test client address to ban (one family): ' F2B_TEST_CLIENT
sudo fail2ban-client set manualblock banip "$F2B_TEST_CLIENT"
sudo f2b sync check
sudo f2b docker verify
sudo nft list set inet docker-block docker-banned-ipv4
sudo nft list set inet docker-block docker-banned-ipv6
```

Do not ban arbitrary documentation addresses: actual packets must originate from
the selected client. Bans are all-port protection even though HTTP is published
on 8088; a jail's `port=http,https` does not imply 8088 bypass for this action.

Repeat the exact client-family curl from section 2 using a **new connection**.
Require timeout/nonzero, while the different control client still receives 200.
An HTTP 403/404 is not a packet drop. Capture ingress during the attempt using
`sudo tcpdump -ni TEST_INTERFACE 'tcp port 8088'` (replace the interface locally)
and privately compare SYN arrival with the original successful baseline. No
new matching NPM access entry should appear for the blocked connection. A timeout
alone can be routing/app failure: correlate ingress, set membership, control-client
success and absence of delivery/access entry. If needed, obtain narrowly scoped
nft trace evidence under separate approval; do not add broad trace/flush rules.

Unban via the VM console, then run the normal reconciler explicitly:

```sh
sudo fail2ban-client set manualblock unbanip "$F2B_TEST_CLIENT" &&
sudo f2b sync enhanced &&
sudo f2b sync check &&
sudo f2b docker verify
```

Require the same client's new curl to return 200 again and the address to be
absent from all applicable jail/shared sets. The unban hook intentionally defers
shared-set removal; cron reconciles every minute. Do not call that expected delay
a failed unban, and do not remove nft elements by hand. Repeat independently for
IPv4 and IPv6, then optionally ban both simultaneously and test reboot persistence
only after the individual baseline/ban/unban tests succeed.

## 5. Real log → filter → ban pipeline (after manual enforcement passes)

Confirm `f2b-webshell-sweep` is active. From the dedicated client, request three
different missing paths within its 30-second findtime, for example
`/lab-missing-one.php`, `/lab-missing-two.php`, `/lab-missing-three.php`, through
`Host: test.example`. Require real HTTP 404 log entries; do not send executable
payloads, credentials or probes to anything outside this disposable stack.

Watch privately: the NPM proxy access log, Fail2Ban Found/Ban entries, the jail's
ban list, `/var/log/f2b-docker-sync.log`, shared set membership, then a new curl
timeout. A different active jail may ban first; record the actual jail rather than
claiming sweep success. The Nginx backend only serves static files; no PHP runtime.

Nginx access buffering, Fail2Ban polling and action scheduling can delay detection;
the ban hook updates the shared Docker set immediately once its action runs.
Record stage timestamps and stop diagnosis at the first missing stage. A request
already in progress is not a new blocked connection. Do not globally flush or
weaken filters to accelerate tests. Unban the test client from **each jail that
actually banned it**, reconcile normally and verify control/test recovery. Stop
repeating requests once a ban is observed; keep all packet captures, logs, addresses,
credentials and resolved Compose/runtime exports outside the public repository.

## Primary references

- [NPM setup and ARM64 support](https://nginxproxymanager.com/setup/)
- [NPM 2.16.0 release](https://github.com/NginxProxyManager/nginx-proxy-manager/releases/tag/v2.16.0)
- [NPM 2.16 fallback log configuration](https://github.com/NginxProxyManager/nginx-proxy-manager/blob/v2.16.0/docker/rootfs/etc/nginx/conf.d/default.conf)
- [Official Nginx image tags and architectures](https://github.com/docker-library/official-images/blob/master/library/nginx)
- [Docker published-port isolation and localhost caveat](https://docs.docker.com/engine/network/port-publishing/)
- [Docker user-defined IPv6 bridge networking](https://docs.docker.com/engine/network/drivers/bridge/)
- [Ubuntu Compose v2 package](https://packages.ubuntu.com/resolute/docker-compose-v2)
