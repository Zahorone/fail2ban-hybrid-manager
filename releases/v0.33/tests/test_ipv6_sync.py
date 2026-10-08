import datetime
import importlib.util
from pathlib import Path
import sys
import time
from types import SimpleNamespace
import types

# Parser/unit tests do not need a local Fail2Ban installation. Prefer the real
# module when available; the installer requires it before deployment.
try:
    from fail2ban.client.csocket import CSocket as _CSocket  # noqa: F401
except ModuleNotFoundError:
    fail2ban_module = types.ModuleType('fail2ban')
    client_module = types.ModuleType('fail2ban.client')
    csocket_module = types.ModuleType('fail2ban.client.csocket')
    csocket_module.CSocket = object
    sys.modules.setdefault('fail2ban', fail2ban_module)
    sys.modules.setdefault('fail2ban.client', client_module)
    sys.modules.setdefault('fail2ban.client.csocket', csocket_module)

spec = importlib.util.spec_from_file_location(
    'ipv6_sync', Path(__file__).resolve().parents[1] / 'scripts/f2b-ipv6-sync.py'
)
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)
now = time.time()
future = now + 7200
fmt = lambda stamp: datetime.datetime.fromtimestamp(stamp).strftime('%Y-%m-%d %H:%M:%S')
address = '2001:db8::1'


def call(command):
    if command == ['status']:
        return [('Number of jail', 2), ('Jail list', ['web', 'recidive'])]
    end = now + 3600 if command[1] == 'web' else future
    return [
        f'{address} \t{fmt(now)} + {int(end - now)} = {fmt(end)}',
        '192.0.2.1 \t' + fmt(now) + ' + 3600 = ' + fmt(now + 3600),
    ]


helper.call = call
all_ips, recidive = helper.snapshot()
assert set(all_ips) == {address} and all_ips[address] == recidive[address]
# nft JSON timeout/expiry values use seconds, not netlink milliseconds.
original_nft = helper.nft
helper.nft = lambda *args: SimpleNamespace(stdout=helper.json.dumps({
    'nftables': [{'set': {'elem': [{'elem': {
        'val': address, 'timeout': 7200, 'expires': 7199,
    }}]}}]
}))
assert now + 7190 < helper.readset('test', 'test')[address] < time.time() + 7200
# Interval/prefix encodings must abort instead of being mistaken for an empty
# set, which could otherwise remove live bans.
helper.nft = lambda *args: SimpleNamespace(stdout=helper.json.dumps({
    'nftables': [{'set': {'elem': [{'prefix': {'addr': address, 'len': 64}}]}}]
}))
try:
    helper.readset('test', 'test')
except RuntimeError as error:
    assert 'Unsupported interval' in str(error)
else:
    raise AssertionError('Unsupported nft interval representation was accepted')
helper.nft = original_nft
if '--net' not in sys.argv:
    print('PASS: runtime parser, IPv4 exclusion and longest IPv6 ban')
    sys.exit()
helper.nft('add', 'table', 'inet', 'docker-block')
helper.nft('add', 'set', 'inet', 'docker-block', 'docker-banned-ipv6',
           '{ type ipv6_addr; flags timeout; timeout 7d; }')
helper.nft('add', 'table', 'inet', 'fail2ban-filter')
helper.nft('add', 'set', 'inet', 'fail2ban-filter', 'f2b-recidive-v6',
           '{ type ipv6_addr; flags timeout; timeout 30d; }')
helper.nft('add', 'element', 'inet', 'docker-block', 'docker-banned-ipv6',
           '{ ' + address + ' timeout 60s }')
helper.reconcile(all_ips, 'docker-block', 'docker-banned-ipv6')
actual = helper.readset('docker-block', 'docker-banned-ipv6')[address]
assert actual > now + 7100, (
    'Expected >7100 seconds remaining, got', actual - time.time(),
    helper.nft('-j', 'list', 'set', 'inet', 'docker-block', 'docker-banned-ipv6').stdout,
)
helper.reconcile(all_ips, 'docker-block', 'docker-banned-ipv6')
helper.reconcile(recidive, 'fail2ban-filter', 'f2b-recidive-v6')
# A stale snapshot must not remove a freshly active ban.
helper.reconcile({}, 'docker-block', 'docker-banned-ipv6')
assert address in helper.readset('docker-block', 'docker-banned-ipv6')
helper.snapshot = lambda: ({}, {})
helper.reconcile({}, 'docker-block', 'docker-banned-ipv6')
assert not helper.readset('docker-block', 'docker-banned-ipv6')
helper.reconcile({address: float('inf')}, 'docker-block', 'docker-banned-ipv6')
assert helper.readset('docker-block', 'docker-banned-ipv6')[address] > time.time() + 29 * 86400
helper.reconcile({address: float('inf')}, 'docker-block', 'docker-banned-ipv6')
assert helper.readset('docker-block', 'docker-banned-ipv6')[address] > time.time() + 29 * 86400
print('PASS: isolated nftables expiry extension, repeated sync, race guard, unban and permanent ban')
