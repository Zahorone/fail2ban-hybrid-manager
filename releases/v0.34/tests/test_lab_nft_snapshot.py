"""Synthetic endpoint tests; --net adds real nft timed bans, NOT boot evidence."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time

spec = importlib.util.spec_from_file_location('snapshot', Path(__file__).resolve().parents[1] / 'scripts/lab-nft-snapshot.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
doc = {'nftables': [{'metainfo': {'version': 'synthetic'}},
    {'table': {'family': 'inet', 'name': 'synthetic', 'handle': 1}},
    {'set': {'family': 'inet', 'table': 'synthetic', 'name': 'bans', 'type': 'ipv4_addr', 'flags': ['timeout'],
             'elem': [{'elem': {'val': '192.0.2.8', 'timeout': 30, 'expires': 10}}, '192.0.2.9']}},
    {'rule': {'family': 'inet', 'table': 'synthetic', 'chain': 'guard', 'handle': 2,
              'expr': [{'counter': {'packets': 10, 'bytes': 100}}, {'accept': None}]}},
    {'rule': {'family': 'inet', 'table': 'synthetic', 'chain': 'guard', 'handle': 3, 'expr': [{'drop': None}]}}]}


def refused(old, new):
    try: m.compare(old, new)
    except ValueError: return
    raise AssertionError('Real/uncertain runtime change was accepted')


before = m.normalized(doc, 100, 100.01)
later = copy.deepcopy(doc)
later['nftables'][0]['metainfo']['version'] = 'different synthetic metadata'
later['nftables'][1]['table']['handle'] = 99
later['nftables'][2]['set']['elem'][0]['elem']['expires'] = 7
later['nftables'][2]['set']['elem'].reverse()
later['nftables'][3]['rule']['expr'][0]['counter'] = {'packets': 20, 'bytes': 200}
assert m.compare(before, m.normalized(later, 103, 103.01)) == 0
for mutation in ('rule', 'order', 'member-add', 'member-delete', 'expiry-extend', 'expiry-shorten', 'timeout', 'counter-reset', 'schema'):
    changed = copy.deepcopy(later)
    entries = changed['nftables'][2]['set']['elem']
    if mutation == 'rule': changed['nftables'][3]['rule']['expr'][-1] = {'drop': None}
    elif mutation == 'order': changed['nftables'][3:5] = reversed(changed['nftables'][3:5])
    elif mutation == 'member-add': entries.append('192.0.2.10')
    elif mutation == 'member-delete': entries.pop(1)
    elif mutation == 'expiry-extend': entries[1]['elem']['expires'] = 20
    elif mutation == 'expiry-shorten': entries[1]['elem']['expires'] = 1
    elif mutation == 'timeout': entries[1]['elem']['timeout'] = 60
    elif mutation == 'counter-reset': changed['nftables'][3]['rule']['expr'][0]['counter']['packets'] = 0
    elif mutation == 'schema': changed['nftables'][2]['set']['type'] = 'ipv6_addr'
    refused(before, m.normalized(changed, 103, 103.01))
expired = copy.deepcopy(doc)
expired['nftables'][2]['set']['elem'] = ['192.0.2.9']
assert m.compare(before, m.normalized(expired, 112, 112.01)) == 1
refused(before, m.normalized(expired, 109, 109.01))  # not proven expired
expired['nftables'][2]['set']['elem'] = []
refused(before, m.normalized(expired, 112, 112.01))  # permanent member lost
print('PASS: semantic rule order/schema/membership/absolute-expiry/counter guard; only proven natural expiration allowed')

if '--net' in sys.argv:
    assert os.geteuid() == 0 and os.readlink('/proc/self/ns/net') != os.readlink('/proc/1/ns/net')

    def run(*args): return subprocess.check_output(args, text=True)

    table = 'synthetic-lab-guard'
    run('ip', 'link', 'set', 'lo', 'up')
    run('nft', 'add', 'table', 'inet', table)
    try:
        for name, kind, address in (('v4', 'ipv4_addr', '192.0.2.8'), ('v6', 'ipv6_addr', '2001:db8::8')):
            run('nft', 'add', 'set', 'inet', table, name, '{ type ' + kind + '; flags timeout; }')
            run('nft', 'add', 'element', 'inet', table, name, '{ ' + address + ' timeout 30s }')
        run('nft', 'add', 'element', 'inet', table, 'v4', '{ 192.0.2.9 timeout 1s }')
        run('nft', 'add', 'counter', 'inet', table, 'traffic', '{ packets 10 bytes 100; }')
        run('nft', 'add', 'chain', 'inet', table, 'output', '{ type filter hook output priority 0; policy accept; }')
        run('nft', 'add', 'rule', 'inet', table, 'output', 'counter', 'name', 'traffic', 'accept')
        old = m.capture(run)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.sendto(b'synthetic local counter fixture', ('127.0.0.1', 9))
        time.sleep(2.3)
        new = m.capture(run)
        assert old != new and m.compare(old, new) == 1
        assert any(new['counters'][key] > value for key, value in old['counters'].items())
        run('nft', 'reset', 'counter', 'inet', table, 'traffic')
        refused(new, m.capture(run))
        old = m.capture(run)
        run('nft', 'delete', 'element', 'inet', table, 'v4', '{ 192.0.2.8 }')
        run('nft', 'add', 'element', 'inet', table, 'v4', '{ 192.0.2.8 timeout 60s }')
        refused(old, m.capture(run))
        old = m.capture(run)
        run('nft', 'delete', 'element', 'inet', table, 'v6', '{ 2001:db8::8 }')
        refused(old, m.capture(run))
        old = m.capture(run)
        run('nft', 'add', 'rule', 'inet', table, 'output', 'drop')
        refused(old, m.capture(run))
        print('PASS: real nft time gap, natural expiry and increasing counters; real counter-reset/retime/removal/rule mutations refused')
    finally: run('nft', 'delete', 'table', 'inet', table)
