"""Synthetic systemd output contracts. NOT real systemd/boot acceptance."""
import importlib.util
import json
from pathlib import Path

spec = importlib.util.spec_from_file_location('boot', Path(__file__).resolve().parents[1] / 'scripts/boot-contract.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
calls = []
values = {}


def run(*args):
    calls.append(args)
    if args[0] == 'systemctl' and args[1] == 'show':
        unit, prop = args[2], args[3].split('=', 1)[1]
        defaults = {'UnitFileState': 'enabled', 'NeedDaemonReload': 'no', 'ActiveState': 'active',
                    'Requires': 'nftables.service', 'After': 'nftables.service',
                    'ExecStart': '{ path=/usr/sbin/nft ; argv[]=/usr/sbin/nft -f /etc/nftables.conf ; }'}
        return values.get((unit, prop), defaults[prop])
    if args[0] == 'nft':
        table, name = args[-2:]
        kind = 'ipv6_addr' if name.endswith(('v6', 'ipv6')) else 'ipv4_addr'
        return json.dumps({'nftables': [{'set': {'family': 'inet', 'table': table, 'name': name, 'type': kind, 'flags': ['timeout']}}]})
    if args[0] == 'systemctl' and args[1] in {'enable', 'disable', 'mask', 'unmask'}:
        values[(args[2], 'UnitFileState')] = {'enable': 'enabled', 'disable': 'disabled', 'mask': 'masked', 'unmask': 'disabled'}[args[1]]
        return ''
    raise AssertionError('Unexpected/mutating command: ' + str(args))


assert m.check(run) == dict.fromkeys(m.UNITS, 'enabled')
assert all(args[1] == 'show' if args[0] == 'systemctl' else args[:4] == ('nft', '-j', 'list', 'set') for args in calls)
for unit, prop, bad in (('nftables.service', 'UnitFileState', 'disabled'),
        ('nftables.service', 'ActiveState', 'inactive'), ('fail2ban.service', 'UnitFileState', 'disabled'),
        ('cron.service', 'UnitFileState', 'enabled-runtime'), ('nftables.service', 'NeedDaemonReload', 'yes'),
        ('fail2ban.service', 'Requires', ''), ('cron.service', 'After', ''),
        ('nftables.service', 'ExecStart', '/bin/true')):
    values[(unit, prop)] = bad; calls.clear()
    try: m.check(run)
    except ValueError: pass
    else: raise AssertionError('Unsafe boot state accepted: ' + str((unit, prop, bad)))
    assert all(args[0] != 'systemctl' or args[1] == 'show' for args in calls)
    values.clear()

def missing(*args):
    if args[0] == 'nft': return '{"nftables": []}'
    return run(*args)
try: m.check(missing)
except ValueError as error: assert 'Required boot infrastructure' in str(error)
else: raise AssertionError('Missing infra sets accepted')
desired = {'fail2ban.service': 'enabled', 'cron.service': 'disabled', 'nftables.service': 'disabled'}
calls.clear(); m.restore_enabled(run, desired)
assert m.enabled_states(run) == desired
assert all('--now' not in args and args[1] not in {'start', 'restart', 'reload'} for args in calls)
print('PASS: synthetic boot readiness, no preflight mutation, missing infra and original enabled-state restoration; NOT reboot acceptance')
