#!/usr/bin/python3
"""Read-only systemd/infra boot gate; never enable or start a firewall here."""
import json

UNITS = ('fail2ban.service', 'cron.service', 'nftables.service')


def output(run, *args):
    result = run(*args)
    return (result.stdout if hasattr(result, 'stdout') else result).strip()


def enabled_states(run):
    result = {unit: output(run, 'systemctl', 'show', unit, '--property=UnitFileState', '--value') for unit in UNITS}
    if any(value not in {'enabled', 'disabled', 'static', 'masked'} for value in result.values()):
        raise ValueError('Unrecognized persistent unit enabled state; review before changing anything')
    return result


def restore_enabled(run, desired):
    if set(desired) != set(UNITS) or any(value not in {'enabled', 'disabled', 'static', 'masked'} for value in desired.values()):
        raise ValueError('Invalid backed-up unit enabled states')
    current = enabled_states(run)
    for unit, state in desired.items():
        if current[unit] == state: continue
        if state == 'static': raise ValueError('Cannot safely synthesize static unit state: ' + unit)
        if current[unit] == 'masked': run('systemctl', 'unmask', unit)
        run('systemctl', {'enabled': 'enable', 'disabled': 'disable', 'masked': 'mask'}[state], unit)
    if enabled_states(run) != desired: raise ValueError('Unit enabled state restoration failed')


def check(run, runtime=True, infra=True):
    states = enabled_states(run)
    for unit in UNITS:
        if states[unit] != 'enabled':
            raise ValueError('Boot not ready: ' + unit + ' is ' + states[unit] + '; no automatic firewall enabling')
        if output(run, 'systemctl', 'show', unit, '--property=NeedDaemonReload', '--value') != 'no':
            raise ValueError('Boot not ready: ' + unit + ' requires reviewed daemon-reload')
        if runtime and output(run, 'systemctl', 'show', unit, '--property=ActiveState', '--value') != 'active':
            raise ValueError('Boot not ready: ' + unit + ' is not active; do not start/load it blindly')
    for consumer in ('fail2ban.service', 'cron.service'):
        required = output(run, 'systemctl', 'show', consumer, '--property=Requires', '--value').split()
        after = output(run, 'systemctl', 'show', consumer, '--property=After', '--value').split()
        if 'nftables.service' not in required or 'nftables.service' not in after:
            raise ValueError('Boot not ready: ' + consumer + ' needs both Requires= and After=nftables.service')
    start = output(run, 'systemctl', 'show', 'nftables.service', '--property=ExecStart', '--value')
    if 'nft' not in start or '/etc/nftables.conf' not in start:
        raise ValueError('Unrecognized nftables boot loader; manual boot-contract review required')
    if runtime and infra:
        for table, name, kind in (('fail2ban-filter', 'f2b-recidive', 'ipv4_addr'),
                ('fail2ban-filter', 'f2b-recidive-v6', 'ipv6_addr'),
                ('docker-block', 'docker-banned-ipv4', 'ipv4_addr'),
                ('docker-block', 'docker-banned-ipv6', 'ipv6_addr')):
            doc = json.loads(output(run, 'nft', '-j', 'list', 'set', 'inet', table, name))
            sets = [e['set'] for e in doc['nftables'] if 'set' in e and e['set'].get('table') == table and e['set'].get('name') == name]
            if len(sets) != 1 or sets[0].get('type') != kind or 'timeout' not in sets[0].get('flags', []):
                raise ValueError('Required boot infrastructure set missing/incompatible: ' + table + '/' + name)
    return states
