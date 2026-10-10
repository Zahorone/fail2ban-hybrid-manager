#!/usr/bin/python3
import datetime
import fcntl
import ipaddress
import json
import re
import subprocess
import sys
import time
from contextlib import contextmanager

from fail2ban.client.csocket import CSocket


def call(command):
    socket = CSocket('/var/run/fail2ban/fail2ban.sock', timeout=15)
    try:
        result = socket.send(command)
    finally:
        socket.close()
    if result[0] != 0:
        raise RuntimeError(str(result))
    return result[1]


def snapshot(family=6):
    status = dict(call(['status']))
    jails = status['Jail list']
    if isinstance(jails, str):
        jails = [item.strip() for item in jails.split(',') if item.strip()]
    all_ips = {}
    recidive = {}
    for jail in jails:
        lines = call(['get', jail, 'banip', '--with-time'])
        if not isinstance(lines, list):
            raise RuntimeError('Unexpected ban list')
        for line in lines:
            match = re.fullmatch(r'(\S+)\s+(.+?) \+ (-?\d+) = (.+)', line)
            if not match:
                raise RuntimeError('Unexpected ban timestamp')
            address = ipaddress.ip_address(match[1])
            if address.version != family:
                continue
            end = (float('inf') if int(match[3]) == -1 else
                   datetime.datetime.strptime(match[4], '%Y-%m-%d %H:%M:%S').timestamp())
            if end <= time.time():
                continue
            key = str(address)
            all_ips[key] = max(all_ips.get(key, 0), end)
            if jail == 'recidive':
                recidive[key] = end
    return all_ips, recidive


def nft(*args, check=True):
    return subprocess.run(
        ['nft', *args], check=check, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )


def readset(table, name):
    document = json.loads(nft('-j', 'list', 'set', 'inet', table, name).stdout)
    output = {}
    for obj in document['nftables']:
        if 'set' not in obj:
            continue
        for element in obj['set'].get('elem', []):
            expiry = None
            if isinstance(element, dict) and 'elem' in element:
                expiry = element['elem'].get('expires')
                element = element['elem']['val']
            if not isinstance(element, str):
                raise RuntimeError('Unsupported interval in ' + name + '; preserving all bans')
            output[str(ipaddress.ip_address(element))] = (
                float('inf') if expiry is None else time.time() + expiry
            )
    return output


def reconcile(desired, table, name, prune=True):
    current = readset(table, name)
    # Extend shorter bans to the longest active jail expiry, without shortening others.
    for address, end in desired.items():
        # timeout 0 inherits a set default on these kernels. Maintain permanent
        # Fail2Ban bans as explicit 30-day leases, renewed by regular sync.
        permanent = end == float('inf')
        target = time.time() + 30 * 86400 if permanent else end
        threshold = target - 86400 if permanent else target - 5
        if address in current and current[address] >= threshold:
            continue
        ttl = ' timeout ' + str(max(1, int(target - time.time()))) + 's'
        command = 'add element inet ' + table + ' ' + name + ' { ' + address + ttl + ' }\n'
        if address in current:
            command = 'delete element inet ' + table + ' ' + name + ' { ' + address + ' }\n' + command
        subprocess.run(['nft', '-f', '-'], input=command, text=True, check=True, capture_output=True)
    # Refresh authority before removing anything, to avoid racing a new ban.
    for address in (set(current) - set(desired)) if prune else ():
        fresh, recidive = snapshot(6 if name.endswith(('ipv6', '-v6')) else 4)
        active = recidive if name.startswith('f2b-recidive') else fresh
        if address not in active:
            nft('delete', 'element', 'inet', table, name, '{ ' + address + ' }', check=False)


@contextmanager
def sync_lock():
    # Hook workers never query Fail2Ban while holding this lock. The daemon's
    # socket remains available while the separate sync process reads bans.
    with open('/run/lock/f2b-runtime-sync.lock', 'a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        yield


def hook_ban(address, bantime):
    address = str(ipaddress.ip_address(address))
    duration = int(bantime)
    if duration != -1 and duration <= 0:
        raise ValueError('Invalid ban duration')
    end = float('inf') if duration == -1 else time.time() + duration
    name = 'docker-banned-ipv6' if ':' in address else 'docker-banned-ipv4'
    with sync_lock():
        reconcile({address: end}, 'docker-block', name, prune=False)


def main():
    if len(sys.argv) > 1 and sys.argv[1] == 'hook-ban':
        hook_ban(sys.argv[2], sys.argv[3])
        return
    if len(sys.argv) > 1 and sys.argv[1] == 'check':
        for family in (4, 6):
            all_ips, recidive = snapshot(family)
            print('Active IPv%d bans:' % family, len(all_ips), 'recidive:', len(recidive))
        return
    with sync_lock():
        for family in (4, 6):
            all_ips, recidive = snapshot(family)
            reconcile(all_ips, 'docker-block', 'docker-banned-ipv%d' % family)
            reconcile(recidive, 'fail2ban-filter', 'f2b-recidive' + ('-v6' if family == 6 else ''))
            print('IPv%d sync OK:' % family, len(all_ips), 'active addresses,', len(recidive), 'recidive addresses')


if __name__ == '__main__':
    main()
