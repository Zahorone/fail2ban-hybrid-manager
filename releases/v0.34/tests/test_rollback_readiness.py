"""Read-only asynchronous restore gate; no host service/ban mutations."""
import datetime as dt
import importlib.util
import json
from pathlib import Path
import sqlite3
import subprocess
import tarfile
import tempfile
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('upgrade_ready', Path(__file__).resolve().parents[1] / 'scripts/upgrade-v033-v034.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
expected = {'manualblock': {'192.0.2.8': 1100}}
jails = {'manualblock', 'recidive'}
stamp = lambda value: dt.datetime.fromtimestamp(value).strftime('%Y-%m-%d %H:%M:%S')
record = '192.0.2.8 ' + stamp(1000) + ' + 100 = ' + stamp(1100)


def scenario(mode):
    clock = [0.0]; calls = []; exports = [0]
    def run(*args, **kwargs):
        calls.append(args)
        assert args[:2] == ('fail2ban-client', 'ping') or args[:2] == ('fail2ban-client', 'status')
        assert 0 < kwargs['timeout'] <= 3
        if mode == 'subprocess-timeout': raise subprocess.TimeoutExpired(args, kwargs['timeout'])
        if args[-1] == 'ping':
            ready = mode != 'socket' and (mode != 'delayed' or clock[0] >= .4)
            return subprocess.CompletedProcess(args, 0 if ready else 255, 'Server replied: pong' if ready else '', '')
        ready = mode != 'jails' and (mode != 'delayed' or clock[0] >= .6)
        return subprocess.CompletedProcess(args, 0, 'Jail list: manualblock, recidive' if ready else 'Jail list: manualblock', '')
    def export(**kwargs):
        exports[0] += 1
        if mode == 'missing' or (mode == 'delayed' and clock[0] < .8): return {'manualblock': [], 'recidive': []}
        value = record.replace(stamp(1100), stamp(1200)) if mode in {'ttl-reset', 'expired-rebanned'} else record
        return {'manualblock': [value], 'recidive': []}
    with patch.object(m, 'run', side_effect=run), patch.object(m, 'snapshot_ban_times', side_effect=export), \
            patch.object(m.time, 'monotonic', side_effect=lambda: clock[0]), \
            patch.object(m.time, 'time', return_value=1101 if mode == 'expired-rebanned' else 1050), patch.object(m.time, 'sleep', side_effect=lambda step: clock.__setitem__(0, clock[0] + step)):
        if mode == 'delayed':
            m.wait_rollback_ready(jails, expected, timeout=1.2)
            assert clock[0] >= .8 and exports[0] >= 2
        else:
            try: m.wait_rollback_ready(jails, expected, timeout=1)
            except m.UpgradeError as error: assert 'readiness timeout' in str(error) and 'no banip writes' in str(error)
            else: raise AssertionError('Incomplete restore was accepted: ' + mode)
        assert clock[0] <= 1.2
        assert all('set' not in args for args in calls)

for mode in ('delayed', 'socket', 'jails', 'missing', 'ttl-reset', 'expired-rebanned', 'subprocess-timeout'): scenario(mode)

with tempfile.TemporaryDirectory() as temporary:
    root = Path(temporary); database = root / 'native.sqlite3'; backup = root / 'backup'; backup.mkdir()
    with sqlite3.connect(database) as connection:
        connection.executescript('CREATE TABLE fail2banDb(version INTEGER); INSERT INTO fail2banDb VALUES(4); '
            'CREATE TABLE bips(jail TEXT, ip TEXT, timeofban INTEGER, bantime INTEGER);')
        connection.execute('INSERT INTO bips VALUES(?,?,?,?)', ('manualblock', '192.0.2.8', 1000, 100))
    original = database.read_bytes()
    assert m.native_tickets(database, 1050) == expected
    assert m.native_tickets(database, 1101) == {}
    assert database.read_bytes() == original
    with tarfile.open(backup / 'system-files.tar', 'w') as archive:
        archive.add(database, arcname='var/lib/fail2ban/fail2ban.sqlite3')
    (backup / 'fail2ban-bans.json').write_text(json.dumps(dict.fromkeys(jails, [])))
    with patch.object(m.time, 'time', return_value=1050):
        assert m.rollback_expectations(backup, compare_live=False) == (jails, expected)
    (backup / 'manifest.json').write_text(json.dumps({'schema': 1, 'targets': [], 'members': []}))
    with patch.object(m, 'verify_backup'), patch.object(m, 'rollback_expectations', side_effect=m.UpgradeError('ticket drift')), patch.object(m, 'run') as run:
        try: m.rollback(backup)
        except m.UpgradeError: pass
        else: raise AssertionError('Unsafe native DB restore was accepted')
        run.assert_not_called()
print('PASS: bounded delayed socket/pong/jails/native restore, timeout/TTL negatives, readonly DB expiry, pre-stop refusal; no re-add writes')
