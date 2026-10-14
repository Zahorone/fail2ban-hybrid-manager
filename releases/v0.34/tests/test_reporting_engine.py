"""Generic synthetic reporting: exact windows, rotations, exclusions and metrics."""
import contextlib
import csv
import datetime as dt
import gzip
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from unittest.mock import patch
from zoneinfo import ZoneInfo

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('reporting_engine', ROOT / 'scripts/f2b-report-filter.py')
m = importlib.util.module_from_spec(spec); sys.modules[spec.name] = m; spec.loader.exec_module(m)
NOW = dt.datetime(2026, 10, 14, 12, tzinfo=dt.timezone.utc)


def http(stamp, path, source='192.0.2.10', status=404, proxy=False, method='GET'):
    prefix = '- 404 ' if proxy else ''
    return f'[{stamp}] {prefix}{status} - {method} https app.example.invalid "{path}" [Client {source}] [Length 0] [Gzip -] "curl" "-"\n'


def event(stamp, kind, jail='sshd', source='192.0.2.17'):
    component = 'filter' if kind == 'Found' else 'actions'
    return f'{stamp} fail2ban.{component} [123]: NOTICE [{jail}] {kind} {source}\n'


def runtime_call(command):
    assert command[0] in {'status', 'get'}
    if command == ['status']: return [('Jail list', ['sshd', 'web'])]
    return ['192.0.2.17'] if command[1] == 'sshd' else ['192.0.2.17', '2001:db8::17']


active = m.runtime_snapshot(runtime_call)
assert active['ban_records_across_jails'] == 3
assert (active['unique_ipv4'], active['unique_ipv6'], active['unique_union']) == (1, 1, 2)
assert 'not audit failure' in active['audit_status']
with tempfile.TemporaryDirectory(prefix='f2b-reporting-') as folder:
    folder = Path(folder); logs = folder / 'npm'; logs.mkdir()
    config = folder / 'reporting.ini'
    config.write_text('[reporting]\nfail2ban_timezone = Europe/Bratislava\nsample_limit = 3\n'
                      'npm_log_dir = ' + str(logs) + '\nfail2ban_log = ' + str(folder / 'fail2ban.log') + '\n'
                      '[trusted-probe "app"]\nsource = 192.0.2.10/32\nmethod = GET\n'
                      'host = app.example.invalid\nstatus = 404\npaths = /api/heartbeat, /api/sysinfo, /api/audit/conn\n')
    # Rotation names deliberately disagree with chronology. The latest record
    # is in gzip; an offset +0200 and UTC record refer to the same time base.
    (logs / 'fallback_http_access.log').write_text(
        http('14/Oct/2026:13:55:00 +0200', '/api/heartbeat') +
        http('14/Oct/2026:11:56:00 +0000', '/api/users', source='192.0.2.11', proxy=True))
    (logs / 'fallback_http_access.log.1').write_text(
        http('13/Oct/2026:12:00:00 +0000', '/', status=200) +
        http('13/Oct/2026:11:59:59 +0000', '/shell.php') +
        http('14/Oct/2026:13:00:00 +0000', '/shell.php'))
    with gzip.open(logs / 'fallback_http_access.log.2.gz', 'wt') as stream:
        stream.write(http('14/Oct/2026:11:57:00 +0000', '/api/data?path=../../.env&cmd=whoami', source='2001:db8::17'))
    # Stream/backend files are never HTTP samples.
    (logs / 'fallback_stream_access.log').write_text(http('14/Oct/2026:12:00:00 +0000', '/shell.php'))
    (logs / 'backend.log').write_text('private synthetic backend text\n')
    (folder / 'fail2ban.log').write_text(event('2026-10-14 13:00:00,000', 'Found') +
        event('2026-10-14 13:45:00,000', 'Ban') +
        ''.join(event('2026-10-14 13:50:00,' + f'{i:03}', 'Found') for i in range(100)))
    (folder / 'fail2ban.log.1').write_text(event('2026-10-13 13:59:59,000', 'Ban') +
        event('2026-10-13 14:00:00,000', 'Ban') + event('2026-10-14 15:00:00,000', 'Ban'))
    with gzip.open(folder / 'fail2ban.log.2.gz', 'wt') as stream:
        stream.write(event('2026-10-14 13:20:00,000', 'Restore Ban') +
                     event('2026-10-14 13:30:00,000', 'Ban', 'web', '2001:db8::17') +
                     event('2026-10-14 13:40:00,000', 'Increase Ban'))
    settings = m.report_settings(config)
    report = m.build_report(settings, NOW, active)
    sample = report['http_sample']
    assert report['http_window']['parsed_records'] == 4
    assert report['coverage']['http']['files'] == 3
    assert report['coverage']['http']['before_window'] == 1 and report['coverage']['http']['future_records'] == 1
    assert (sample['raw_records'], sample['trusted_probe_records'], sample['included_records']) == (3, 1, 2)
    assert sample['raw_http_errors'] == 3 and sample['included_http_errors'] == 2
    assert sample['candidate_records'] == 1 and sample['candidate_fraction'] == 0.5
    assert sum(sample['category_hits'].values()) == 2, 'Overlapping categories are not summed as attempts'
    assert report['fail2ban_events_24h']['new_ban'] == 3
    assert report['fail2ban_events_24h']['restored_ban'] == 1
    assert report['fail2ban_events_24h']['extended_ban'] == 1
    assert report['fail2ban_events_24h']['found'] == 101
    assert report['found_summary']['average_per_hour'] == 101 / 24
    assert report['trends']['1']['new_ban'] == 2 and report['trends']['24']['new_ban'] == 3
    assert sum(item['found_records'] for item in report['found_timeline']) == 101
    recent = report['recent_ban_event_sample']
    assert len(recent) == 5, 'Newer Found events must not push bans out of the ban sample'
    assert [item['timestamp_utc'] for item in recent] == sorted(item['timestamp_utc'] for item in recent)
    assert recent[-1]['timestamp_utc'].endswith('11:45:00+00:00')
    assert len(m.build_report(settings, NOW, active, scope='ssh-only')['http_sample']['category_hits']) == 0
    # Exclusions use FINAL status, exact request fields, both families and safe targets.
    rule = settings['rules'][0]
    assert rule.matches(http('14/Oct/2026:11:55:00 +0000', '/api/sysinfo'))
    assert not rule.matches(http('14/Oct/2026:11:55:00 +0000', '/api/sysinfo', status=200, proxy=True))
    assert not rule.matches(http('14/Oct/2026:11:55:00 +0000', '/api/sysinfo', source='192.0.2.11'))
    assert not rule.matches(http('14/Oct/2026:11:55:00 +0000', '/api/sysinfo', method='POST'))
    assert not rule.matches(http('14/Oct/2026:11:55:00 +0000', '/api/data?cmd=whoami'))
    assert not m.indicators(m.parse_http(http('14/Oct/2026:11:55:00 +0000', '/api/users'), settings['zone']))
    benign = http('14/Oct/2026:11:55:00 +0000', '/api/users').replace('"curl"', '"curl sqlmap /shell.php?cmd=whoami"')
    assert not m.indicators(m.parse_http(benign, settings['zone']))
    assert m.indicators(m.parse_http(http('14/Oct/2026:11:55:00 +0000', '/api/users?cmd=whoami'), settings['zone']))
    assert not rule.matches(http('14/Oct/2026:11:55:00 +0000', '/api/heartbeat-near'))
    assert not rule.matches(http('14/Oct/2026:11:55:00 +0000', '/api/heartbeat?cmd=whoami'))
    assert not rule.matches(http('14/Oct/2026:11:55:00 +0000', '/api/heartbeat').replace('[Client 192.0.2.10]', ''))
    v6rule = m.ProbeRule(m.ipaddress.ip_network('2001:db8::10/128'), 'GET', rule.host, 404, rule.paths)
    assert v6rule.matches(http('14/Oct/2026:11:55:00 +0000', '/api/heartbeat', source='2001:db8::10'))
    assert not v6rule.matches(http('14/Oct/2026:11:55:00 +0000', '/api/heartbeat', source='2001:db8::11'))
    assert not rule.matches(http('14/Oct/2026:11:55:00 +0000', '/api/heartbeat').replace('app.example.invalid', 'other.example.invalid'))
    # Ambiguous fall-back and nonexistent spring local times are not guessed.
    for value in ('2026-10-25 02:30:00', '2026-03-29 02:30:00'):
        try: m.timestamp(value, ZoneInfo('Europe/Bratislava'))
        except m.AmbiguousTimestamp: pass
        else: raise AssertionError('Naive ambiguous/nonexistent time silently guessed')
    assert m.timestamp('2026-10-25 02:30:00+02:00', settings['zone']) != m.timestamp('2026-10-25 02:30:00+01:00', settings['zone'])
    assert m.timestamp('2026-10-14 12:00:00Z', settings['zone']) == NOW
    # CLI JSON is pure data; active bans alone do not make audit fail.
    for mode in ('json', 'audit', 'stats', 'timeline', 'trends'):
        output = io.StringIO()
        with patch.object(sys, 'argv', ['report', '--report', mode, '--config', str(config)]), \
             patch.object(m.os, 'geteuid', return_value=0), patch.object(m, 'runtime_snapshot', return_value=active), \
             contextlib.redirect_stdout(output):
            assert m.main() == 0
        assert '\x1b' not in output.getvalue()
        json.loads(output.getvalue())
    output = io.StringIO()
    with patch.object(sys, 'argv', ['report', '--report', 'csv']), \
         patch.object(m.os, 'geteuid', return_value=0), patch.object(m, 'runtime_snapshot', return_value=active), contextlib.redirect_stdout(output):
        assert m.main() == 0
    rows = list(csv.reader(io.StringIO(output.getvalue())))
    assert rows[0] == ['snapshot_utc', 'jail', 'active_ban_records'] and len(rows) == 3
    assert '\x1b' not in output.getvalue()
    missing = dict(settings, npm_dir=folder / 'missing', fail2ban_log=folder / 'missing/fail2ban.log')
    absent = m.build_report(missing, NOW, active)
    assert absent['coverage']['http']['availability'].startswith('unavailable')
    assert absent['http_window']['parsed_records'] is None
    assert absent['fail2ban_events_24h']['new_ban'] is None
    assert absent['found_timeline'][0]['found_records'] is None
    for bad in ('[typo]\nx=1\n', '[reporting]\nsample_limt=2\n', '[trusted-probe broken]\nsource=192.0.2.10\n'):
        invalid = folder / 'bad.ini'; invalid.write_text(bad)
        with patch.object(sys, 'argv', ['report', '--validate-config', '--config', str(invalid)]), contextlib.redirect_stderr(io.StringIO()):
            assert m.main() == 2
    output = io.StringIO()
    with patch.object(sys, 'argv', ['report', '--report', 'audit']), \
         patch.object(m.os, 'geteuid', return_value=0), patch.object(m, 'runtime_snapshot', side_effect=ValueError('synthetic API failure')), \
         contextlib.redirect_stdout(output), contextlib.redirect_stderr(io.StringIO()):
        assert m.main() == 2 and not output.getvalue()

spec = importlib.util.spec_from_file_location('report_hotfix', ROOT / 'scripts/install-reporting-hotfix.py')
h = importlib.util.module_from_spec(spec); spec.loader.exec_module(h)
with tempfile.TemporaryDirectory(prefix='f2b-report-rollback-test-') as directory:
    directory = Path(directory); wrapper = directory / 'wrapper'; helper = directory / 'helper'
    before = {helper: b'old helper\n', wrapper: b'#!/bin/bash\ntrue\n'}
    after = {helper: b'new helper\n', wrapper: b'#!/bin/bash\nfalse\n'}
    manifest = {'schema': 1, 'targets': {}}
    for index, (path, content) in enumerate(before.items()):
        path.write_bytes(after[path]); (directory / ('target-' + str(index))).write_bytes(content)
        manifest['targets'][str(path)] = {'existed': True, 'before': hashlib.sha256(content).hexdigest(), 'after': hashlib.sha256(after[path]).hexdigest()}
    (directory / 'manifest.json').write_text(json.dumps(manifest))
    def atomic(path, contents): path.write_bytes(contents)
    with patch.object(h.transaction, 'secure'), patch.object(h.transaction, 'WRAPPER', wrapper), \
         patch.object(h.transaction, 'CHECKER', helper), patch.object(h.transaction, 'atomic', side_effect=atomic):
        helper.write_bytes(b'intervening local change\n')
        try: h.rollback(directory)
        except h.transaction.HotfixError: pass
        else: raise AssertionError('Rollback overwrote intervening edits')
        assert wrapper.read_bytes() == after[wrapper]
        helper.write_bytes(after[helper]); h.rollback(directory)
        assert all(path.read_bytes() == content for path, content in before.items())
for source in (ROOT.parent / 'v0.33/scripts/f2b-wrapper-v033.sh', ROOT / 'scripts/f2b-wrapper-v034.sh'):
    original = source.read_text(); patched = h.wrapper_source(original).decode()
    subprocess.run(['bash', '-n'], input=patched, text=True, check=True)
    for name in ('manage_block_port', 'manage_unblock_port', 'f2b_sync_check', 'f2b_docker_verify',
                 'sync_silent', 'manage_manual_ban', 'manage_reload'):
        assert h.function(original, name) == h.function(patched, name), name
    if source.parent.parent.name == 'v0.33':
        assert 'Legacy IPv4 count/union diagnostic' in h.function(patched, 'show_help')
    assert 'local report_result=$?' in h.function(patched, 'main')
    # A legacy report failure must survive successful lock cleanup.
    shell = '''LOGFILE=/synthetic/report.log
mkdir() { :; }; touch() { :; }; acquire_lock() { :; }; release_lock() { return 0; }
report_json() { return 42; }
''' + h.function(patched, 'main') + '\nmain report json\n'
    result = subprocess.run(['bash', '-c', shell], capture_output=True, text=True)
    assert result.returncode == 42, result.stderr
print('PASS: chronological plain/gz sampling, timezone/cutoff/DST, restored vs new events, explicit probes, denominators/unions and scoped legacy wrapper patch')
