"""Synthetic schema-2 presentation, CLI grammar and deployed-code upgrade."""
import ast
import contextlib
import csv
import datetime as dt
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import types
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def load(name, script):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts' / script)
    module = importlib.util.module_from_spec(spec); sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


m = load('presentation_reporting', 'f2b-report-filter.py')
h = load('presentation_installer', 'install-reporting-hotfix.py')
NOW = dt.datetime(2026, 10, 14, 12, tzinfo=dt.timezone.utc)
active = {'snapshot_utc': NOW.isoformat(), 'jails': {'sshd': 1, 'web': 2},
          'ban_records_across_jails': 3, 'unique_ipv4': 1, 'unique_ipv6': 1, 'unique_union': 2}


def historical(path):
    return subprocess.run(['git', '-C', str(ROOT.parents[1]), 'show', h.REPORTING_BASELINE + ':' + path],
                          capture_output=True, text=True, check=True).stdout


# Short's formatter is intentionally byte-for-byte the deployed formatter.
def definition(source, name):
    return next(ast.get_source_segment(source, node) for node in ast.parse(source).body
                if isinstance(node, ast.FunctionDef) and node.name == name)


baseline = historical('releases/v0.34/scripts/f2b-report-filter.py')
old = types.ModuleType('deployed_reporting_baseline'); sys.modules[old.__name__] = old
exec(compile(baseline, '<generic-deployed-baseline>', 'exec'), old.__dict__)
assert definition(baseline, 'human') == definition((ROOT / 'scripts/f2b-report-filter.py').read_text(), 'human')
with tempfile.TemporaryDirectory(prefix='f2b-presentation-') as directory:
    folder = Path(directory); logs = folder / 'logs'; logs.mkdir()
    config = folder / 'reporting.ini'
    config.write_text('[reporting]\nfail2ban_timezone=UTC\nnpm_log_dir=' + str(logs) +
                      '\nfail2ban_log=' + str(folder / 'fail2ban.log') + '\nsample_limit=10\n'
                      '[trusted-probe example]\nsource=192.0.2.10\nmethod=GET\n'
                      'host=app.example.invalid\nstatus=404\npaths=/api/heartbeat\n')
    prefix = '[14/Oct/2026:11:59:00 +0000] 404 - GET https app.example.invalid '
    (logs / 'proxy-host-1_access.log').write_text(''.join(prefix + '"' + path +
        '" [Client 192.0.2.10] "curl sqlmap" "-"\n'
        for path in ('/api/heartbeat', '/api/heartbeat?cmd=whoami', '/shell.php?token=synthetic-private-query', '/ordinary')))
    (folder / 'fail2ban.log').write_text(''.join('2026-10-14 11:59:00,000 fail2ban.' + component +
        ' [123]: NOTICE [sshd] ' + event + ' 2001:db8::17\n'
        for component, event in (('filter', 'Found'), ('actions', 'Ban'), ('actions', 'Restore Ban'), ('actions', 'Increase Ban'))))
    settings = m.report_settings(config)
    original_build = m.build_report
    report = original_build(settings, NOW, active)
    metrics = {k: v for k, v in report.items() if k != 'presentation_top'}
    assert metrics == old.build_report(old.report_settings(config), NOW, active), 'Presentation changed reporting semantics'
    assert report['http_sample']['candidate_records'] == 2
    assert report['http_sample']['trusted_probe_records'] == 1
    assert dict(report['presentation_top']['raw_sample_paths'])['/api/heartbeat'] == 2
    assert dict(report['presentation_top']['included_candidate_paths']) == {'/api/heartbeat': 1, '/shell.php': 1}

    def cli(args, scope='all', tty=False, env=None):
        output = io.StringIO()
        with patch.object(sys, 'argv', ['report', '--config', str(config), *args]), \
             patch.object(m.os, 'geteuid', return_value=0), patch.object(m, 'runtime_snapshot', return_value=active), \
             patch.object(m, 'build_report', side_effect=lambda *a, **k: original_build(settings, NOW, active, scope=scope)), \
             patch.dict(os.environ, env or {'TERM': 'xterm-256color'}, clear=True), \
             patch.object(output, 'isatty', return_value=tty), contextlib.redirect_stdout(output):
            assert m.main() == 0
        return output.getvalue()

    for scope in ('all', 'npm-only', 'ssh-only'):
        full = cli(['--report', 'analysis', '--scope', scope], scope)
        short = cli(['--report', 'analysis', '--format', 'short', '--scope', scope], scope)
        scoped = original_build(settings, NOW, active, scope=scope)
        assert short == m.human(scoped, scope) + '\n'
        assert '┌' in full and 'FOUND TIMELINE' in full and 'Reporting schema 2;' not in full
        assert '\x1b' not in full and '\x1b' not in short and '┌' not in short
        assert ('TOP REQUEST PATHS' in full) == (scope != 'ssh-only')
        assert ('SSH JAIL SIGNALS' in full) == (scope != 'npm-only')
        assert 'new_ban' in full and 'restored_ban' in full and 'extended_ban' in full
        assert 'synthetic-private-query' not in full
        assert 'defenses are working' not in full.lower()
    assert '\x1b[1;36m' in cli(['--report', 'analysis'], tty=True)
    assert '\x1b' not in cli(['--report', 'analysis'], tty=True, env={'NO_COLOR': '', 'TERM': 'xterm'})
    assert '\x1b' not in cli(['--report', 'analysis'], tty=True, env={'TERM': 'dumb'})
    for mode in ('json', 'timeline', 'trends', 'audit', 'stats'):
        output = cli(['--report', mode], tty=True)
        json.loads(output); assert '\x1b' not in output and '┌' not in output
    output = cli(['--report', 'csv'], tty=True)
    assert len(list(csv.reader(io.StringIO(output)))) == 3 and '\x1b' not in output
    missing = dict(settings, npm_dir=folder / 'absent', fail2ban_log=folder / 'absent/fail2ban.log')
    unavailable = m.full_human(original_build(missing, NOW, active))
    assert 'unavailable' in unavailable and 'empty sample is not zero traffic' in unavailable
    report['presentation_top']['raw_sample_paths'] = [('/x\x1b[31m\nforged', 1)]
    assert '\x1b' not in m.full_human(report) and '\\u001b' in m.full_human(report)

# Main+analysis together exercise actual public CLI argument forwarding and exit codes.
original = historical('releases/v0.34/scripts/f2b-wrapper-v034.sh')
patched = h.wrapper_source(original).decode()
for name in ('manage_block_port', 'manage_unblock_port', 'f2b_sync_check', 'f2b_docker_verify', 'sync_silent', 'manage_reload'):
    assert h.function(patched, name) == h.function(original, name)
subprocess.run(['bash', '-n'], input=patched, text=True, check=True)
assert 'report attack-analysis short' in h.function(patched, 'show_help')
script = '''LOGFILE=/synthetic/report.log
mkdir() { :; }; touch() { :; }; acquire_lock() { :; }; release_lock() { return 0; }
sudo() { printf '%s\\n' "$@"; }
''' + h.function(patched, 'report_attack_analysis') + '\n' + h.function(patched, 'main') + '\nmain "$@"\n'
for args, scope, mode in (([], 'all', 'full'), (['short'], 'all', 'short'),
                          (['--npm-only'], 'npm-only', 'full'), (['--ssh-only'], 'ssh-only', 'full'),
                          (['short', '--npm-only'], 'npm-only', 'short'), (['--npm-only', 'short'], 'npm-only', 'short'),
                          (['short', '--ssh-only'], 'ssh-only', 'short'), (['--ssh-only', 'short'], 'ssh-only', 'short')):
    result = subprocess.run(['bash', '-c', script, 'test', 'report', 'attack-analysis', *args], text=True, capture_output=True)
    assert result.returncode == 0, result.stderr
    argv = result.stdout.splitlines()
    assert argv[argv.index('--scope') + 1] == scope and argv[argv.index('--format') + 1] == mode
for args in (['nonsense'], ['short', 'short'], ['--npm-only', '--ssh-only'], ['--npm-only', '--npm-only'], ['--bad-flag']):
    result = subprocess.run(['bash', '-c', script, 'test', 'report', 'attack-analysis', *args], text=True, capture_output=True)
    assert result.returncode == 2 and result.stderr and not result.stdout
print('PASS: full/unchanged-short rendering, scope CLI grammar, clean JSON/CSV, TTY/NO_COLOR, safe top paths and deployed baseline preservation')
