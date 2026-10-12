"""Synthetic fresh-install preflight/selection contracts; no host mutation."""
import argparse
import hashlib
import importlib.util
import json
import re
from pathlib import Path
import subprocess
import sqlite3
import tempfile
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('fresh', Path(__file__).resolve().parents[1] / 'scripts/fresh-install.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

STOCK = '''#!/usr/sbin/nft -f
# Synthetic distro-style empty chains, not a deployment export.
flush ruleset
table inet filter {
 chain input { type filter hook input priority filter; }
 chain forward { type filter hook forward priority filter; }
 chain output { type filter hook output priority filter; }
}
'''
digest = hashlib.md5(STOCK.encode()).hexdigest()
assert m.stock_nft(STOCK, digest)
assert not m.stock_nft(STOCK + '# changed\n', digest)
assert not m.stock_nft(STOCK, None)
custom = STOCK.replace('priority filter;', 'priority filter; policy drop;')
assert not m.stock_nft(custom, hashlib.md5(custom.encode()).hexdigest())

docker_source = (m.SOURCE / 'scripts/04-install-docker-block-v034.sh').read_text()
assert 'iifname "docker0" return' in docker_source
assert 'iif "docker0" return' not in docker_source
counting = re.search(r'  BANNED_SNAPSHOT=.*?\n  BANNED=.*?\n', docker_source, re.S)[0]
for payload, expected in (('table inet docker-block { set docker-banned-ipv4 { } }', '0'),
                          ('elements = { 192.0.2.7, 198.51.100.9 }', '2')):
    script = 'set -e; set -o pipefail\nnft() { printf "%s\\n" "' + payload + '"; }\n' + counting + 'test "$BANNED" = ' + expected
    subprocess.run(['bash', '-c', script], check=True)
assert subprocess.run(['bash', '-c', 'set -e; set -o pipefail\nnft() { return 42; }\n' + counting]).returncode == 42
custom = STOCK.replace('chain input {', 'chain input { tcp dport 22 accept;')
assert not m.stock_nft(custom, hashlib.md5(custom.encode()).hexdigest())


def args(**changes):
    result = argparse.Namespace(ssh=False, ssh_port=22, docker=False, mail_to=None,
                                npm_log_dir=None, install_prerequisites=False,
                                apply=False, bootstrap_stock_nft=False)
    for key, value in changes.items(): setattr(result, key, value)
    return result


def refused(function, *values):
    try: function(*values)
    except m.FreshError: return
    raise AssertionError('Expected fail-closed refusal')


with patch.object(m.shutil, 'which', return_value=None):
    assert 'docker.io' not in m.packages(args())
    assert 'default-mta' not in m.packages(args())
    assert 'openssh-server' not in m.packages(args())
    assert {'openssh-server', 'python3-systemd', 'docker.io', 'default-mta', 'whois'} <= set(m.packages(args(ssh=True, docker=True, mail_to='admin@example.invalid')))

with patch.object(m, 'missing_packages', return_value=['nftables']), patch.object(m, 'run') as run:
    refused(m.dependencies, args())
    assert not run.called, 'No apt or other mutation on read-only missing-dependency refusal'
with patch.object(m, 'missing_packages', side_effect=[['nftables'], []]), patch.object(m, 'run') as run, patch.object(m.subprocess, 'run') as install, patch.object(m.shutil, 'which', return_value='/synthetic/command'):
    m.dependencies(args(install_prerequisites=True))
    assert ('apt-get', 'update') in [call.args for call in run.call_args_list]
    assert install.call_args.args[0] == ['apt-get', 'install', '-y', 'nftables']
with patch.object(m, 'missing_packages', return_value=['nftables']), patch.object(m, 'run'), patch.object(m.subprocess, 'run'):
    refused(m.dependencies, args(install_prerequisites=True))

profile, enabled, disabled = m.policy(args())
assert set(enabled) == {'recidive', 'manualblock'}
assert len(disabled) == 11
assert all(profile[jail]['action'] == '%(action_)s' for jail in profile.sections() if jail != 'recidive')
profile, enabled, _ = m.policy(args(ssh=True, ssh_port=2222))
assert len(enabled) == 4 and profile['sshd']['backend'] == 'systemd' and profile['sshd']['port'] == '2222'

with tempfile.TemporaryDirectory(prefix='f2b-fresh-unit-') as temporary:
    root = Path(temporary)
    logs = root / 'npm'
    # A missing log directory is never created by policy selection.
    assert set(m.policy(args(npm_log_dir=logs))[1]) == {'recidive', 'manualblock'}
    assert not logs.exists()
    logs.mkdir()
    (logs / 'proxy-host-1_access.log').write_text('synthetic data\n')
    profile, enabled, _ = m.policy(args(npm_log_dir=logs))
    assert 'f2b-webshell-sweep' in enabled and 'nginx-php-errors' not in enabled
    assert 'tail' in profile['f2b-webshell-sweep']['logpath']
    assert not (logs / 'fallback_error.log').exists()
    with patch.object(m, 'ROOT', root):
        for name, data in (('/etc/os-release', 'ID=ubuntu\nVERSION_ID="26.04"\n'), ('/proc/1/comm', 'systemd\n'), ('/etc/nftables.conf', STOCK)):
            target = m.path(name); target.parent.mkdir(parents=True, exist_ok=True); target.write_text(data)
        m.path('/run/systemd/system').mkdir(parents=True)
        foreign = {'nftables': [{'table': {'family': 'ip', 'name': 'synthetic-foreign'}}]}
        calls = []

        def command(*parts, **kwargs):
            calls.append(parts)
            text = ''
            if parts[:2] == ('dpkg', '--print-architecture'): text = 'arm64\n'
            if parts[:2] == ('dpkg-query', '-W'): text = ' /etc/nftables.conf ' + digest + '\n'
            if parts[:3] == ('nft', '-j', 'list'): text = json.dumps(foreign)
            return subprocess.CompletedProcess(parts, 0, text, '')

        with patch.object(m, 'run', side_effect=command):
            m.platform_check()
            m.file_guards()
            original = m.path('/etc/nftables.conf').read_bytes()
            assert m.nft_preflight() == foreign
            assert m.path('/etc/nftables.conf').read_bytes() == original
            assert all(parts in {('dpkg', '--print-architecture'), ('systemctl', 'show', '--property=Version', '--value'), ('dpkg-query', '-W', '-f=${Conffiles}', 'nftables'), ('nft', '-j', 'list', 'ruleset'), ('crontab', '-l')} for parts in calls)
            m.path('/etc/nftables.conf').write_text('flush ruleset\n# custom\n')
            refused(m.nft_preflight)
            assert '# custom' in m.path('/etc/nftables.conf').read_text()
            m.path('/etc/nftables.conf').write_text(STOCK)
            foreign['nftables'].append({'table': {'family': 'inet', 'name': 'fail2ban-filter'}})
            refused(m.nft_preflight)
            foreign['nftables'].pop()
            database = m.path('/var/lib/fail2ban/fail2ban.sqlite3')
            database.parent.mkdir(parents=True)
            with sqlite3.connect(database) as connection:
                connection.execute('CREATE TABLE bans (ip TEXT)')
            m.file_guards()
            with sqlite3.connect(database) as connection:
                connection.execute('INSERT INTO bans VALUES (?)', ('192.0.2.7',))
            refused(m.file_guards)
            with sqlite3.connect(database) as connection:
                connection.execute('DELETE FROM bans')
            marker = m.path('/etc/f2b/fresh-install.state'); marker.parent.mkdir(parents=True); marker.write_text('incomplete\n')
            refused(m.file_guards)
            assert marker.read_text() == 'incomplete\n', 'Rerun must not clean/rebuild partial state'

print('PASS: stock/unknown config, ARM64 platform, explicit dependency installation, optional profiles, real-log selection, foreign preservation and rerun refusal')
