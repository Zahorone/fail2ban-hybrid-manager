"""Actual lab archive -> pinned 1964009 upgrade -> rollback/restart.

Private namespaces; platform/systemd/cron simulated, NOT ARM64/Ubuntu26/VM evidence.
"""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile

sys.dont_write_bytecode = True
assert os.geteuid() == 0 and os.readlink('/proc/self/ns/net') != os.readlink('/proc/1/ns/net')
assert os.readlink('/proc/self/ns/mnt') != os.readlink('/proc/1/ns/mnt')


def run(*args, check=True):
    result = subprocess.run(args, text=True, capture_output=True)
    if check and result.returncode: raise AssertionError(str(args) + '\n' + result.stdout[-3000:] + result.stderr[-3000:])
    return result


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, file); module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module); return module


run('mount', '--make-rprivate', '/'); run('mount', '-t', 'tmpfs', 'tmpfs', '/run'); Path('/run/lock').mkdir()
with tempfile.TemporaryDirectory(prefix='f2b-v033-lab-test-') as directory:
    directory = Path(directory)
    for archive_name, folder in (('/tmp/f2b-v033-lab.tar.gz', 'lab'), ('/tmp/f2b-pinned1964/f2b-complete-upgrade.tar.gz', 'upgrade')):
        with tarfile.open(archive_name) as archive:
            assert all(item.isfile() and not Path(item.name).is_absolute() and '..' not in Path(item.name).parts for item in archive.getmembers())
            archive.extractall(directory / folder)
    lab = next((directory / 'lab').iterdir()); upgrade = next((directory / 'upgrade').iterdir())
    assert hashlib.sha256(Path('/tmp/f2b-pinned1964/f2b-complete-upgrade.tar.gz').read_bytes()).hexdigest() == '271ca3d229bbe5cacebba2c48bb6fb0069d1ff9d52aaedaf7adaffd949635bbb'
    private_etc = directory / 'etc'; shutil.copytree('/etc', private_etc, symlinks=True); run('mount', '--bind', str(private_etc), '/etc')
    for name in ('/usr/local', '/var/log', '/var/lib/fail2ban', '/var/backups', '/opt'):
        clone = directory / 'root' / name.lstrip('/'); clone.mkdir(parents=True); Path(name).mkdir(parents=True, exist_ok=True); run('mount', '--bind', str(clone), name)
    stock = '#!/usr/sbin/nft -f\nflush ruleset\ntable inet filter {\n' + ''.join(' chain ' + name + ' { type filter hook ' + name + ' priority filter; }\n' for name in ('input', 'forward', 'output')) + '}\n'
    Path('/etc/nftables.conf').write_text(stock)
    stubs = directory / 'bin'; stubs.mkdir()
    (stubs / 'systemctl').write_text('#!/bin/sh\ncase "$*" in\n'
        '"stop fail2ban") fail2ban-client stop >/dev/null 2>&1; exit 0;;\n'
        '"start fail2ban") exec fail2ban-client -x start;;\n'
        '"restart fail2ban") fail2ban-client stop >/dev/null 2>&1; exec fail2ban-client -x start;;\n'
        '"is-active --quiet cron"|"enable --now cron"|"daemon-reload") exit 0;;\n'
        '"is-active fail2ban nftables docker") printf "active\\nactive\\nactive\\n";;\n'
        '*) echo "Forbidden lifecycle command" >&2; exit 99;;\nesac\n')
    (stubs / 'crontab').write_text('#!/bin/sh\n[ "$1" = -l ] || exit 99\nexit 0\n')
    (stubs / 'sudo').write_text('#!/bin/sh\nexec "$@"\n')
    for file in stubs.iterdir(): file.chmod(0o755)
    os.environ['PATH'] = str(stubs) + ':' + os.environ['PATH']
    run('nft', 'add', 'table', 'inet', 'synthetic-foreign')
    run('nft', 'add', 'chain', 'inet', 'synthetic-foreign', 'sentinel')
    run('nft', 'add', 'rule', 'inet', 'synthetic-foreign', 'sentinel', 'tcp', 'dport', '12345', 'accept')
    before_foreign = run('nft', '-s', 'list', 'table', 'inet', 'synthetic-foreign').stdout
    b = load('lab_bootstrap', lab / 'scripts/bootstrap-v033-lab.py')
    fresh = load('lab_fresh_fixture', upgrade / 'scripts/fresh-install.py')
    fresh.platform_check = lambda: print('SIMULATED platform guard in namespace only')
    conffiles = fresh.conffiles
    fresh.conffiles = lambda name: {'/etc/nftables.conf': hashlib.md5(stock.encode()).hexdigest()} if name == 'nftables' else conffiles(name)
    original_load = b.load
    b.load = lambda name, file: fresh if name == 'lab_fresh' else original_load(name, file)
    try:
        # Rename within the same private bind mount, not across /etc -> /tmp.
        parent = Path('/etc/fail2ban/jail.d'); saved_parent = parent.with_name('jail.d-fixture-saved')
        parent.rename(saved_parent); parent.symlink_to(saved_parent)
        try:
            try: b.preflight(upgrade)
            except (ValueError, fresh.FreshError) as error:
                assert 'Unsafe' in str(error) or 'symlink' in str(error)
            else: raise AssertionError('Symlink parent was accepted')
            assert not (saved_parent / 'zz-v033-lab.local').exists()
        finally:
            parent.unlink(); saved_parent.rename(parent)
        before = {p: p.read_bytes() for p in Path('/etc/fail2ban').rglob('*') if p.is_file()}
        b.preflight(upgrade)
        assert before == {p: p.read_bytes() for p in Path('/etc/fail2ban').rglob('*') if p.is_file()}
        b.apply(upgrade)
        mail = run('fail2ban-client', 'get', 'nginx-php-errors', 'action', 'sendmail-whois-lines', 'actionban').stdout
        assert 'Synthetic lab: external whois disabled' in mail
        assert '/bin/cat >> /var/log/f2b-v033-lab-mail.log' in mail
        run('fail2ban-client', 'set', 'nginx-php-errors', 'banip', '192.0.2.18')
        import time
        for _ in range(100):
            if '192.0.2.18' in Path('/var/log/f2b-v033-lab-mail.log').read_text(): break
            time.sleep(.1)
        else: raise AssertionError('Genuine mail action did not reach local-only sink')
        run('fail2ban-client', 'set', 'nginx-php-errors', 'unbanip', '192.0.2.18')
        canonical = {target: target.read_bytes() for target in b.mapping()}
        policy = Path('/etc/fail2ban/jail.d/zz-v033-lab.local').read_bytes()
        sink = Path('/etc/fail2ban/action.d/sendmail-whois-lines.local').read_bytes()
        command = ['/usr/bin/python3', str(upgrade / 'scripts/upgrade-v033-v034.py')]
        result = run(*command, '--apply', '--backup-dir', str(directory / 'backups'))
        backup = next(line.split(': ', 1)[1] for line in result.stdout.splitlines() if line.startswith('Backup complete:'))
        assert Path('/etc/fail2ban/jail.d/zz-v033-lab.local').read_bytes() == policy
        assert Path('/etc/fail2ban/action.d/sendmail-whois-lines.local').read_bytes() == sink
        run(*command, '--rollback', backup)
        assert all(path.read_bytes() == data for path, data in canonical.items())
        assert Path('/etc/fail2ban/jail.d/zz-v033-lab.local').read_bytes() == policy
        assert Path('/etc/fail2ban/action.d/sendmail-whois-lines.local').read_bytes() == sink
        run('systemctl', 'restart', 'fail2ban'); fresh.wait_ready(b.lab_policy()[1])
        for address in ('192.0.2.8', '2001:db8::8'): assert address in run('fail2ban-client', 'get', 'manualblock', 'banip').stdout
        run(*command)
        assert run('nft', '-s', 'list', 'table', 'inet', 'synthetic-foreign').stdout == before_foreign
        print('PASS: exact canonical lab archive, readonly preflight, bootstrap/restart, pinned 1964009 upgrade, rollback/restart/repreflight, overrides/both-family bans/foreign rules preserved; systemd/platform simulated')
    finally:
        run('fail2ban-client', 'stop', check=False)
