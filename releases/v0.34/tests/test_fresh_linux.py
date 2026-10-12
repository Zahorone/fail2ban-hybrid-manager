"""Real fresh file/firewall/daemon path; PRIVATE namespaces, simulated systemd.

Not an apt/network download, real boot, ARM64 VM or reboot validation.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

assert os.geteuid() == 0
assert os.readlink('/proc/self/ns/net') != os.readlink('/proc/1/ns/net'), 'Require unshare --net'
assert os.readlink('/proc/self/ns/mnt') != os.readlink('/proc/1/ns/mnt'), 'Require unshare --mount'


def run(*args, check=True):
    result = subprocess.run(args, capture_output=True, text=True)
    if check and result.returncode:
        raise AssertionError(str(args) + '\n' + result.stdout[-3000:] + result.stderr[-3000:])
    return result


run('mount', '--make-rprivate', '/')
run('mount', '-t', 'tmpfs', 'tmpfs', '/run')
Path('/run/lock').mkdir()
Path('/run/fail2ban').mkdir()
source = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('fresh', source / 'scripts/fresh-install.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
with tempfile.TemporaryDirectory(prefix='f2b-fresh-linux-') as temporary:
    temporary = Path(temporary)
    private_etc = temporary / 'etc'
    shutil.copytree('/etc', private_etc, symlinks=True)
    run('mount', '--bind', str(private_etc), '/etc')
    # Every written path is private; the source checkout stays read-only.
    for name in ('/usr/local', '/var/log', '/var/lib/fail2ban', '/var/backups', '/opt'):
        clone = temporary / 'root' / name.lstrip('/')
        clone.mkdir(parents=True)
        Path(name).mkdir(parents=True, exist_ok=True)
        run('mount', '--bind', str(clone), name)
    for name in ('/etc/nftables.d', '/etc/systemd/system/nftables.service.d', '/etc/f2b'):
        Path(name).mkdir(parents=True, exist_ok=True)
        assert not list(Path(name).iterdir()), 'Fixture must start without custom config'
    assert not Path('/etc/fail2ban/jail.local').exists()
    stock = '#!/usr/sbin/nft -f\nflush ruleset\ntable inet filter {\n' + ''.join(
        ' chain ' + chain + ' { type filter hook ' + chain + ' priority filter; }\n'
        for chain in ('input', 'forward', 'output')) + '}\n'
    Path('/etc/nftables.conf').write_text(stock)
    original_conffiles = m.conffiles
    m.conffiles = lambda package: ({'/etc/nftables.conf': hashlib.md5(stock.encode()).hexdigest()}
                                  if package == 'nftables' else original_conffiles(package))
    stubs = temporary / 'bin'
    stubs.mkdir()
    (stubs / 'systemctl').write_text('#!/bin/sh\ncase "$*" in\n'
        '"stop fail2ban") fail2ban-client stop >/dev/null 2>&1; exit 0;;\n'
        '"enable --now fail2ban") exec fail2ban-client -x start;;\n'
        '"is-active --quiet fail2ban") exec fail2ban-client ping >/dev/null 2>&1;;\n'
        '"is-enabled --quiet nftables.service") exit 1;;\n'
        '"list-unit-files") echo fail2ban.service;;\n'
        '"daemon-reload"|"enable nftables.service"|"enable --now cron"|"is-active --quiet cron") exit 0;;\n'
        '*) echo "Forbidden systemctl: $*" >&2; exit 99;;\nesac\n')
    (stubs / 'crontab').write_text('#!/bin/sh\n[ "$1" = -l ] || exit 99\nexit 0\n')
    (stubs / 'sudo').write_text('#!/bin/sh\nexec "$@"\n')
    nft = shutil.which('nft')
    nft_log = temporary / 'nft-commands.txt'
    (stubs / 'nft').write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> "' + str(nft_log) + '"\nexec "' + nft + '" "$@"\n')
    for file in stubs.iterdir(): file.chmod(0o755)
    os.environ['PATH'] = str(stubs) + ':' + os.environ['PATH']
    os.environ['TERM'] = 'xterm'
    run('nft', 'add', 'table', 'ip', 'synthetic_foreign')
    run('nft', 'add', 'chain', 'ip', 'synthetic_foreign', 'guard')
    run('nft', 'add', 'rule', 'ip', 'synthetic_foreign', 'guard', 'tcp', 'dport', '12345', 'drop')
    before = m.nft_preflight()
    from argparse import Namespace
    args = Namespace(ssh=False, ssh_port=22, docker=False, mail_to=None,
                     npm_log_dir=None, bootstrap_stock_nft=True)
    selected = m.policy(args)
    assert selected[1] == ['recidive', 'manualblock']
    m.file_guards()
    try:
        m.install(args, before, selected)
        assert Path('/etc/f2b/fresh-install.state').read_text() == 'complete\n'
        assert 'flush ruleset' not in Path('/etc/nftables.conf').read_text()
        assert not Path('/var/log/auth.log').exists()
        assert not Path('/opt/rustnpm/data/logs').exists()
        run('fail2ban-client', 'set', 'manualblock', 'banip', '192.0.2.7')
        run('fail2ban-client', 'set', 'manualblock', 'banip', '2001:db8::7')
        run('/usr/bin/python3', '/usr/local/sbin/f2b-ipv6-sync.py')
        for family, ip in ((4, '192.0.2.7'), (6, '2001:db8::7')):
            elements = run('nft', 'list', 'set', 'inet', 'docker-block', 'docker-banned-ipv' + str(family)).stdout
            assert ip in elements
        after = json.loads(run('nft', '-j', 'list', 'ruleset').stdout)
        assert m.load_upgrade().external_nft_digest(before) == m.load_upgrade().external_nft_digest(after)
        config_before = Path('/etc/nftables.conf').read_bytes()
        try: m.file_guards()
        except m.FreshError: pass
        else: raise AssertionError('Rerun did not refuse existing install')
        assert Path('/etc/nftables.conf').read_bytes() == config_before
        commands = nft_log.read_text()
        assert 'flush ruleset' not in commands
        assert all('-c -f /etc/nftables.conf' in line for line in commands.splitlines()
                   if '-f /etc/nftables.conf' in line), 'Only isolated syntax checks may read persistence'
        assert 'delete table' not in commands
        print('PASS: real fresh core install, active/log-backed jail count, dual-family bans, scoped persistence, foreign-rule preservation and rerun refusal (systemd simulated)')
    finally:
        run('fail2ban-client', 'stop', check=False)
