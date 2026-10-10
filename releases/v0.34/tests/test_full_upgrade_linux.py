"""Full file transaction with real Fail2Ban/nft, PRIVATE mount/net namespaces.

systemd/cron are deliberately simulated: this is NOT a VM/reboot test.
"""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import time

REPO = Path(__file__).resolve().parents[3]


def run(*args, check=True):
    result = subprocess.run(args, check=False, text=True, capture_output=True)
    if check and result.returncode:
        raise AssertionError(f'{args}:\n{result.stdout}\n{result.stderr}')
    return result


def wait(predicate):
    for _ in range(150):
        if predicate(): return
        time.sleep(.1)
    raise AssertionError('Timed out waiting for real daemon')


run('mount', '--make-rprivate', '/')
run('mount', '-t', 'tmpfs', 'tmpfs', '/run')
Path('/run/lock').mkdir()
with tempfile.TemporaryDirectory(prefix='f2b-full-upgrade-') as temporary:
    temporary = Path(temporary)
    with tarfile.open('/tmp/f2b-complete-upgrade.tar.gz') as archive:
        archive.extractall(temporary / 'package')
    package = next((temporary / 'package').iterdir())
    script = package / 'scripts/upgrade-v033-v034.py'
    legacy = REPO / 'releases/v0.33'
    private_etc = temporary / 'private-etc'
    shutil.copytree('/etc', private_etc, symlinks=True)
    run('mount', '--bind', str(private_etc), '/etc')
    # Clone just fixture-owned paths and bind them privately, never the host.
    bind_targets = ('/etc/fail2ban', '/etc/nftables.d', '/etc/cron.d', '/etc/systemd/system',
                    '/usr/local', '/etc/f2b', '/var/lib/fail2ban', '/var/log', '/opt/rustnpm/data/logs')
    for name in bind_targets:
        target = Path(name)
        clone = temporary / 'root' / target.relative_to('/')
        clone.mkdir(parents=True)
        if name == '/etc/fail2ban': shutil.copytree(target, clone, dirs_exist_ok=True)
        target.mkdir(parents=True, exist_ok=True)
        run('mount', '--bind', str(clone), name)
    for name in ('bin', 'sbin', 'libexec'): (Path('/usr/local') / name).mkdir()
    for source in (legacy / 'filters').glob('*.conf'):
        shutil.copy2(source, Path('/etc/fail2ban/filter.d') / source.name)
    for source in (legacy / 'actions').iterdir():
        shutil.copy2(source, Path('/etc/fail2ban/action.d') / source.name)
    shutil.copy2(legacy / 'config/jail.local', '/etc/fail2ban/jail.local')
    shutil.copy2(legacy / 'scripts/f2b-wrapper-v033.sh', '/usr/local/bin/f2b')
    shutil.copy2(legacy / 'scripts/f2b-docker-hook.sh', '/usr/local/sbin/f2b-docker-hook')
    Path('/usr/local/bin/f2b').chmod(0o755)
    Path('/usr/local/sbin/f2b-docker-hook').chmod(0o755)
    # Synthetic, independent site override must survive every transaction.
    site = Path('/etc/fail2ban/filter.d/site-preserved.local')
    site.write_text('[Definition]\n# namespace fixture only\n')
    original_jail = Path('/etc/fail2ban/jail.local').read_bytes()
    for name in ('auth.log', 'fail2ban.log', 'fail2ban-blocked-ips.txt'):
        (Path('/var/log') / name).touch()
    for name in ('fallback_access.log', 'fallback_http_access.log', 'dead-host_access.log',
                 'proxy-host-1_access.log', 'fallback_error.log', 'proxy-host-1_error.log'):
        (Path('/opt/rustnpm/data/logs') / name).touch()
    nft_config = Path('/etc/nftables.conf')
    nft_config.write_text('flush ruleset\ninclude "/etc/nftables.d/fail2ban-filter.nft"\ninclude "/etc/nftables.d/docker-block.nft"\n')
    # Executable stubs model only daemon lifecycle/cron availability. No real
    # host service is stopped, started or daemon-reloaded in this namespace.
    stubs = temporary / 'bin'
    stubs.mkdir()
    systemctl = stubs / 'systemctl'
    systemctl.write_text('#!/bin/sh\ncase "$*" in\n'
        '"stop fail2ban") exec fail2ban-client stop;;\n'
        '"start fail2ban") exec fail2ban-client -x start;;\n'
        '"daemon-reload"|"is-active --quiet cron") exit 0;;\n'
        '"is-active fail2ban nftables docker") printf "active\\nactive\\nactive\\n";;\n'
        '*) echo "Forbidden systemctl: $*" >&2; exit 99;;\nesac\n')
    cron = stubs / 'crontab'
    cron.write_text('#!/bin/sh\n[ "$1" = -l ] || exit 99\n# no original root cron in fixture\nexit 0\n')
    for path in stubs.iterdir(): path.chmod(0o755)
    import os
    os.environ['PATH'] = str(stubs) + ':' + os.environ['PATH']
    # Real foreign NAT sentinel and owned legacy tables, including IPv6 hooks.
    run('nft', 'add', 'table', 'ip', 'foreign-nat')
    run('nft', 'add', 'chain', 'ip', 'foreign-nat', 'prerouting', '{ type nat hook prerouting priority dstnat; }')
    run('nft', 'add', 'rule', 'ip', 'foreign-nat', 'prerouting', 'tcp', 'dport', '8080', 'dnat', 'to', '192.0.2.90:80')
    foreign = run('nft', '-s', 'list', 'table', 'ip', 'foreign-nat').stdout
    for table, names in (('fail2ban-filter', ('f2b-recidive', 'f2b-recidive-v6')),
                         ('docker-block', ('docker-banned-ipv4', 'docker-banned-ipv6'))):
        run('nft', 'add', 'table', 'inet', table)
        for name in names:
            kind = 'ipv6_addr' if name.endswith(('ipv6', '-v6')) else 'ipv4_addr'
            run('nft', 'add', 'set', 'inet', table, name, '{ type ' + kind + '; flags interval,timeout; auto-merge; timeout 30d; }')
    for chain, hook in (('f2b-input', 'input'), ('f2b-forward', 'forward')):
        run('nft', 'add', 'chain', 'inet', 'fail2ban-filter', chain, '{ type filter hook ' + hook + ' priority -100; }')
        for family, name in (('ip', 'f2b-recidive'), ('ip6', 'f2b-recidive-v6')):
            run('nft', 'add', 'rule', 'inet', 'fail2ban-filter', chain, family, 'saddr', '@' + name, 'drop')
    run('nft', 'add', 'chain', 'inet', 'docker-block', 'prerouting', '{ type filter hook prerouting priority -110; }')
    for family, name in (('ip', 'docker-banned-ipv4'), ('ip6', 'docker-banned-ipv6')):
        run('nft', 'add', 'rule', 'inet', 'docker-block', 'prerouting', family, 'saddr', '@' + name, 'drop')
    try:
        run('fail2ban-client', '-x', 'start')
        wait(lambda: run('fail2ban-client', 'ping', check=False).returncode == 0)
        for ip in ('192.0.2.8', '2001:db8::8'):
            run('fail2ban-client', 'set', 'manualblock', 'banip', ip)
        wait(lambda: '2001:db8::8' in run('fail2ban-client', 'get', 'manualblock', 'banip').stdout)
        command = ['/usr/bin/python3', str(script)]
        # Read-only preflight leaves existing site files/firewall unchanged.
        before = {p: p.read_bytes() for p in Path('/etc/fail2ban').rglob('*') if p.is_file()}
        result = run(*command)
        print(result.stdout)
        assert all(p.read_bytes() == data for p, data in before.items())
        assert foreign == run('nft', '-s', 'list', 'table', 'ip', 'foreign-nat').stdout
        result = run(*command, '--apply', '--backup-dir', str(temporary / 'backups'))
        print(result.stdout)
        backup = Path(next(line.split(': ', 1)[1] for line in result.stdout.splitlines() if line.startswith('Backup complete:')))
        assert json.loads((backup / 'fail2ban-ban-times.json').read_text())['manualblock']
        assert Path('/etc/fail2ban/jail.local').read_bytes() == original_jail
        assert site.read_bytes() == before[site]
        assert 'flush ruleset' not in Path('/etc/nftables.conf').read_text().split('# v0.34 upgrade:')[0]
        assert foreign == run('nft', '-s', 'list', 'table', 'ip', 'foreign-nat').stdout
        # Reapplication must pass preflight with the now-installed v0.34 files.
        print(run(*command).stdout)
        run('fail2ban-client', 'set', 'f2b-webshell-sweep', 'banip', '192.0.2.99')
        wait(lambda: '192.0.2.99' in run('fail2ban-client', 'get', 'f2b-webshell-sweep', 'banip').stdout)
        print(run(*command, '--rollback', str(backup)).stdout)
        assert Path('/etc/fail2ban/jail.local').read_bytes() == original_jail
        assert not Path('/etc/fail2ban/jail.d/99-webshell-sweep.local').exists()
        assert not Path('/etc/cron.d/f2b-v034-sync').exists()
        restored = run('fail2ban-client', 'get', 'manualblock', 'banip').stdout
        assert all(ip in restored for ip in ('192.0.2.8', '2001:db8::8', '192.0.2.99'))
        assert foreign == run('nft', '-s', 'list', 'table', 'ip', 'foreign-nat').stdout
        print('PASS: legacy v0.33 full preflight/apply/repeat/rollback; overrides, timed bans, new-jail fallback and foreign NAT preserved (systemd/cron simulated)')
    except Exception:
        print('\n'.join(Path('/var/log/fail2ban.log').read_text(errors='replace').splitlines()[-80:]))
        raise
    finally:
        run('fail2ban-client', 'stop', check=False)
        for target in reversed(bind_targets): run('umount', target)
        run('umount', '/etc')
