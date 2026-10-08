#!/usr/bin/python3
"""Apply the IPv6 maintenance patch without rebuilding the firewall."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

base = Path(__file__).resolve().parent


def run(*args):
    result = subprocess.run(args, text=True, capture_output=True)
    if result.returncode:
        raise RuntimeError(f'{args!r}\n{result.stdout}\n{result.stderr}')
    return result.stdout


if os.geteuid():
    raise SystemExit('Run with sudo')
if Path('/etc/fail2ban/action.d/nftables-recidive.local').exists():
    raise SystemExit('Existing nftables-recidive.local override: review it before upgrading; no changes made.')

sources = {
    Path('/etc/fail2ban/jail.d/99-recidive-mail.local'): base.parent / 'config/recidive-mail.local',
    Path('/usr/local/bin/f2b'): base / 'f2b-wrapper-v033.sh',
    Path('/usr/local/sbin/f2b-ipv6-sync.py'): base / 'f2b-ipv6-sync.py',
    Path('/usr/local/sbin/f2b-docker-hook'): base / 'f2b-docker-hook.sh',
    Path('/etc/fail2ban/action.d/nftables-recidive.conf'): base.parent / 'actions/nftables-recidive.conf',
}
for source in sources.values():
    if not source.is_file():
        raise SystemExit(f'Missing package file: {source}')
print(run('bash', '-n', str(base / 'f2b-wrapper-v033.sh')))
print(run('/usr/bin/python3', str(base.parent / 'tests/test_wrapper.py')))
print(run('unshare', '--net', '/usr/bin/python3', str(base.parent / 'tests/test_ipv6_sync.py'), '--net'))
for chain in ('f2b-input', 'f2b-forward'):
    if 'ip6 saddr @f2b-recidive-v6 drop' not in run('nft', 'list', 'chain', 'inet', 'fail2ban-filter', chain):
        raise SystemExit(f'Missing IPv6 recidive drop rule in {chain}; no changes made.')
print(run('/usr/bin/python3', str(base / 'f2b-ipv6-sync.py'), 'check'))
with tempfile.TemporaryDirectory() as temporary:
    candidate = Path(temporary) / 'fail2ban'
    shutil.copytree('/etc/fail2ban', candidate)
    shutil.copy2(sources[Path('/etc/fail2ban/action.d/nftables-recidive.conf')], candidate / 'action.d/nftables-recidive.conf')
    shutil.copy2(base.parent / 'config/recidive-mail.local', candidate / 'jail.d/99-recidive-mail.local')
    dump = run('fail2ban-client', '-c', str(candidate), '-d')
    if 'f2b-recidive-v6' not in dump:
        raise SystemExit('IPv6 action did not resolve; no changes made.')

backup = Path(tempfile.mkdtemp(prefix='f2b-ipv6-upgrade-', dir='/var/backups'))
saved = {}
for target in sources:
    saved[target] = target.exists()
    if target.exists():
        destination = backup / str(target).lstrip('/')
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(target, destination)
try:
    staged_files = []
    for target, source in sources.items():
        staged = target.with_name(target.name + '.ipv6-new')
        staged_files.append(staged)
        shutil.copyfile(source, staged)
        staged.chmod(0o644 if target.suffix in ('.conf', '.local') else 0o755)
        os.replace(staged, target)
    print(run('fail2ban-client', '-t'))
    print(run('fail2ban-client', 'reload', 'recidive'))
    for _ in range(2):
        print(run('/usr/bin/python3', '/usr/local/sbin/f2b-ipv6-sync.py'))
except Exception as original_error:
    rollback_errors = []
    for target, existed in saved.items():
        try:
            if existed:
                shutil.copy2(backup / str(target).lstrip('/'), target)
            else:
                target.unlink(missing_ok=True)
        except Exception as rollback_error:
            rollback_errors.append(f'{target}: {rollback_error}')
    try:
        run('fail2ban-client', 'reload', 'recidive')
    except Exception as rollback_error:
        rollback_errors.append(f'recidive reload: {rollback_error}')
    if rollback_errors:
        raise RuntimeError(
            f'Upgrade failed: {original_error}\nRollback also had errors:\n' +
            '\n'.join(rollback_errors)
        ) from original_error
    raise
finally:
    for staged in locals().get('staged_files', []):
        staged.unlink(missing_ok=True)
print(f'PASS: IPv6 patch installed. Backup: {backup}')
print('Docker was not restarted. No global firewall reload was performed.')
