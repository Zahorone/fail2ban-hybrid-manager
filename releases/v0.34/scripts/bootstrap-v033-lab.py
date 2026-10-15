#!/usr/bin/python3
"""Disposable synthetic VM only. Read-only preflight by default; no old installer."""
import argparse
import configparser
import hashlib
import grp
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import time

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
BASELINE = '196400970b669f8fd43eebadad3b971125de857e'
PRIVATE_LOGS = Path('/var/lib/f2b-v033-lab/logs')
CANONICAL_LOGS = ('fail2ban.log', 'fail2ban-blocked-ips.txt', 'f2b-docker-sync.log', 'f2b-wrapper.log')
MAIL_SINK = ('# Synthetic lab only: preserve the real binary-safe mail action,\n'
             '# but consume its output locally and never query external whois.\n'
             '[Definition]\n_whois_command = printf %%b "Synthetic lab: external whois disabled\\n"\n'
             '[Init]\nmailcmd = /bin/cat >> /var/lib/f2b-v033-lab/logs/mail.log\n')


def run(*parts):
    result = subprocess.run(parts, text=True, capture_output=True)
    if result.returncode: raise RuntimeError('Lab command failed: ' + ' '.join(parts) + '\n' + result.stderr[-1500:])
    return result.stdout


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module); return module


def inventory():
    manifest = json.loads((ROOT / 'LAB-MANIFEST.json').read_text())
    if manifest.get('schema') != 1 or manifest.get('canonical_source') != BASELINE: raise ValueError('Wrong lab provenance')
    if any(path.is_symlink() for path in ROOT.rglob('*')): raise ValueError('Lab symlinks forbidden')
    expected = manifest['files']
    if {str(path.relative_to(ROOT)) for path in ROOT.rglob('*') if path.is_file()} != set(expected) | {'LAB-MANIFEST.json', 'SHA256SUMS'}:
        raise ValueError('Lab inventory mismatch; keep outputs/cache outside the payload')
    for name, digest in expected.items():
        relative = Path(name)
        if relative.is_absolute() or '..' in relative.parts or hashlib.sha256((ROOT / relative).read_bytes()).hexdigest() != digest:
            raise ValueError('Lab checksum mismatch')
    return manifest


def mapping():
    result = {Path('/etc/fail2ban') / folder / path.name: path for folder in ('filter.d', 'action.d')
              for path in (ROOT / 'baseline' / ('filters' if folder == 'filter.d' else 'actions')).iterdir()}
    result.update({Path('/etc/fail2ban/jail.local'): ROOT / 'baseline/config/jail.local',
        Path('/usr/local/bin/f2b'): ROOT / 'baseline/scripts/f2b-wrapper-v033.sh',
        Path('/usr/local/sbin/f2b-docker-hook'): ROOT / 'baseline/scripts/f2b-docker-hook.sh',
        Path('/usr/local/sbin/f2b-ipv6-sync.py'): ROOT / 'baseline/scripts/f2b-ipv6-sync.py'})
    return result


def lab_policy():
    parser = configparser.ConfigParser(interpolation=None); parser.read(ROOT / 'baseline/config/jail.local')
    output = configparser.ConfigParser(interpolation=None)
    output['DEFAULT'] = {'ignoreip': '127.0.0.0/8 ::1 192.0.2.123 2001:db8::123', 'action_mwl': '%(action_)s'}
    for jail in parser.sections():
        output[jail] = {'enabled': 'false' if jail in {'sshd', 'sshd-slowattack'} else 'true', 'action': '%(action_)s'}
        if jail == 'recidive':
            output[jail]['action'] = ('nftables-recidive[name=%(__name__)s, bantime="%(bantime)s", port="%(port)s", '
                                     'protocol="%(protocol)s", chain="%(chain)s"]\ndocker-sync-hook')
    output['manualblock']['bantime'] = '7200'
    # The pinned upgrade requires this genuine binary-safe evidence action.
    # Keep it; change only its transport via the explicit action .local below.
    output['nginx-php-errors']['action'] = (
        '%(banaction)s[port="%(port)s", protocol="%(protocol)s"]\ndocker-sync-hook\n'
        'sendmail-whois-lines[dest="%(destemail)s", sender="%(sender)s", sendername="%(sendername)s", '
        'protocol="%(protocol)s", chain="%(chain)s", logpath="%(logpath)s", grepopts="-a -m <grepmax>"]')
    stream = io.StringIO(); output.write(stream); return stream.getvalue(), [j for j in parser.sections() if output[j]['enabled'] == 'true']


def safe(target):
    for path in (target, *target.parents):
        if not path.exists() and not path.is_symlink(): continue
        info = path.lstat()
        check_node(path, info)


def check_node(path, info, syslog_parent=False):
    reason = None
    if stat.S_ISLNK(info.st_mode): reason = 'symlink'
    elif info.st_uid != 0: reason = 'owner is not root'
    elif info.st_mode & 0o002: reason = 'world-writable'
    elif info.st_mode & 0o020:
        try: syslog_gid = grp.getgrnam('syslog').gr_gid
        except KeyError: syslog_gid = None
        if not (syslog_parent and path == Path('/var/log') and stat.S_ISDIR(info.st_mode)
                and info.st_gid == syslog_gid and stat.S_IMODE(info.st_mode) == 0o775):
            reason = 'group-writable outside trusted root:syslog 0775 /var/log'
    if reason: raise ValueError('Unsafe lab target/parent: ' + str(path) + ': ' + reason)


def log_directory():
    # Deliberately separate from safe(): only this exact distro directory may
    # trust syslog. Pin each ancestor with O_NOFOLLOW, including the final one.
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part, path in (('var', Path('/var')), ('log', Path('/var/log'))):
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd); fd = next_fd
            check_node(path, os.fstat(fd), syslog_parent=True)
        return fd
    except Exception as error:
        os.close(fd)
        raise ValueError('Unsafe log directory /var/log: ' + str(error)) from error


def canonical_logs(create=False):
    fd = log_directory()
    try:
        for name in CANONICAL_LOGS:
            path = Path('/var/log') / name
            try:
                info = os.stat(name, dir_fd=fd, follow_symlinks=False)
            except FileNotFoundError:
                if not create: continue
                # Never follow/truncate a file inserted since preflight.
                child = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                0o600, dir_fd=fd)
            else:
                check_node(path, info)
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                    raise ValueError('Unsafe lab log: ' + str(path) + ': expected single-link regular file')
                if name != 'fail2ban.log':
                    raise ValueError('Synthetic lab refuses existing traffic/output: ' + str(path))
                # Preserve an existing distribution Fail2Ban log without reading
                # or truncating it; verify the opened inode against lstat.
                child = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
                opened = os.fstat(child)
                if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
                    os.close(child)
                    raise ValueError('Unsafe lab log: ' + str(path) + ': replaced during validation')
            os.close(child)
    finally: os.close(fd)


def preflight(bundle):
    inventory()
    upgrade = load('lab_upgrade', bundle / 'scripts/upgrade-v033-v034.py')
    upgrade.validate_package(bundle, upgrade.install_map(bundle))
    package = upgrade.verify_package_manifest(bundle)
    if package['source_commit'] != BASELINE: raise ValueError('Use the exact integrated 1964009 bundle')
    fresh = load('lab_fresh', bundle / 'scripts/fresh-install.py')
    fresh.platform_check(); fresh.file_guards()
    fresh.dependencies(argparse.Namespace(ssh=False, docker=False, mail_to=None, install_prerequisites=False))
    foreign = fresh.nft_preflight()
    written = ('/etc/fail2ban/jail.d/zz-v033-lab.local', '/etc/f2b/v033-lab.state',
               '/etc/nftables.conf', '/etc/nftables.d/fail2ban-filter.nft', '/etc/nftables.d/docker-block.nft',
               '/etc/fail2ban/action.d/sendmail-whois-lines.local', str(PRIVATE_LOGS / 'mail.log'))
    for name in written:
        target = Path(name); safe(target)
        if target.exists() and not target.is_file(): raise ValueError('Expected regular lab output target')
    for target, source in mapping().items():
        safe(target)
        if target.exists():
            stock = fresh.conffiles('fail2ban').get(str(target))
            if not stock or hashlib.md5(target.read_bytes()).hexdigest() != stock: raise ValueError('Not a clean managed target: ' + str(target))
        if str(target) in package['known_targets'] and hashlib.sha256(source.read_bytes()).hexdigest() not in package['known_targets'][str(target)]:
            raise ValueError('Canonical v0.33 component not recognized by pinned upgrade: ' + str(target))
    canonical_logs()
    for name in ('/var/lib/f2b-v033-lab', '/opt/rustnpm/data/logs'):
        path = Path(name); safe(path)
        if path.exists(): raise ValueError('Synthetic lab refuses existing traffic source: ' + name)
    policy, enabled = lab_policy()
    with tempfile.TemporaryDirectory(prefix='f2b-v033-lab-check-') as directory:
        candidate = Path(directory) / 'fail2ban'; shutil.copytree('/etc/fail2ban', candidate, symlinks=True)
        for target, source in mapping().items():
            if str(target).startswith('/etc/fail2ban/'):
                destination = candidate / target.relative_to('/etc/fail2ban'); destination.parent.mkdir(parents=True, exist_ok=True); shutil.copyfile(source, destination)
        (candidate / 'jail.d/zz-v033-lab.local').write_text(policy)
        (candidate / 'action.d/sendmail-whois-lines.local').write_text(MAIL_SINK)
        # Shadow-only log paths let -t validate without manufacturing live logs.
        fixture = Path(directory) / 'synthetic.log'; fixture.touch()
        shadow = configparser.ConfigParser(interpolation=None)
        for jail in enabled: shadow[jail] = {'logpath': str(fixture), 'backend': 'auto'}
        with (candidate / 'jail.d/zzz-shadow-only.local').open('w') as stream: shadow.write(stream)
        run('fail2ban-client', '-c', str(candidate), '-t')
    print('PASS: read-only lab preflight; exact recognized v0.33-ipv6.1; selected synthetic jails=' + str(len(enabled)))
    return upgrade, fresh, foreign, policy, enabled


def owned_commands():
    lines = []
    for table, sets in (('fail2ban-filter', ('f2b-recidive', 'f2b-recidive-v6')),
                        ('docker-block', ('docker-banned-ipv4', 'docker-banned-ipv6'))):
        lines.append('add table inet ' + table)
        for name in sets:
            kind = 'ipv6_addr' if name.endswith(('ipv6', '-v6')) else 'ipv4_addr'
            lines.append('add set inet ' + table + ' ' + name + ' { type ' + kind + '; flags timeout; }')
    for hook in ('input', 'forward'):
        chain = 'f2b-' + hook
        lines.append('add chain inet fail2ban-filter ' + chain + ' { type filter hook ' + hook + ' priority -100; }')
        for family, name in (('ip', 'f2b-recidive'), ('ip6', 'f2b-recidive-v6')):
            lines.append('add rule inet fail2ban-filter ' + chain + ' ' + family + ' saddr @' + name + ' drop')
    lines.append('add chain inet docker-block prerouting { type filter hook prerouting priority -110; }')
    for family, name in (('ip', 'docker-banned-ipv4'), ('ip6', 'docker-banned-ipv6')):
        lines.append('add rule inet docker-block prerouting ' + family + ' saddr @' + name + ' drop')
    return '\n'.join(lines) + '\n'


def apply(bundle):
    upgrade, fresh, before, policy, enabled = preflight(bundle)
    safe(Path('/var/backups'))
    backup = Path(tempfile.mkdtemp(prefix='f2b-v033-lab-', dir='/var/backups')); backup.chmod(0o700)
    run('tar', '--acls', '--xattrs', '-cpf', str(backup / 'original-config.tar'), '-C', '/', 'etc/fail2ban', 'etc/nftables.conf')
    print('Private lab backup:', backup)
    run('systemctl', 'stop', 'fail2ban')
    Path('/etc/f2b').mkdir(exist_ok=True); Path('/etc/f2b/v033-lab.state').write_text('incomplete; use clean VM snapshot on failure\n')
    for target, source in mapping().items():
        target.parent.mkdir(parents=True, exist_ok=True); shutil.copyfile(source, target)
        target.chmod(0o755 if str(target).startswith('/usr/local/') else 0o644)
    Path('/etc/fail2ban/jail.d/zz-v033-lab.local').write_text(policy)
    Path('/etc/fail2ban/action.d/sendmail-whois-lines.local').write_text(MAIL_SINK)
    PRIVATE_LOGS.parent.mkdir(mode=0o700)
    PRIVATE_LOGS.mkdir(mode=0o700)
    with (PRIVATE_LOGS / 'mail.log').open('x') as stream: os.fchmod(stream.fileno(), 0o600)
    Path('/opt/rustnpm/data/logs').mkdir(parents=True)
    for name in ('fallback_access.log', 'fallback_http_access.log', 'fallback_error.log', 'proxy-host-1_access.log', 'proxy-host-1_error.log'):
        (Path('/opt/rustnpm/data/logs') / name).touch()
    canonical_logs(create=True)
    with tempfile.NamedTemporaryFile(mode='w', prefix='f2b-v033-owned-', suffix='.nft') as source:
        source.write(owned_commands()); source.flush(); run('nft', '-f', source.name)
    Path('/etc/nftables.d').mkdir(exist_ok=True)
    for table in ('fail2ban-filter', 'docker-block'):
        (Path('/etc/nftables.d') / (table + '.nft')).write_text(run('nft', '-s', 'list', 'table', 'inet', table))
    # Replace only the verified stock persistence file; NEVER execute/load it.
    Path('/etc/nftables.conf').write_text('# Synthetic v0.33 lab: scoped includes only\ninclude "/etc/nftables.d/fail2ban-filter.nft"\ninclude "/etc/nftables.d/docker-block.nft"\n')
    run('fail2ban-client', '-t'); run('systemctl', 'enable', '--now', 'cron'); run('systemctl', 'start', 'fail2ban')
    fresh.wait_ready(enabled)
    run('systemctl', 'restart', 'fail2ban'); fresh.wait_ready(enabled)
    if upgrade.external_nft_digest(before) != upgrade.external_nft_digest(json.loads(run('nft', '-j', 'list', 'ruleset'))):
        raise ValueError('Foreign rules changed; never automatically overwrite them')
    for target, source in mapping().items():
        if target.read_bytes() != source.read_bytes(): raise ValueError('Canonical component changed')
    for address in ('192.0.2.8', '2001:db8::8'): run('fail2ban-client', 'set', 'manualblock', 'banip', address)
    run('/usr/bin/python3', str(bundle / 'scripts/upgrade-v033-v034.py'))
    Path('/etc/f2b/v033-lab.state').write_text('complete; synthetic only; upgrade preflight passed\n')
    print('PASS: synthetic baseline restarted, canonical bytes intact, exact 1964009 upgrade preflight passed; no global firewall load')


def main():
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument('--upgrade-bundle', type=Path, required=True)
    mode = parser.add_mutually_exclusive_group(); mode.add_argument('--check', action='store_true'); mode.add_argument('--apply', action='store_true')
    parser.add_argument('--snapshot-confirmed', action='store_true', help='operator confirms separate disposable clean snapshot')
    args = parser.parse_args()
    try:
        if os.geteuid() != 0: raise ValueError('Run with sudo')
        if args.apply and not args.snapshot_confirmed: raise ValueError('Apply requires --snapshot-confirmed on a disposable VM')
        if args.apply: apply(args.upgrade_bundle.resolve())
        else: preflight(args.upgrade_bundle.resolve())
        return 0
    except Exception as error:
        print('REFUSED/FAILED:', error, file=sys.stderr)
        if args.apply: print('Do not rerun/flush; retain backup and restore the clean VM snapshot after review', file=sys.stderr)
        return 1


if __name__ == '__main__': sys.exit(main())
