#!/usr/bin/python3
"""Fail-closed fresh installation. No cleanup, upgrades or global firewall loads."""
import argparse
import configparser
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time

ROOT = Path('/')
SOURCE = Path(__file__).resolve().parents[1]
CORE = ('nftables', 'fail2ban', 'python3', 'cron', 'iproute2', 'util-linux',
        'sudo', 'acl', 'attr', 'tar', 'gzip', 'coreutils', 'grep', 'sed', 'gawk')
COMMANDS = ('nft', 'fail2ban-client', 'systemctl', 'crontab', 'ip', 'flock',
            'sudo', 'tar', 'getfacl', 'getfattr', 'logger', 'bash')
OWNED = {'fail2ban-filter', 'docker-block'}


class FreshError(RuntimeError):
    pass


def run(*args, check=True, timeout=None):
    result = subprocess.run(args, text=True, capture_output=True, timeout=timeout)
    if check and result.returncode:
        raise FreshError('Command failed: ' + ' '.join(args) + '\n' + result.stdout[-1500:] + result.stderr)
    return result


def path(name):
    return ROOT / name.lstrip('/')


def platform_check():
    values = {}
    for line in path('/etc/os-release').read_text().splitlines():
        if '=' in line:
            key, value = line.split('=', 1)
            values[key] = value.strip('"')
    if values.get('ID') not in {'ubuntu', 'debian'}:
        raise FreshError('Only Debian/Ubuntu with apt and systemd are supported')
    arch = run('dpkg', '--print-architecture').stdout.strip()
    if arch not in {'amd64', 'arm64'}:
        raise FreshError('Supported architectures: amd64, arm64')
    if path('/proc/1/comm').read_text().strip() != 'systemd' or not path('/run/systemd/system').is_dir():
        raise FreshError('A booted systemd host is required; containers/chroots are not a full install target')
    run('systemctl', 'show', '--property=Version', '--value')
    print('Platform:', values['ID'], values.get('VERSION_ID', 'unknown'), arch)
    print('Development installer: OS/architecture detection is not VM/reboot validation')


def packages(args):
    selected = list(CORE)
    if args.ssh:
        selected += ['openssh-server', 'python3-systemd']
    if args.docker and shutil.which('docker') is None:
        selected += ['docker.io']
    if args.mail_to:
        selected += ['mailutils', 'whois']
        if shutil.which('sendmail') is None:
            selected += ['default-mta']
    return selected


def missing_packages(selected):
    return [name for name in selected if run('dpkg-query', '-W', '-f=${Status}', name,
            check=False).stdout.strip() != 'install ok installed']


def dependencies(args):
    missing = missing_packages(packages(args))
    if missing:
        print('Missing packages:', ' '.join(missing))
        print('Explicit package-only setup: rerun with --install-prerequisites and the same profile flags')
        if not args.install_prerequisites:
            raise FreshError('Prerequisites missing; no installation changes made')
        run('apt-get', 'update')
        # Keep package prompts visible, particularly when an MTA was selected.
        subprocess.run(['apt-get', 'install', '-y', *missing], check=True)
        if missing_packages(packages(args)):
            raise FreshError('Package installation did not satisfy the selected prerequisites')
    missing_commands = [name for name in COMMANDS if shutil.which(name) is None]
    if missing_commands:
        raise FreshError('Missing commands after package check: ' + ', '.join(missing_commands))
    run('bash', '-c', 'test "${BASH_VERSINFO[0]}" -ge 4')
    run('/usr/bin/python3', '-c', 'from fail2ban.client.csocket import CSocket')
    if args.ssh:
        run('/usr/bin/python3', '-c', 'from systemd import journal')
        run('sshd', '-t')
    if args.docker:
        run('docker', 'info', '--format', '{{.ServerVersion}}')
    if args.mail_to and (shutil.which('sendmail') is None or shutil.which('whois') is None):
        raise FreshError('Selected mail requires a configured sendmail-compatible MTA and whois')


def file_guards():
    for name in ('/etc/fail2ban', '/etc/fail2ban/jail.d', '/etc/fail2ban/filter.d',
                 '/etc/fail2ban/action.d', '/etc/f2b', '/usr/local/bin', '/usr/local/sbin',
                 '/usr/local/libexec'):
        if path(name).is_symlink():
            raise FreshError('Custom symlinked installation path requires review: ' + name)
    for name in ('/usr/local/bin/f2b', '/etc/fail2ban/jail.local', '/etc/f2b/fresh-install.state'):
        if path(name).exists() or path(name).is_symlink():
            raise FreshError('Existing installation detected at ' + name + '; use upgrade/recovery, not fresh install')
    for name in ('/etc/nftables.d', '/etc/systemd/system/nftables.service.d'):
        folder = path(name)
        if folder.is_symlink() or (folder.exists() and any(folder.iterdir())):
            raise FreshError('Existing custom configuration requires review: ' + name)
    if path('/etc/systemd/system/nftables.service').exists():
        raise FreshError('Custom nftables service requires review')
    if list(path('/etc/fail2ban').rglob('*.local')):
        raise FreshError('Existing Fail2Ban local overrides require review')
    database = path('/var/lib/fail2ban/fail2ban.sqlite3')
    if database.is_symlink():
        raise FreshError('Custom Fail2Ban database symlink requires review')
    if database.exists():
        try:
            with sqlite3.connect(database.as_uri() + '?mode=ro', uri=True) as connection:
                if connection.execute('SELECT count(*) FROM bans').fetchone()[0]:
                    raise FreshError('Existing Fail2Ban ban history requires reviewed upgrade/recovery')
        except sqlite3.Error as error:
            raise FreshError('Existing Fail2Ban database cannot be safely classified') from error


def conffiles(package):
    result = run('dpkg-query', '-W', '-f=${Conffiles}', package, check=False)
    return {row[0]: row[1] for line in result.stdout.splitlines()
            if len(row := line.split()) == 2 and re.fullmatch('[0-9a-f]{32}', row[1])}


def stock_nft(contents, expected_md5):
    """Only the exact installed conffile AND a harmless empty-chain template."""
    if not expected_md5 or hashlib.md5(contents.encode()).hexdigest() != expected_md5:
        return False
    cleaned = re.sub(r'#.*', '', contents)
    cleaned = re.sub(r'\s+', '', cleaned)
    cleaned = cleaned.removeprefix('flushruleset')
    chain = r'chain(input|forward|output)\{typefilterhook\1priority(?:filter|0);(?:policyaccept;)?\}'
    chains = re.findall(chain, cleaned)
    remainder = re.sub(chain, '', cleaned)
    return remainder in {'', 'tableinetfilter{}'} and len(chains) in {0, 3} and len(set(chains)) == len(chains)


def nft_preflight():
    config = path('/etc/nftables.conf')
    if config.is_symlink() or (config.exists() and not config.is_file()):
        raise FreshError('Refusing non-regular /etc/nftables.conf')
    if config.exists() and not stock_nft(config.read_text(), conffiles('nftables').get('/etc/nftables.conf')):
        raise FreshError('Unknown/modified /etc/nftables.conf; preserve it and review scoped persistence manually')
    document = json.loads(run('nft', '-j', 'list', 'ruleset').stdout)
    for entry in document['nftables']:
        table = entry.get('table', {})
        if table.get('family') == 'inet' and table.get('name') in OWNED:
            raise FreshError('Existing installation detected: managed nft table; use upgrade/recovery')
    distribution = conffiles('fail2ban')
    for name, expected in distribution.items():
        if not name.startswith('/etc/fail2ban/'):
            continue
        file = path(name)
        if file.is_symlink() or not file.is_file() or hashlib.md5(file.read_bytes()).hexdigest() != expected:
            raise FreshError('Missing/modified distribution Fail2Ban configuration requires review: ' + name)
    for file in path('/etc/fail2ban/jail.d').glob('*'):
        expected = distribution.get('/etc/fail2ban/jail.d/' + file.name)
        if not file.is_file() or not expected or hashlib.md5(file.read_bytes()).hexdigest() != expected:
            raise FreshError('Custom jail.d configuration requires review: ' + str(file))
    cron = run('crontab', '-l', check=False).stdout
    if re.search(r'^[^#\n]*(?:flush\s+ruleset|nft\s+-f|systemctl\s+(?:reload|restart)\s+nftables)', cron, re.M):
        raise FreshError('Root crontab contains a firewall reload; review before installing')
    return document


def policy(args):
    """Generate site-local selection only; never change canonical regexes."""
    parser = configparser.ConfigParser(interpolation=None)
    parser.read([SOURCE / 'config/jail.local', SOURCE / 'config/exploit-critical-rce.local',
                 SOURCE / 'config/webshell-sweep.local'])
    output = configparser.ConfigParser(interpolation=None)
    output['DEFAULT'] = {}
    if args.mail_to:
        if not re.fullmatch(r'[A-Za-z0-9_.+\-]+@[A-Za-z0-9.\-]+', args.mail_to):
            raise FreshError('Invalid --mail-to address')
        output['DEFAULT'] = {'destemail': args.mail_to, 'sender': 'fail2ban@localhost', 'mta': 'sendmail'}
    enabled, disabled = [], []
    for jail in parser.sections():
        fields = {'enabled': 'false'}
        if jail in {'manualblock', 'recidive'}:
            fields['enabled'] = 'true'
        elif jail in {'sshd', 'sshd-slowattack'}:
            if args.ssh:
                fields.update(enabled='true', backend='systemd', port=str(args.ssh_port), logpath='')
        elif args.npm_log_dir:
            directory = str(args.npm_log_dir)
            if not re.fullmatch(r'/[A-Za-z0-9_./\-]+', directory):
                raise FreshError('NPM log directory must be an absolute simple path')
            matches = []
            for line in parser[jail]['logpath'].splitlines():
                parts = line.split()
                pattern = parts[0].replace('/opt/rustnpm/data/logs', directory)
                for file in Path(pattern).parent.glob(Path(pattern).name):
                    if file.is_file():
                        matches.append(str(file) + (' tail' if len(parts) > 1 and parts[1] == 'tail' else ''))
            if matches:
                fields.update(enabled='true', logpath='\n'.join(sorted(set(matches))))
        if not args.mail_to:
            fields['action'] = ('nftables-recidive[name=%(__name__)s, bantime="%(bantime)s", '
                                'port="%(port)s", protocol="%(protocol)s", chain="%(chain)s"]'
                                if jail == 'recidive' else '%(action_)s')
        output[jail] = fields
        (enabled if fields['enabled'] == 'true' else disabled).append(jail)
    return output, enabled, disabled


def load_upgrade():
    spec = importlib.util.spec_from_file_location('fresh_upgrade', SOURCE / 'scripts/upgrade-v033-v034.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def wait_ready(expected, timeout=60):
    """systemd start completion does not imply a usable Fail2Ban socket."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            remaining = max(0.01, deadline - time.monotonic())
            ping = run('fail2ban-client', 'ping', check=False, timeout=min(3, remaining))
            if ping.returncode == 0 and ping.stdout.strip() == 'Server replied: pong':
                remaining = max(0.01, deadline - time.monotonic())
                status = run('fail2ban-client', 'status', check=False, timeout=min(3, remaining))
                names = re.search(r'Jail list:\s*([^\r\n]*)', status.stdout)
                if status.returncode == 0 and names and {
                        n.strip() for n in names[1].split(',') if n.strip()} == set(expected):
                    return
        except subprocess.TimeoutExpired:
            pass
        time.sleep(min(0.2, max(0, deadline - time.monotonic())))
    raise FreshError('Fail2Ban readiness deadline exceeded (ping/selected active jails); preserve backup and use recovery')


def install(args, before, selected):
    if not args.bootstrap_stock_nft:
        raise FreshError('Apply requires --bootstrap-stock-nft: explicit backup/scoped-persistence consent')
    module = load_upgrade()
    mapping = module.install_map(SOURCE)
    mapping.update({Path('/etc/fail2ban/action.d') / f.name: f for f in (SOURCE / 'actions').glob('*.local')})
    mapping.update({Path('/etc/fail2ban/filter.d') / n: SOURCE / 'config' / n
                    for n in ('nginx-recon-optimized.local', 'f2b-anomaly-detection.local')})
    # Refuse unexpected pre-existing managed paths outside distribution config.
    distribution = conffiles('fail2ban')
    for target in mapping:
        existing = path(str(target))
        if existing.exists() or existing.is_symlink():
            expected = distribution.get(str(target))
            if existing.is_symlink() or not existing.is_file() or not expected or hashlib.md5(existing.read_bytes()).hexdigest() != expected:
                raise FreshError('Existing managed target requires review: ' + str(target))
    run('systemctl', 'is-active', '--quiet', 'cron', check=False)
    status = run('fail2ban-client', 'status', check=False)
    if status.returncode == 0:
        names = re.search(r'Jail list:\s*(.*)', status.stdout)
        for jail in (names[1].split(',') if names else []):
            if jail.strip() and run('fail2ban-client', 'get', jail.strip(), 'banip').stdout.strip():
                raise FreshError('Distribution Fail2Ban has active bans; use reviewed upgrade/recovery')
    backup_parent = path('/var/backups')
    backup_parent.mkdir(parents=True, exist_ok=True)
    backup = Path(tempfile.mkdtemp(prefix='f2b-fresh-', dir=backup_parent))
    backup.chmod(0o700)
    roots = [name for name in ('etc/fail2ban', 'etc/nftables.conf') if (ROOT / name).exists()]
    run('tar', '--acls', '--xattrs', '-cpf', str(backup / 'original-config.tar'), '-C', str(ROOT), *roots)
    (backup / 'foreign-firewall.json').write_text(json.dumps(before))
    print('Private fresh-install backup:', backup)
    marker = path('/etc/f2b/fresh-install.state')
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_text('incomplete; inspect backup before recovery\n')
    try:
        run('systemctl', 'stop', 'fail2ban')
        # Never execute the distro configuration. Only owned includes persist.
        config = path('/etc/nftables.conf')
        config.write_text('# Scoped Fail2Ban persistence; no global load during installation\n'
                          'include "/etc/nftables.d/fail2ban-filter.nft"\n'
                          'include "/etc/nftables.d/docker-block.nft"\n')
        for target, source in mapping.items():
            destination = path(str(target))
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, destination)
            destination.chmod(module.file_mode(target))
        shutil.copyfile(SOURCE / 'config/jail.local', path('/etc/fail2ban/jail.local'))
        with path('/etc/fail2ban/jail.d/zz-f2b-fresh-profile.local').open('w') as stream:
            selected[0].write(stream)
        # These are application-owned outputs/intentional manual-ban input, not
        # fabricated SSH/NPM traffic sources.
        for name in ('fail2ban.log', 'fail2ban-blocked-ips.txt', 'f2b-wrapper.log', 'f2b-docker-sync.log'):
            logfile = path('/var/log') / name
            logfile.touch(exist_ok=True)
            logfile.chmod(0o640)
        run('bash', str(SOURCE / 'scripts/01-install-nftables-v034.sh'))
        run('bash', str(SOURCE / 'scripts/04-install-docker-block-v034.sh'))
        run('systemctl', 'daemon-reload')
        run('fail2ban-client', '-t')
        run('systemctl', 'enable', '--now', 'cron')
        run('systemctl', 'enable', '--now', 'fail2ban')
        wait_ready(selected[1])
        run('/usr/bin/python3', '/usr/local/sbin/f2b-ipv6-sync.py')
        run('/usr/bin/python3', '/usr/local/sbin/f2b-save-owned-tables.py')
        actual = run('fail2ban-client', 'status').stdout
        names = re.search(r'Jail list:\s*(.*)', actual)
        if not names or {n.strip() for n in names[1].split(',') if n.strip()} != set(selected[1]):
            raise FreshError('Active jail list does not match selected/log-backed profile')
        if module.external_nft_digest(before) != module.external_nft_digest(json.loads(run('nft', '-j', 'list', 'ruleset').stdout)):
            raise FreshError('Foreign firewall changed; no automatic foreign rewrite attempted')
        marker.write_text('complete\n')
        print('PASS: active jails:', len(selected[1]), ', '.join(selected[1]))
        print('Two owned nft tables support synchronization; Docker/NPM were not implicitly installed')
    except Exception as error:
        raise FreshError('Fresh installation incomplete; do not rerun/flush. Review backup ' + str(backup) + '\n' + str(error)) from error


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true', help='read-only preflight (default)')
    parser.add_argument('--apply', action='store_true', help='install fresh profile after preflight')
    parser.add_argument('--install-prerequisites', action='store_true', help='explicitly allow apt package installation')
    parser.add_argument('--bootstrap-stock-nft', action='store_true', help='back up and replace verified empty stock nft persistence; never load it')
    parser.add_argument('--ssh', action='store_true', help='select SSH jails and journal dependencies')
    parser.add_argument('--ssh-port', type=int, default=22)
    parser.add_argument('--docker', action='store_true', help='select Docker engine dependency and require a working daemon')
    parser.add_argument('--npm-log-dir', type=Path, help='select web jails backed by real files here; never install NPM/create fake logs')
    parser.add_argument('--mail-to', help='select mail dependencies/actions; configure MTA separately')
    args = parser.parse_args()
    try:
        if os.geteuid() != 0:
            raise FreshError('Run with sudo')
        if args.check and (args.apply or args.install_prerequisites):
            raise FreshError('--check cannot be combined with mutating flags')
        if not 1 <= args.ssh_port <= 65535:
            raise FreshError('SSH port must be between 1 and 65535')
        platform_check()
        file_guards()
        dependencies(args)
        before = nft_preflight()
        selected = policy(args)
        print('Selected jails:', ', '.join(selected[1]))
        print('Disabled (profile not selected or no real log files):', ', '.join(selected[2]))
        print('No NPM/SSH traffic log placeholders are created. Mail delivery is not certified.')
        if args.apply:
            with load_upgrade().acquire_upgrade_lock():
                # Recheck after acquiring the same lock used by runtime cron.
                file_guards()
                before = nft_preflight()
                install(args, before, selected)
        else:
            print('PASS: preflight only. Apply requires --apply --bootstrap-stock-nft and the same profile flags')
        return 0
    except (FreshError, OSError, subprocess.CalledProcessError) as error:
        print('ERROR:', error, file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
