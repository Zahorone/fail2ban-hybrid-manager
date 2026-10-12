#!/usr/bin/python3
"""Conservative completion of the known pre-readiness core fresh install.

Read-only by default. Not an installer, upgrader, or a database rollback tool.
Unknown state is refused; the original backup is never extracted over the host.
"""
import argparse
import hashlib
import importlib.util
import io
import json
import os
import re
from pathlib import Path
import stat
import sys
import tarfile

spec = importlib.util.spec_from_file_location('fresh', Path(__file__).with_name('fresh-install.py'))
fresh = importlib.util.module_from_spec(spec); spec.loader.exec_module(fresh)
LEGACY = '06d730b189fcb77867bb5d73db7de941c0e31618'
PERSISTENCE = ('# Scoped Fail2Ban persistence; no global load during installation\n'
               'include "/etc/nftables.d/fail2ban-filter.nft"\n'
               'include "/etc/nftables.d/docker-block.nft"\n').encode()


def fingerprint(data):
    return hashlib.sha256(data).hexdigest()


def secure(file, directory=False):
    for parent in (file, *file.parents):
        info = parent.lstat()
        if stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise fresh.FreshError('Unsafe ownership, permissions or symlink in recovery path')
    if not (file.is_dir() if directory else file.is_file()):
        raise fresh.FreshError('Missing/non-regular recovery input')


def mapping():
    result = fresh.load_upgrade().install_map(fresh.SOURCE)
    result.update({Path('/etc/fail2ban/action.d') / f.name: f
                   for f in (fresh.SOURCE / 'actions').glob('*.local')})
    result.update({Path('/etc/fail2ban/filter.d') / n: fresh.SOURCE / 'config' / n
                   for n in ('nginx-recon-optimized.local', 'f2b-anomaly-detection.local')})
    result[Path('/etc/fail2ban/jail.local')] = fresh.SOURCE / 'config/jail.local'
    return result


def legacy_bytes(source):
    repo = fresh.SOURCE.parents[1]
    relative = source.relative_to(repo)
    # Git objects supply generic published payload fingerprints, not VM data.
    result = fresh.run('git', '-C', str(repo), 'show', LEGACY + ':' + str(relative))
    return result.stdout.encode()


def inspect(backup):
    if not backup.is_absolute() or not backup.name.startswith('f2b-fresh-') or backup.parent != Path('/var/backups'):
        raise fresh.FreshError('Use the exact absolute /var/backups/f2b-fresh-* directory')
    secure(backup, directory=True)
    if backup.stat().st_mode & 0o077:
        raise fresh.FreshError('Backup directory must be private (0700)')
    archive = backup / 'original-config.tar'
    foreign_file = backup / 'foreign-firewall.json'
    secure(archive); secure(foreign_file)
    distribution = {n: h for n, h in fresh.conffiles('fail2ban').items()
                    if n.startswith('/etc/fail2ban/')}
    originals = {}
    with tarfile.open(archive) as stream:
        for member in stream.getmembers():
            name = '/' + member.name.rstrip('/')
            if '..' in Path(name).parts or name in originals:
                raise fresh.FreshError('Ambiguous backup member')
            if member.isdir() and (name == '/etc/fail2ban' or name.startswith('/etc/fail2ban/')):
                continue
            if not member.isfile() or not (name == '/etc/nftables.conf' or name.startswith('/etc/fail2ban/')):
                raise fresh.FreshError('Unexpected backup member; manual review required')
            data = stream.extractfile(member).read()
            if name == '/etc/nftables.conf':
                if not fresh.stock_nft(data.decode(), fresh.conffiles('nftables').get(name)):
                    raise fresh.FreshError('Original nft configuration is not verified stock')
            elif hashlib.md5(data).hexdigest() != distribution.get(name):
                raise fresh.FreshError('Original Fail2Ban configuration is not verified stock')
            originals[name] = data
    if '/etc/nftables.conf' not in originals or not set(distribution).issubset(originals):
        raise fresh.FreshError('Incomplete original configuration backup')
    targets = {str(t): legacy_bytes(s) for t, s in mapping().items()}
    args = argparse.Namespace(ssh=False, ssh_port=22, docker=False, mail_to=None, npm_log_dir=None)
    selected = fresh.policy(args)
    output = io.StringIO(); selected[0].write(output)
    targets['/etc/fail2ban/jail.d/zz-f2b-fresh-profile.local'] = output.getvalue().encode()
    targets['/etc/nftables.conf'] = PERSISTENCE
    journal_file = backup / 'recovery-manifest.json'
    journal = None
    if journal_file.exists():
        secure(journal_file)
        journal = json.loads(journal_file.read_text())
        if (journal.get('schema') != 1 or journal.get('legacy') != LEGACY or
                journal.get('archive_sha256') != fingerprint(archive.read_bytes()) or
                journal.get('foreign_sha256') != fingerprint(foreign_file.read_bytes())):
            raise fresh.FreshError('Recovery manifest/archive mismatch')
        if journal.get('targets') != {n: fingerprint(b) for n, b in targets.items()}:
            raise fresh.FreshError('Recovery manifest/payload mismatch')
    marker = fresh.path('/etc/f2b/fresh-install.state')
    secure(marker)
    if marker.read_text() != 'incomplete; inspect backup before recovery\n':
        raise fresh.FreshError('Not the recognized incomplete fresh transaction')
    replacements = {str(t): s for t, s in mapping().items()
                    if str(t) in {'/usr/local/bin/f2b', '/usr/local/libexec/f2b-runtime-verify.py'}}
    for name, expected in {**originals, **targets}.items():
        file = fresh.path(name); secure(file)
        allowed = [expected]
        if journal and name in replacements:
            allowed.append(replacements[name].read_bytes())
        if file.read_bytes() not in allowed:
            raise fresh.FreshError('Installed target fingerprint differs; refuse recovery: ' + name)
    # No unrecognized site overrides may silently change this core-only profile.
    known = set(originals) | set(targets)
    for file in fresh.path('/etc/fail2ban').rglob('*'):
        if not file.is_dir() and '/' + str(file.relative_to(fresh.ROOT)) not in known:
            raise fresh.FreshError('Unrecognized Fail2Ban file; manual review required')
    if set(fresh.path('/etc/nftables.d').iterdir()) != {
            fresh.path('/etc/nftables.d/fail2ban-filter.nft'), fresh.path('/etc/nftables.d/docker-block.nft')}:
        raise fresh.FreshError('Unrecognized nft include files')
    for name in ('fail2ban-filter.nft', 'docker-block.nft'):
        file = fresh.path('/etc/nftables.d/' + name)
        secure(file)
        if re.search(r'\b(flush|include|delete|destroy)\b', file.read_text()):
            raise fresh.FreshError('Unsafe command in owned persistence snapshot')
    if set(fresh.path('/etc/systemd/system/nftables.service.d').iterdir()) != {
            fresh.path('/etc/systemd/system/nftables.service.d/90-f2b-preserve-runtime.conf')}:
        raise fresh.FreshError('Unrecognized nft service override')
    if fresh.path('/etc/systemd/system/nftables.service').exists():
        raise fresh.FreshError('Custom nft service requires review')
    fresh.wait_ready(selected[1])
    for unit in ('fail2ban', 'cron', 'nftables'):
        fresh.run('systemctl', 'is-enabled', '--quiet', unit)
    for unit in ('fail2ban', 'cron'):
        fresh.run('systemctl', 'is-active', '--quiet', unit)
    fresh.run('unshare', '--net', 'nft', '-c', '-f', '/etc/nftables.conf')
    module = fresh.load_upgrade()
    foreign = json.loads(foreign_file.read_text())
    live = json.loads(fresh.run('nft', '-j', 'list', 'ruleset').stdout)
    if module.external_nft_digest(foreign) != module.external_nft_digest(live):
        raise fresh.FreshError('Foreign firewall differs from the original backup; refuse rewrite')
    for table in fresh.OWNED:
        fresh.run('nft', 'list', 'table', 'inet', table)
    return targets, replacements, foreign


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--backup', type=Path, required=True)
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    try:
        if os.geteuid() != 0: raise fresh.FreshError('Run with sudo')
        with fresh.load_upgrade().acquire_upgrade_lock():
            targets, replacements, foreign = inspect(args.backup)
            if not args.apply:
                print('PASS: recognized incomplete core profile; read-only recovery preflight')
                return 0
            journal = args.backup / 'recovery-manifest.json'
            if not journal.exists():
                journal.write_text(json.dumps({'schema': 1, 'legacy': LEGACY,
                    'archive_sha256': fingerprint((args.backup / 'original-config.tar').read_bytes()),
                    'foreign_sha256': fingerprint((args.backup / 'foreign-firewall.json').read_bytes()),
                    'targets': {n: fingerprint(b) for n, b in targets.items()}}, sort_keys=True))
                journal.chmod(0o600)
                for name in replacements:
                    saved = args.backup / ('recovery-original-' + Path(name).name)
                    saved.write_bytes(fresh.path(name).read_bytes()); saved.chmod(0o600)
            # No daemon/config/database replacement or firewall service start.
            before = fresh.run('/usr/bin/python3', '/usr/local/sbin/f2b-ipv6-sync.py', 'export').stdout
            (args.backup / 'recovery-bans.json').write_text(before)
            (args.backup / 'recovery-bans.json').chmod(0o600)
            for name, source in replacements.items():
                target = fresh.path(name)
                temporary = target.with_name(target.name + '.recovery-new')
                if temporary.exists() or temporary.is_symlink():
                    raise fresh.FreshError('Unexpected staged recovery target')
                temporary.write_bytes(source.read_bytes()); temporary.chmod(0o755)
                os.replace(temporary, target)
            fresh.run('/usr/bin/python3', '/usr/local/sbin/f2b-ipv6-sync.py')
            fresh.run('/usr/bin/python3', '/usr/local/libexec/f2b-runtime-verify.py', '--docker-check')
            fresh.run('/usr/bin/python3', '/usr/local/sbin/f2b-save-owned-tables.py')
            after = fresh.run('/usr/bin/python3', '/usr/local/sbin/f2b-ipv6-sync.py', 'export').stdout
            # Timestamped ban records must be retained; newly arriving bans are fine.
            old, new = json.loads(before), json.loads(after)
            if any(not set(records).issubset(new.get(jail, [])) for jail, records in old.items()):
                raise fresh.FreshError('Ban snapshot changed during recovery; inspect privately before completion')
            live = json.loads(fresh.run('nft', '-j', 'list', 'ruleset').stdout)
            if fresh.load_upgrade().external_nft_digest(foreign) != fresh.load_upgrade().external_nft_digest(live):
                raise fresh.FreshError('Foreign firewall changed during recovery; no rewrite attempted')
            fresh.run('unshare', '--net', 'nft', '-c', '-f', '/etc/nftables.conf')
            fresh.path('/etc/f2b/fresh-install.state').write_text('complete\n')
            print('PASS: recovery complete; active bans and foreign firewall preserved; reboot still unverified')
            return 0
    except Exception as error:
        print('REFUSED/INCOMPLETE:', error, file=sys.stderr)
        print('Do not reinstall, flush, delete configuration or restore the database by hand.', file=sys.stderr)
        return 1


if __name__ == '__main__': sys.exit(main())
