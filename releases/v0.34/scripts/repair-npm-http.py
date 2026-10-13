#!/usr/bin/python3
"""Scoped HTTP log repair for an already complete fresh NPM profile.

Default: private temporary merged-config preflight only. --apply backs up first.
Never installs packages, enables disabled jails, restarts Docker or loads nft.
"""
import argparse
import ast
import configparser
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import sqlite3
import stat
import sys
import tempfile

SOURCE = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('fresh_repair', SOURCE / 'scripts/fresh-install.py')
fresh = importlib.util.module_from_spec(spec); spec.loader.exec_module(fresh)
LEGACY = '393abab6c0285826c56f2e39b07608288c21318a'
PROFILE = Path('/etc/fail2ban/jail.d/zz-f2b-fresh-profile.local')
SWEEP = Path('/etc/fail2ban/filter.d/f2b-webshell-sweep.conf')
VERIFIER = Path('/usr/local/libexec/f2b-runtime-verify.py')


def digest(data): return hashlib.sha256(data).hexdigest()


def secure(file):
    for parent in (file, *file.parents):
        info = parent.lstat()
        if stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise fresh.FreshError('Unsafe target ownership/permissions/symlink')
    if not file.is_file(): raise fresh.FreshError('Expected regular repair target')


def inventory():
    result = {}
    for file in sorted(Path('/etc/fail2ban').rglob('*')):
        if file.is_symlink(): result[str(file)] = 'link:' + os.readlink(file)
        elif file.is_file(): result[str(file)] = digest(file.read_bytes())
    return result


def commands(text):
    return [ast.literal_eval(line) for line in text.splitlines() if line.startswith('[')]


def stable_config(dump, affected):
    """Ignore only the approved logpath/failregex changes, not whitelist/actions."""
    return sorted(json.dumps(c, sort_keys=True) for c in commands(dump) if not (
        len(c) >= 3 and c[0] in {'set', 'multi-set'} and
        ((c[1] in affected and c[2] == 'addlogpath') or
         (c[1] == 'f2b-webshell-sweep' and c[2] == 'addfailregex'))))


def logpaths(dump, jail):
    return {c[3] for c in commands(dump) if len(c) >= 4 and
            c[:3] == ['set', jail, 'addlogpath']}


def expression_list(dump, jail, key):
    result = []
    for c in commands(dump):
        if len(c) == 4 and c[0] in {'set', 'multi-set'} and c[1:3] == [jail, 'add' + key]:
            result.extend(c[3] if isinstance(c[3], list) else [c[3]])
    return result


def timed_bans(sync, jails):
    return {j: sync.call(['get', j, 'banip', '--with-time']) for j in jails}


def require_bans(before, after):
    if set(before) != set(after) or any(not set(values) <= set(after[j]) for j, values in before.items()):
        raise fresh.FreshError('Timed bans changed; preserve private backup for diagnosis')


def preflight(directory):
    marker = Path('/etc/f2b/fresh-install.state')
    secure(marker)
    if marker.read_text() != 'complete\n':
        raise fresh.FreshError('Requires complete fresh profile; not incomplete recovery or a legacy upgrade')
    if not directory.is_absolute() or directory.is_symlink():
        raise fresh.FreshError('Use the actual absolute HTTP log directory, not a symlink')
    for file in (PROFILE, SWEEP, VERIFIER): secure(file)
    module = fresh.load_upgrade()
    verifier = module.load_verifier()
    if verifier.validate_dbfile(fresh.run('fail2ban-client', 'get', 'dbfile').stdout) != '/var/lib/fail2ban/fail2ban.sqlite3':
        raise fresh.FreshError('This scoped repair requires the standard SQLite database; review custom DB backup first')
    sync = verifier.load_sync()
    bans = verifier.snapshot_bans()
    affected = sorted(set(bans) & verifier.HTTP_JAILS)
    if not {'f2b-exploit-critical', 'f2b-webshell-sweep'} <= set(affected):
        raise fresh.FreshError('Requires the existing active critical/sweep NPM profile; no profile enabling')
    profile = configparser.ConfigParser(interpolation=None)
    profile.read(PROFILE)
    logs = verifier.npm_logs(directory)
    for jail in affected:
        if not profile.has_section(jail) or not profile.getboolean(jail, 'enabled'):
            raise fresh.FreshError('Fresh selection/runtime mismatch')
        required = verifier.npm_required(jail)
        if not all(logs[k] for k in required):
            raise fresh.FreshError('Required HTTP access/error files missing; no placeholders created')
        # Refuse accidental adoption of another instance's log directory.
        prior = [line.split()[0] for line in profile[jail]['logpath'].splitlines() if line.strip()]
        if not prior or any(Path(f).parent != directory for f in prior):
            raise fresh.FreshError('Existing profile belongs to another log directory; review manually')
        profile[jail]['logpath'] = '\n'.join(f + ' tail' for k in sorted(required) for f in logs[k])
    output = io.StringIO(); profile.write(output)
    replacement = {PROFILE: output.getvalue().encode(),
                   SWEEP: (SOURCE / 'filters/f2b-webshell-sweep.conf').read_bytes(),
                   VERIFIER: (SOURCE / 'scripts/upgrade-v034dev-canary-227c393.py').read_bytes()}
    for file, source in ((SWEEP, 'filters/f2b-webshell-sweep.conf'),
                         (VERIFIER, 'scripts/upgrade-v034dev-canary-227c393.py')):
        old = fresh.run('git', '-C', str(SOURCE.parents[1]), 'show', LEGACY + ':releases/v0.34/' + source).stdout.encode()
        if file.read_bytes() not in (old, replacement[file]):
            raise fresh.FreshError('Unknown managed target modification; review rather than overwrite')
    before_dump = fresh.run('fail2ban-client', '-d').stdout
    if {c[1] for c in commands(before_dump) if c[0] == 'add'} != set(bans):
        raise fresh.FreshError('Disk/runtime active profile mismatch; refuse unrelated changes')
    # The loaded filters must match disk before any reload is authorized.
    from fail2ban.server.failregex import FailRegex, Regex
    for jail in affected:
        dns = sync.call(['get', jail, 'usedns'])
        for key in ('failregex', 'ignoreregex'):
            compiler = FailRegex if key == 'failregex' else Regex
            expected = [compiler(value, useDns=dns).getRegex()
                        for value in expression_list(before_dump, jail, key)]
            if sync.call(['get', jail, key]) != expected:
                raise fresh.FreshError('Loaded filter/disk mismatch: ' + jail + '/' + key + '; review pending edits first')
    whitelist = {j: fresh.run('fail2ban-client', 'get', j, 'ignoreip').stdout for j in bans}
    before_inventory = inventory()
    with tempfile.TemporaryDirectory(prefix='f2b-npm-candidate-') as folder:
        candidate = Path(folder) / 'fail2ban'
        shutil.copytree('/etc/fail2ban', candidate, symlinks=True)
        for target, data in replacement.items():
            if str(target).startswith('/etc/fail2ban/'):
                (candidate / target.relative_to('/etc/fail2ban')).write_bytes(data)
        fresh.run('fail2ban-client', '-c', str(candidate), '-t')
        after_dump = fresh.run('fail2ban-client', '-c', str(candidate), '-d').stdout
        if stable_config(before_dump, affected) != stable_config(after_dump, affected):
            raise fresh.FreshError('Candidate changes unrelated jail settings/actions/whitelists')
        for jail in affected:
            expected = {f for k in verifier.npm_required(jail) for f in logs[k]}
            if logpaths(after_dump, jail) != expected:
                raise fresh.FreshError('A local override suppresses intended HTTP log coverage')
        parser = configparser.ConfigParser(); parser.read(SOURCE / 'filters/f2b-webshell-sweep.conf')
        if expression_list(after_dump, 'f2b-webshell-sweep', 'failregex') != parser['Definition']['failregex'].splitlines():
            raise fresh.FreshError('Local sweep override suppresses new format; preserve and review it')
        for jail in ('f2b-exploit-critical', 'f2b-webshell-sweep'):
            for label, count in (('attacks', 4), ('benign', 0)):
                fixture = SOURCE / 'tests/fixtures' / ('npm216-' + jail + '-' + label + '.log')
                result = fresh.run('fail2ban-regex', '-c', str(candidate), str(fixture), jail)
                import re
                found = re.search(r'Lines:\s+\d+ lines,\s+\d+ ignored,\s+(\d+) matched', result.stdout)
                if not found or int(found[1]) != count:
                    raise fresh.FreshError('Merged NPM format/benign fixture contract failed: ' + jail)
    return {'module': module, 'verifier': verifier, 'sync': sync, 'bans': bans,
            'times': timed_bans(sync, bans), 'affected': affected, 'whitelist': whitelist,
            'inventory': before_inventory, 'replacement': replacement,
            'foreign': json.loads(fresh.run('nft', '-j', 'list', 'ruleset').stdout)}


def atomic(file, data, mode):
    descriptor, name = tempfile.mkstemp(prefix='.f2b-npm-', dir=file.parent)
    try:
        with os.fdopen(descriptor, 'wb') as stream: stream.write(data)
        os.chmod(name, mode)
        os.replace(name, file)
    finally:
        if os.path.exists(name): os.unlink(name)


def verify_preserved(plan):
    after = inventory()
    allowed = {str(PROFILE), str(SWEEP)}
    if {k: v for k, v in plan['inventory'].items() if k not in allowed} != {
            k: v for k, v in after.items() if k not in allowed}:
        raise fresh.FreshError('Unrelated Fail2Ban configuration changed')
    fresh.wait_ready(plan['bans'])
    require_bans(plan['times'], timed_bans(plan['sync'], plan['bans']))
    for jail, value in plan['whitelist'].items():
        if fresh.run('fail2ban-client', 'get', jail, 'ignoreip').stdout != value:
            raise fresh.FreshError('Runtime whitelist changed')
    now = json.loads(fresh.run('nft', '-j', 'list', 'ruleset').stdout)
    if plan['module'].external_nft_digest(plan['foreign']) != plan['module'].external_nft_digest(now):
        raise fresh.FreshError('Foreign firewall changed; no rewrite attempted')


def apply(plan, parent):
    if inventory() != plan['inventory']: raise fresh.FreshError('Configuration changed since preflight')
    parent.mkdir(parents=True, exist_ok=True)
    # Check directory ancestors without creating a file.
    for item in (parent, *parent.parents):
        info = item.lstat()
        if stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise fresh.FreshError('Unsafe backup parent')
    backup = Path(tempfile.mkdtemp(prefix='f2b-npm-http-', dir=parent)); backup.chmod(0o700)
    old = {file: (file.read_bytes(), stat.S_IMODE(file.stat().st_mode)) for file in plan['replacement']}
    fresh.run('tar', '--acls', '--xattrs', '-cpf', str(backup / 'fail2ban-config.tar'), '-C', '/', 'etc/fail2ban')
    database = Path('/var/lib/fail2ban/fail2ban.sqlite3')
    secure(database)
    with sqlite3.connect(database.as_uri() + '?mode=ro', uri=True) as source:
        with sqlite3.connect(backup / 'fail2ban.sqlite3') as destination: source.backup(destination)
    for index, (file, (data, mode)) in enumerate(old.items()):
        (backup / ('target-' + str(index))).write_bytes(data)
    for name, value in (('timed-bans.json', plan['times']), ('foreign.json', plan['foreign'])):
        (backup / name).write_text(json.dumps(value))
    manifest = {'schema': 1, 'affected': plan['affected'], 'before_config': plan['inventory'],
                'targets': {str(f): {'before': digest(old[f][0]), 'after': digest(b), 'mode': old[f][1]}
                            for f, b in plan['replacement'].items()},
                'files': {f.name: digest(f.read_bytes()) for f in backup.iterdir()}}
    (backup / 'manifest.json').write_text(json.dumps(manifest, sort_keys=True))
    print('Private repair backup:', backup)
    try:
        for file, data in plan['replacement'].items(): atomic(file, data, old[file][1])
        fresh.run('fail2ban-client', '-t')
        for jail in plan['affected']: fresh.run('fail2ban-client', 'reload', jail)
        verify_preserved(plan)
        plan['verifier'].verify_npm_coverage(plan['bans'], plan['sync'])
        fresh.run('/usr/bin/python3', '/usr/local/sbin/f2b-ipv6-sync.py')
        fresh.run('/usr/bin/python3', '/usr/local/libexec/f2b-runtime-verify.py', '--docker-check')
        verify_preserved(plan)
        (backup / 'result').write_text('complete\n')
    except Exception as error:
        for file, (data, mode) in old.items(): atomic(file, data, mode)
        try:
            fresh.run('fail2ban-client', '-t')
            for jail in plan['affected']: fresh.run('fail2ban-client', 'reload', jail)
            verify_preserved(plan)
            (backup / 'result').write_text('rolled-back\n')
        except Exception:
            (backup / 'result').write_text('rollback-needs-review\n')
            raise fresh.FreshError('Repair and rollback verification failed; retain private backup and VM console') from error
        raise fresh.FreshError('Repair failed; original target files and runtime preserved after rollback verification') from error


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--npm-log-dir', type=Path, required=True)
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--backup-dir', type=Path, default=Path('/var/backups'))
    args = parser.parse_args()
    try:
        if os.geteuid() != 0: raise fresh.FreshError('Run with sudo')
        with fresh.load_upgrade().acquire_upgrade_lock():
            plan = preflight(args.npm_log_dir)
            if args.apply: apply(plan, args.backup_dir)
            print('PASS: HTTP log repair ' + ('applied' if args.apply else 'preflight only; no daemon/config changes'))
            return 0
    except Exception as error:
        print('REFUSED/FAILED:', error, file=sys.stderr)
        return 1


if __name__ == '__main__': sys.exit(main())
