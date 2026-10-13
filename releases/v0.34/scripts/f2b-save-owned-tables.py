#!/usr/bin/python3
"""Validated persistence; transactional ports; known-corruption repair preflight.

No global host firewall load, foreign-table rewrite, or ban-set flush. Validation
runs in private mount/network namespaces. Port batches touch only the port set.
"""
import argparse
from contextlib import contextmanager, ExitStack
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile

DIRECTORY = Path('/etc/nftables.d')
CONFIG = Path('/etc/nftables.conf')
BACKUPS = Path('/var/backups')
TABLES = ('fail2ban-filter', 'docker-block')
SET = 'docker-blocked-ports'


class PersistenceError(RuntimeError): pass


def run(*args, input_text=None):
    result = subprocess.run(args, input=input_text, text=True, capture_output=True)
    if result.returncode:
        raise PersistenceError('Command failed: ' + ' '.join(args) + '\n' + result.stderr[-1800:])
    return result.stdout


def secure(file):
    for item in (file, *file.parents):
        info = item.lstat()
        if stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise PersistenceError('Unsafe persistence ownership, permissions or symlink')
    if not file.is_file(): raise PersistenceError('Persistence target must be a regular file')


@contextmanager
def locks(upgrade=False):
    with ExitStack() as stack:
        names = (['f2b-upgrade.lock'] if upgrade else []) + ['f2b-runtime-sync.lock']
        for name in names:
            lock = stack.enter_context(open('/run/lock/' + name, 'a'))
            fcntl.flock(lock, fcntl.LOCK_EX)
        yield


def validate_global(staged):
    secure(CONFIG)
    # The bind mounts and historical iif docker0 compatibility interface are
    # PRIVATE to these namespaces, never created in the host/Docker namespace.
    script = ('mount --make-rprivate /; ip link add docker0 type bridge; '
              'config=$1; shift; while [ "$#" -gt 0 ]; do '
              'mount --bind "$1" "$2"; shift 2; done; nft -c -f "$config"; '
              'nft -f "$config"; nft -n -j list ruleset')
    arguments = [str(CONFIG)]
    for target, candidate in staged.items():
        secure(target)
        arguments.extend((str(candidate), str(target)))
    document = json.loads(run('unshare', '--mount', '--net', '--', '/bin/sh', '-ec', script, 'f2b-check', *arguments))
    present = {e['table'].get('name') for e in document['nftables']
               if 'table' in e and e['table'].get('family') == 'inet'}
    if not set(TABLES) <= present: raise PersistenceError('Global persistence does not include both owned tables')
    return document


def stable(document, ignore_ports=False):
    def clean(value):
        if isinstance(value, dict):
            return {k: clean(v) for k, v in value.items() if k not in {'handle', 'expires', 'packets', 'bytes'}}
        if isinstance(value, list): return [clean(v) for v in value]
        return value
    rows = []
    for entry in document['nftables']:
        if 'metainfo' in entry: continue
        item = clean(entry)
        if ignore_ports and item.get('set', {}).get('table') == 'docker-block' and item['set'].get('name') == SET:
            item['set'].pop('elem', None)
        rows.append(item)
    return json.dumps(rows, sort_keys=True)


def ruleset(): return json.loads(run('nft', '-n', '-j', 'list', 'ruleset'))


def ports(document=None):
    if document is None:
        document = json.loads(run('nft', '-n', '-j', 'list', 'set', 'inet', 'docker-block', SET))
    found = [e['set'] for e in document['nftables'] if 'set' in e and
             e['set'].get('table') == 'docker-block' and e['set'].get('name') == SET]
    if len(found) != 1 or found[0].get('type') != 'inet_service' or 'timeout' in found[0].get('flags', []):
        raise PersistenceError('Unexpected blocked-port set schema')
    result = set()
    for element in found[0].get('elem', []):
        if isinstance(element, dict) and 'elem' in element: element = element['elem']['val']
        if isinstance(element, int): start = end = element
        elif isinstance(element, dict) and set(element) == {'range'}: start, end = element['range']
        else: raise PersistenceError('Unsupported port element; preserving runtime')
        if type(start) is not int or type(end) is not int or not 1 <= start <= end <= 65535:
            raise PersistenceError('Invalid port element; preserving runtime')
        result.update(range(start, end + 1))
    return result


def set_ports(values):
    # Atomic scoped set replacement handles auto-merged intervals correctly.
    # No IP ban set, chain, table or foreign rule is flushed/replaced here.
    batch = 'flush set inet docker-block ' + SET + '\n'
    if values:
        batch += 'add element inet docker-block ' + SET + ' { ' + ', '.join(map(str, sorted(values))) + ' }\n'
    run('nft', '-f', '-', input_text=batch)
    if ports() != values: raise PersistenceError('Runtime port membership verification failed')


def atomic(target, data):
    secure(target)
    descriptor, filename = tempfile.mkstemp(prefix='.' + target.name + '-', dir=target.parent)
    try:
        with os.fdopen(descriptor, 'wb') as output:
            output.write(data); output.flush(); os.fsync(output.fileno())
        shutil.copystat(target, filename, follow_symlinks=False)
        info = target.stat(); os.chown(filename, info.st_uid, info.st_gid)
        os.replace(filename, target)
        directory = os.open(target.parent, os.O_RDONLY | os.O_DIRECTORY)
        try: os.fsync(directory)
        finally: os.close(directory)
    finally:
        Path(filename).unlink(missing_ok=True)


def commit(contents):
    original = {file: file.read_bytes() for file in contents}
    with tempfile.TemporaryDirectory(prefix='.f2b-persist-', dir=DIRECTORY) as folder:
        staged = {}
        for index, (target, data) in enumerate(contents.items()):
            secure(target)
            candidate = Path(folder) / str(index); candidate.write_bytes(data); candidate.chmod(0o600)
            staged[target] = candidate
        validate_global(staged)
        changed = []
        try:
            for target, data in contents.items():
                atomic(target, data); changed.append(target)
            validate_global({})
        except Exception:
            for target in reversed(changed): atomic(target, original[target])
            raise


def snapshots(directory):
    # Read all before replacing any. A failed nft read changes no file.
    return {directory / (name + '.nft'): run('nft', '-n', '-s', 'list', 'table', 'inet', name).encode()
            for name in TABLES}


def save(directory=DIRECTORY):
    with locks(): commit(snapshots(directory))


def backup(files, before=None):
    for parent in (BACKUPS, *BACKUPS.parents):
        info = parent.lstat()
        if stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise PersistenceError('Unsafe backup parent')
    folder = Path(tempfile.mkdtemp(prefix='f2b-ports-', dir=BACKUPS)); folder.chmod(0o700)
    targets = {}
    for index, file in enumerate(files):
        secure(file)
        copied = folder / ('target-' + str(index)); shutil.copy2(file, copied)
        targets[str(file)] = {'file': copied.name, 'sha256': hashlib.sha256(copied.read_bytes()).hexdigest()}
    if before is not None: (folder / 'runtime.json').write_text(json.dumps(before))
    (folder / 'manifest.json').write_text(json.dumps({'schema': 1, 'targets': targets}, sort_keys=True))
    print('Private port-persistence backup:', folder)
    return folder


def change_port(port, block):
    if not re.fullmatch(r'[0-9]+', str(port)) or not 1 <= int(port) <= 65535:
        raise PersistenceError('Port must be an integer between 1 and 65535')
    port = int(port)
    with locks(upgrade=True):
        persisted = validate_global({})  # Refuse bad persistence BEFORE runtime mutation.
        old = ports()
        if ports(persisted) != old: raise PersistenceError('Runtime/persisted ports differ; review before mutation')
        if not block and port not in old: raise PersistenceError('Port not blocked; nothing changed')
        desired = old | {port} if block else old - {port}
        before = ruleset()
        files = [DIRECTORY / (name + '.nft') for name in TABLES]
        folder = backup(files, before)
        original = {file: file.read_bytes() for file in files}
        try:
            set_ports(desired)
            commit(snapshots(DIRECTORY))
            if ports(validate_global({})) != desired:
                raise PersistenceError('Persisted port membership differs from runtime')
            if stable(before, True) != stable(ruleset(), True):
                raise PersistenceError('Ban/foreign runtime structure changed; no global rewrite attempted')
            if ports() != desired: raise PersistenceError('Port membership changed during persistence')
            (folder / 'result').write_text('complete\n')
        except Exception as error:
            try:
                set_ports(old)
                for target, data in original.items(): atomic(target, data)
                validate_global({})
                if stable(before, True) != stable(ruleset(), True): raise PersistenceError('Unrelated runtime changed')
                (folder / 'result').write_text('rolled-back\n')
            except Exception:
                (folder / 'result').write_text('rollback-needs-review\n')
                raise PersistenceError('Port operation and rollback verification failed; keep backup and console') from error
            raise PersistenceError('Port operation failed; runtime ports and persistence rolled back and verified') from error
        print('PASS: port ' + str(port) + (' blocked' if block else ' unblocked') + '; persisted syntax verified')


def repair_text(text):
    """Remove only known sed-produced extra closes, preserving every other byte."""
    token = re.compile(r'\s+|\#[^\n]*|"(?:\\.|[^"\\])*"|[{};]|[^\s{};"#]+')
    tokens = []; position = 0
    for match in token.finditer(text):
        if match.start() != position: raise PersistenceError('Unsupported token in repair input')
        position = match.end()
        if not match[0].isspace() and not match[0].startswith('#'):
            tokens.append((match[0], match.start(), match.end()))
    if position != len(text): raise PersistenceError('Incomplete token in repair input')
    values = [t[0] for t in tokens]
    if values[:4] != ['table', 'inet', 'docker-block', '{']: raise PersistenceError('Not the known scoped Docker table')
    if any(v in {'flush', 'include', 'delete', 'destroy', 'add', 'insert', 'replace', 'reset'} for v in values):
        raise PersistenceError('Unexpected commands in repair input')
    starts = [i for i in range(len(values)-2) if values[i:i+3] == ['set', SET, '{']]
    if len(starts) != 1: raise PersistenceError('Ambiguous blocked-port declaration')
    start = starts[0] + 2; depth = 0
    for end in range(start, len(values)):
        depth += (values[end] == '{') - (values[end] == '}')
        if depth == 0: break
    extra = end + 1; stop = extra
    while stop < len(values) and values[stop] == '}': stop += 1
    if not 1 <= stop - extra <= 8 or values[stop:stop+3] != ['set', 'docker-banned-ipv4', '{']:
        raise PersistenceError('Not the recognized premature-close bug; manual review required')
    for index in reversed(range(extra, stop)):
        text = text[:tokens[index][1]] + text[tokens[index][2]:]
    return text


def repair_file(apply=False):
    with locks(upgrade=True):
        target = DIRECTORY / 'docker-block.nft'; secure(target)
        original = target.read_bytes(); candidate = repair_text(original.decode()).encode()
        with tempfile.TemporaryDirectory(prefix='.f2b-repair-', dir=DIRECTORY) as folder:
            file = Path(folder) / 'candidate.nft'; file.write_bytes(candidate); file.chmod(0o600)
            validate_global({target: file})
        if not apply:
            print('PASS: known premature-close corruption; isolated syntax valid; preflight only')
            return
        folder = backup([target])
        try:
            commit({target: candidate})
            (folder / 'result').write_text('file-repaired; services/runtime untouched\n')
        except Exception:
            atomic(target, original)
            (folder / 'result').write_text('original-corrupt-file-restored; review-required\n')
            raise
        print('PASS: known file corruption repaired; no services started and no host rules loaded')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--block-port')
    mode.add_argument('--unblock-port')
    mode.add_argument('--repair-port-file', action='store_true')
    parser.add_argument('--apply', action='store_true', help='explicit file repair only')
    args = parser.parse_args()
    try:
        if os.geteuid() != 0: raise PersistenceError('Run with sudo')
        if args.apply and not args.repair_port_file: raise PersistenceError('--apply requires --repair-port-file')
        if args.repair_port_file: repair_file(args.apply)
        elif args.block_port is not None: change_port(args.block_port, True)
        elif args.unblock_port is not None: change_port(args.unblock_port, False)
        else: save()
        return 0
    except Exception as error:
        print('ERROR:', error, file=sys.stderr)
        return 1


if __name__ == '__main__': sys.exit(main())
