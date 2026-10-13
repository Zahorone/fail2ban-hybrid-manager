#!/usr/bin/python3
"""Stage a standalone read-only checker and patch only two wrapper diagnostics.

No service reload, synchronization, filter/port/persistence/DB or ban changes.
Default preflight validates code/dependencies, not membership correctness.
"""
import argparse
import ast
from contextlib import contextmanager
import fcntl
import hashlib
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile

SOURCE = Path(__file__).resolve().parents[1]
WRAPPER = Path('/usr/local/bin/f2b')
CHECKER = Path('/usr/local/libexec/f2b-diagnostic-membership.py')
FUNCTIONS = ('diagnostic_socket', 'diagnostic_bans', 'diagnostic_action_sets',
             'diagnostic_merge', 'diagnostic_ranges', 'diagnostic_nft',
             'diagnostic_compare', 'diagnose_sync')


class HotfixError(RuntimeError): pass


def run(*parts):
    result = subprocess.run(parts, text=True, capture_output=True)
    if result.returncode: raise HotfixError('Preflight command failed: ' + ' '.join(parts))
    return result.stdout


def checker_source():
    # Generate from the canonical pure read-only functions, not a mutable
    # reconciler/upgrader import. No production helper versions are replaced.
    source = (SOURCE / 'scripts/upgrade-v034dev-canary-227c393.py').read_text()
    nodes = {n.name: n for n in ast.parse(source).body if isinstance(n, ast.FunctionDef)}
    code = '#!/usr/bin/python3\nimport ipaddress,json,os,re,subprocess,sys\n'
    code += 'class UpgradeError(RuntimeError): pass\n\n'
    code += '\n\n'.join(ast.get_source_segment(source, nodes[name]) for name in FUNCTIONS)
    code += '''

if __name__ == '__main__':
    try:
        if os.geteuid() != 0: raise UpgradeError('Run with sudo')
        if sys.argv[1:] not in [['--sync-check'], ['--docker-check']]:
            raise UpgradeError('Only --sync-check or --docker-check is supported; read-only')
        diagnose_sync(docker=sys.argv[1] == '--docker-check')
    except Exception as error:
        print('ERROR:', error, file=sys.stderr)
        sys.exit(1)
'''
    compile(code, str(CHECKER), 'exec')
    return code.encode()


def function(text, name):
    found = list(re.finditer(r'^' + name + r'\(\) \{\n.*?^\}$', text, re.M | re.S))
    if len(found) != 1: raise HotfixError('Unknown/ambiguous diagnostic function: ' + name)
    return found[0][0]


def wrapper_source(installed):
    for name, option in (('f2b_sync_check', '--sync-check'), ('f2b_docker_verify', '--docker-check')):
        body = function(installed, name)
        replacement = name + '() {\n  sudo /usr/bin/python3 ' + str(CHECKER) + ' ' + option + '\n}'
        canonical = ('f2b-runtime-verify.py ' + option in body)
        legacy = (all(value in body for value in ('get_f2b_ips', 'ALLSYNCED')) if name == 'f2b_sync_check'
                  else all(value in body for value in ('ALL_JAILS', 'ALL_SETS', 'docker-banned-ipv4')))
        if body != replacement and not canonical and not legacy:
            raise HotfixError('Unrecognized diagnostic body; preserve and review manually: ' + name)
        installed = installed.replace(body, replacement, 1)
    return installed.encode()


def secure(file, missing=False):
    if missing and not file.exists() and not file.is_symlink(): items = file.parents
    else: items = (file, *file.parents)
    for item in items:
        if missing and not item.exists() and not item.is_symlink(): continue
        info = item.lstat()
        if stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise HotfixError('Unsafe diagnostic target/ancestor ownership, mode or symlink')
        if item != file and not item.is_dir(): raise HotfixError('Diagnostic ancestor must be a directory')
    if file.exists() and not file.is_file(): raise HotfixError('Expected regular diagnostic target')


@contextmanager
def lock():
    with open('/run/lock/f2b-upgrade.lock', 'a') as stream:
        fcntl.flock(stream, fcntl.LOCK_EX)
        if Path('/tmp/f2b-wrapper.lock').exists():
            raise HotfixError('A legacy wrapper operation may be active; inspect it before retrying')
        yield


def plan():
    secure(WRAPPER); secure(CHECKER, missing=True)
    if not shutil.which('nft') or not shutil.which('bash'):
        raise HotfixError('nft and bash required; no packages installed by this tool')
    run('/usr/bin/python3', '-c', 'from fail2ban.client.csocket import CSocket')
    helper = checker_source()
    if CHECKER.exists() and CHECKER.read_bytes() != helper:
        raise HotfixError('Existing standalone checker differs; preserve/review it before overwrite')
    original = WRAPPER.read_bytes().decode('utf-8')
    patched = wrapper_source(original)
    # Exact non-diagnostic bytes, including port fixes and local edits, must stay.
    before, after = original, patched.decode()
    for name in ('f2b_sync_check', 'f2b_docker_verify'):
        before = before.replace(function(before, name), name, 1)
        after = after.replace(function(after, name), name, 1)
    if before != after: raise HotfixError('Unexpected wrapper changes outside diagnostics')
    with tempfile.TemporaryDirectory(prefix='f2b-diag-stage-') as temporary:
        candidate = Path(temporary) / 'f2b'; candidate.write_bytes(patched)
        run('bash', '-n', str(candidate))
    return {CHECKER: helper, WRAPPER: patched}


def atomic(file, contents):
    secure(file, missing=True)
    descriptor, candidate = tempfile.mkstemp(prefix='.f2b-diag-', dir=file.parent)
    try:
        with os.fdopen(descriptor, 'wb') as output:
            output.write(contents); output.flush(); os.fsync(output.fileno())
        if file.exists():
            shutil.copystat(file, candidate, follow_symlinks=False)
            info = file.stat(); os.chown(candidate, info.st_uid, info.st_gid)
        else: os.chmod(candidate, 0o755)
        os.replace(candidate, file)
        directory = os.open(file.parent, os.O_RDONLY | os.O_DIRECTORY)
        try: os.fsync(directory)
        finally: os.close(directory)
    finally: Path(candidate).unlink(missing_ok=True)


def apply(replacement):
    parent = Path('/var/backups')
    for item in (parent, *parent.parents):
        info = item.lstat()
        if item.is_symlink() or info.st_uid != 0 or info.st_mode & 0o022:
            raise HotfixError('Unsafe private backup parent')
    backup = Path(tempfile.mkdtemp(prefix='f2b-diagnostics-', dir=parent)); backup.chmod(0o700)
    old = {file: file.read_bytes() if file.exists() else None for file in replacement}
    manifest = {}
    for index, (file, contents) in enumerate(old.items()):
        if contents is not None: shutil.copy2(file, backup / ('target-' + str(index)))
        manifest[str(file)] = {'existed': contents is not None,
                              'before': hashlib.sha256(contents).hexdigest() if contents is not None else None,
                              'after': hashlib.sha256(replacement[file]).hexdigest()}
    (backup / 'manifest.json').write_text(__import__('json').dumps({'schema': 1, 'targets': manifest}, sort_keys=True))
    print('Private diagnostic-code backup:', backup)
    try:
        CHECKER.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
        # Helper first; wrapper never points at an absent staged dependency.
        for file, contents in replacement.items(): atomic(file, contents)
        run('bash', '-n', str(WRAPPER))
        if any(file.read_bytes() != contents for file, contents in replacement.items()):
            raise HotfixError('Diagnostic deployment fingerprint mismatch')
        (backup / 'result').write_text('complete; runtime untouched\n')
    except Exception:
        for file in reversed(list(replacement)):
            if old[file] is None: file.unlink(missing_ok=True)
            else: atomic(file, old[file])
        (backup / 'result').write_text('original-code-restored\n')
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    try:
        if os.geteuid() != 0: raise HotfixError('Run with sudo')
        with lock():
            replacement = plan()
            if args.apply: apply(replacement)
        print('PASS: diagnostic-only ' + ('deployment' if args.apply else 'staging/dependency preflight') +
              '; membership correctness is checked separately; no synchronization/service changes')
        return 0
    except Exception as error:
        print('REFUSED/FAILED:', error, file=sys.stderr)
        return 1


if __name__ == '__main__': sys.exit(main())
