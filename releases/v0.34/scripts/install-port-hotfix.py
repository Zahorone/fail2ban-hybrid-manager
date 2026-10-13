#!/usr/bin/python3
"""Scoped v0.33/v0.34 port-persistence hotfix; preflight unless --apply.

Preserve the installed wrapper outside two recognized functions. No services,
host firewall loads, packages, profiles, CrowdSec configuration or DB changes.
"""
import argparse
import importlib.util
import os
from pathlib import Path
import re
import sys
import tempfile

SOURCE = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('port_save', SOURCE / 'scripts/f2b-save-owned-tables.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
WRAPPER = Path('/usr/local/bin/f2b')
HELPER = Path('/usr/local/sbin/f2b-save-owned-tables.py')
LEGACY = '0f9209f0244c100a27627c315a306ba1a2479482'


def function(text, name):
    matches = list(re.finditer(r'^' + name + r'\(\) \{\n.*?^\}$', text, re.M | re.S))
    if len(matches) != 1: raise m.PersistenceError('Unknown/ambiguous wrapper function: ' + name)
    return matches[0][0]


def legacy(relative):
    return m.run('git', '-C', str(SOURCE.parents[1]), 'show', LEGACY + ':' + relative)


def plan():
    if Path('/tmp/f2b-wrapper.lock').exists():
        raise m.PersistenceError('Legacy wrapper operation may be active; inspect it, do not blindly remove its lock')
    m.secure(WRAPPER)
    installed = WRAPPER.read_bytes().decode('utf-8')
    canonical = (SOURCE / 'scripts/f2b-wrapper-v034.sh').read_text()
    old = [legacy('releases/v0.34/scripts/f2b-wrapper-v034.sh'),
           (SOURCE.parent / 'v0.33/scripts/f2b-wrapper-v033.sh').read_text()]
    for name in ('manage_block_port', 'manage_unblock_port'):
        body = function(installed, name)
        wanted = function(canonical, name)
        if body not in [wanted, *(function(text, name) for text in old)]:
            raise m.PersistenceError('Unrecognized local port function; refuse overwriting it')
        installed = installed.replace(body, wanted, 1)
    with tempfile.TemporaryDirectory(prefix='f2b-port-wrapper-') as folder:
        candidate = Path(folder) / 'f2b'; candidate.write_text(installed)
        m.run('bash', '-n', str(candidate))
    helper = (SOURCE / 'scripts/f2b-save-owned-tables.py').read_bytes()
    compile(helper, str(HELPER), 'exec')
    if HELPER.exists() or HELPER.is_symlink():
        m.secure(HELPER)
        if HELPER.read_bytes() not in (helper, legacy('releases/v0.34/scripts/f2b-save-owned-tables.py').encode()):
            raise m.PersistenceError('Unknown local snapshot helper; preserve and review it')
    else:
        for parent in HELPER.parents:
            info = parent.lstat()
            if parent.is_symlink() or info.st_uid != 0 or info.st_mode & 0o022:
                raise m.PersistenceError('Unsafe helper installation parent')
    target = m.DIRECTORY / 'docker-block.nft'; m.secure(target)
    replacement = {WRAPPER: installed.encode(), HELPER: helper}
    try: m.validate_global({})
    except Exception:
        repaired = m.repair_text(target.read_text()).encode()
        with tempfile.TemporaryDirectory(prefix='.f2b-port-check-', dir=m.DIRECTORY) as folder:
            candidate = Path(folder) / 'docker-block.nft'; candidate.write_bytes(repaired)
            m.validate_global({target: candidate})
        replacement[target] = repaired
    return replacement


def apply(replacement):
    existed = {file: file.exists() for file in replacement}
    old = {file: file.read_bytes() for file in replacement if existed[file]}
    backup = m.backup(list(old))
    try:
        for file, data in replacement.items():
            if existed[file]: m.atomic(file, data)
            else:
                descriptor, candidate = tempfile.mkstemp(prefix='.f2b-helper-', dir=file.parent)
                try:
                    with os.fdopen(descriptor, 'wb') as output:
                        output.write(data); output.flush(); os.fsync(output.fileno())
                    os.chmod(candidate, 0o755)
                    if file.exists() or file.is_symlink(): raise m.PersistenceError('Helper appeared during install')
                    os.replace(candidate, file)
                finally: Path(candidate).unlink(missing_ok=True)
        m.run('bash', '-n', str(WRAPPER))
        m.validate_global({})
        if any(file.read_bytes() != data for file, data in replacement.items()):
            raise m.PersistenceError('Installed hotfix fingerprint mismatch')
        (backup / 'result').write_text('hotfix-installed; runtime/services untouched\n')
    except Exception:
        for file, data in old.items(): m.atomic(file, data)
        for file in replacement:
            if not existed[file]: file.unlink(missing_ok=True)
        (backup / 'result').write_text('original-files-restored; prior-corrupt-state-may-remain\n')
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    try:
        if os.geteuid() != 0: raise m.PersistenceError('Run with sudo')
        with m.locks(upgrade=True):
            replacement = plan()
            if args.apply: apply(replacement)
        print('PASS: port hotfix ' + ('installed' if args.apply else 'preflight only') + '; no host rules loaded or services started')
        return 0
    except Exception as error:
        print('REFUSED/FAILED:', error, file=sys.stderr)
        return 1


if __name__ == '__main__': sys.exit(main())
