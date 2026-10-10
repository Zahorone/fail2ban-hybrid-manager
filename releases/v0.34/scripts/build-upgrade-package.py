#!/usr/bin/env python3
"""Build a self-contained, checksummed v0.33 upgrade archive from a clean HEAD."""
import argparse
import gzip
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile


def build(output):
    root = Path(__file__).resolve().parents[1]
    repo = root.parents[1]
    def git(*args):
        return subprocess.check_output(['git', '-C', str(repo), *args], text=True).strip()
    if git('status', '--porcelain', '--untracked-files=no'):
        raise RuntimeError('Build only from a clean committed tracked checkout')
    commit = git('rev-parse', 'HEAD')
    spec = importlib.util.spec_from_file_location('upgrade', root / 'scripts/upgrade-v033-v034.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    mapping = module.install_map(root)
    files = set(mapping.values()) | {root / 'VERSION', root / 'scripts/upgrade-v033-v034.py',
             root / 'docs/UPGRADE-v033-v034.md'}
    for source in files:
        relative = str(source.relative_to(repo))
        if git('hash-object', relative) != git('rev-parse', 'HEAD:' + relative):
            raise RuntimeError('Payload is not the committed HEAD: ' + relative)
    known = {}
    for target, source in mapping.items():
        previous = root.parent / 'v0.33' / source.relative_to(root)
        if source.name == 'f2b-wrapper-v034.sh': previous = root.parent / 'v0.33/scripts/f2b-wrapper-v033.sh'
        known[str(target)] = [hashlib.sha256(p.read_bytes()).hexdigest() for p in (previous, source) if p.is_file()]
    manifest = {'schema': 1, 'release': module.RELEASE, 'source_commit': commit,
                'upgrade_from': ['0.33', '0.34-dev'], 'known_targets': known,
                'files': {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(files)},
                'targets': {str(p): str(s.relative_to(root)) for p, s in sorted(mapping.items())},
                'generated_targets': ['/etc/nftables.conf', '/etc/nftables.d/fail2ban-filter.nft', '/etc/nftables.d/docker-block.nft'],
                'optional_application_hardening': 'not included'}
    with tempfile.TemporaryDirectory(prefix='f2b-upgrade-build-') as directory:
        package = Path(directory) / ('f2b-upgrade-v033-v034-' + commit[:7])
        package.mkdir()
        for source in sorted(files):
            target = package / source.relative_to(root)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(source.read_bytes())
        (package / 'UPGRADE-MANIFEST.json').write_text(json.dumps(manifest, indent=2, sort_keys=True) + '\n')
        sums = [hashlib.sha256(p.read_bytes()).hexdigest() + '  ' + str(p.relative_to(package))
                for p in sorted(package.rglob('*')) if p.is_file()]
        (package / 'SHA256SUMS').write_text('\n'.join(sums) + '\n')
        module.validate_package(package, module.install_map(package))
        # No real hostnames, addresses, logs, credentials or databases are
        # included. Refuse common secret/production artifacts as an extra guard.
        for path in package.rglob('*'):
            if path.is_file() and (path.suffix in {'.sqlite3', '.db', '.pem', '.key', '.log'} or
                                  b'BEGIN PRIVATE KEY' in path.read_bytes()):
                raise RuntimeError('Sensitive artifact: ' + str(path))
        with output.open('xb') as raw, gzip.GzipFile(fileobj=raw, mode='wb', mtime=0, filename='') as compressed:
            with tarfile.open(fileobj=compressed, mode='w') as archive:
                for path in sorted(package.rglob('*')):
                    if not path.is_file(): continue
                    info = tarfile.TarInfo(str(path.relative_to(package.parent)))
                    data = path.read_bytes()
                    info.size, info.mode = len(data), 0o644
                    archive.addfile(info, io.BytesIO(data))
    print(json.dumps({'commit': commit, 'archive': str(output.resolve()), 'bytes': output.stat().st_size,
                      'sha256': hashlib.sha256(output.read_bytes()).hexdigest()}, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    build(parser.parse_args().output)
