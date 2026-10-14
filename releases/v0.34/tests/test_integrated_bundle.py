"""Validate the actual generic archive, offline inventory and failure refusals."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile


def run(root, okay=True):
    result = subprocess.run(['/usr/bin/python3', str(root / 'scripts/verify-integrated-bundle.py')],
                            text=True, capture_output=True)
    assert (result.returncode == 0) == okay, result.stdout + result.stderr


def test(archive, destination):
    receipt = json.loads(archive.with_name(archive.name + '.json').read_text())
    assert hashlib.sha256(archive.read_bytes()).hexdigest() == receipt['sha256']
    assert archive.with_name(archive.name + '.sha256').read_text() == receipt['sha256'] + '  ' + archive.name + '\n'
    destination.mkdir()
    with tarfile.open(archive) as stream:
        names = set()
        for item in stream.getmembers():
            path = Path(item.name)
            assert item.isfile() and not path.is_absolute() and '..' not in path.parts and len(path.parts) >= 2
            assert item.name not in names; names.add(item.name)
            assert item.uid == item.gid == item.mtime == 0
        assert len({Path(name).parts[0] for name in names}) == 1
        stream.extractall(destination)
    root = next(destination.iterdir())
    run(root)
    manifest = json.loads((root / 'UPGRADE-MANIFEST.json').read_text())
    assert manifest['source_commit'] == receipt['commit'] and receipt['release'] == '0.34-dev'
    assert manifest['bundle']['runtime_git_required'] is False
    assert not any(part == '.git' for name in names for part in Path(name).parts)
    with tempfile.TemporaryDirectory(prefix='f2b-integrated-tamper-') as temporary:
        clone = Path(temporary) / 'bundle'; shutil.copytree(root, clone)
        # Required dependency removed / modified, foreign file, truncated sums,
        # symlink substitution and wrong pinned source must fail offline.
        target = clone / 'scripts/f2b-report-filter.py'; content = target.read_bytes()
        target.unlink(); run(clone, False)
        target.write_bytes(content + b'\n# changed\n'); run(clone, False)
        target.write_bytes(content)
        extra = clone / 'unlisted'; extra.touch(); run(clone, False); extra.unlink()
        sums = clone / 'SHA256SUMS'; original = sums.read_bytes(); sums.write_bytes(b''); run(clone, False); sums.write_bytes(original)
        target.unlink(); target.symlink_to(root / 'scripts/f2b-report-filter.py'); run(clone, False); target.unlink(); target.write_bytes(content)
        result = subprocess.run(['/usr/bin/python3', str(clone / 'scripts/verify-integrated-bundle.py'), '--expected-commit', '0' * 40], capture_output=True)
        assert result.returncode != 0
        run(clone)
    print('PASS: exact artifact checksums/inventory, offline dependency and tamper/symlink/commit refusals; no Git repository in runtime package')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(); parser.add_argument('archive', type=Path); parser.add_argument('--extract-to', required=True, type=Path)
    args = parser.parse_args(); test(args.archive, args.extract_to)
