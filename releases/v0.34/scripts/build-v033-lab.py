#!/usr/bin/python3
"""Generic lab payload only: exact recognized v0.33-family canonical sources."""
import gzip
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile
import argparse

BASELINE = '196400970b669f8fd43eebadad3b971125de857e'
ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT.parents[1]


def git(*args): return subprocess.check_output(['git', '-C', str(REPO), *args])


def build(output):
    if git('status', '--porcelain', '--untracked-files=no').strip(): raise ValueError('Build requires clean committed HEAD')
    spec = importlib.util.spec_from_file_location('policy', REPO / 'scripts/check-publication-safety.py')
    policy = importlib.util.module_from_spec(spec); spec.loader.exec_module(policy)
    names = git('ls-tree', '-r', '--name-only', BASELINE, '--', 'releases/v0.33/filters', 'releases/v0.33/actions').decode().splitlines()
    names += ['releases/v0.33/' + p for p in ('config/jail.local', 'scripts/f2b-wrapper-v033.sh',
              'scripts/f2b-docker-hook.sh', 'scripts/f2b-ipv6-sync.py')]
    files = {str(Path('baseline') / Path(name).relative_to('releases/v0.33')): git('show', BASELINE + ':' + name) for name in names}
    for name in ('scripts/bootstrap-v033-lab.py', 'scripts/boot-contract.py', 'docs/V033-LAB-BOOTSTRAP.md'):
        current = (ROOT / name).read_bytes()
        if current != git('show', 'HEAD:releases/v0.34/' + name): raise ValueError('Uncommitted builder payload')
        files[name] = current
    for name, data in files.items():
        if policy.findings(data.decode(), name): raise ValueError('Publication policy rejected generic lab file: ' + name)
    commit = git('rev-parse', 'HEAD').decode().strip()
    files['LAB-MANIFEST.json'] = (json.dumps({'schema': 1, 'canonical_source': BASELINE, 'bootstrap_source': commit,
        'kind': 'synthetic-lab-only', 'baseline_version': '0.33-ipv6.1',
        'files': {name: hashlib.sha256(data).hexdigest() for name, data in files.items()}}, sort_keys=True, indent=2) + '\n').encode()
    files['SHA256SUMS'] = ''.join(hashlib.sha256(data).hexdigest() + '  ' + name + '\n' for name, data in sorted(files.items())).encode()
    with output.open('xb') as raw, gzip.GzipFile(fileobj=raw, mode='wb', mtime=0, filename='') as compressed:
        with tarfile.open(fileobj=compressed, mode='w') as archive:
            for name, data in sorted(files.items()):
                info = tarfile.TarInfo('f2b-v033-lab-' + commit[:7] + '/' + name); info.size = len(data); info.mode = 0o644
                archive.addfile(info, io.BytesIO(data))
    digest = hashlib.sha256(output.read_bytes()).hexdigest()
    output.with_name(output.name + '.sha256').write_text(digest + '  ' + output.name + '\n')
    print(json.dumps({'canonical_source': BASELINE, 'bootstrap_source': commit, 'sha256': digest, 'archive': output.name}, sort_keys=True))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument('output', type=Path)
    build(parser.parse_args().output)
