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


INTEGRATED_FILES = (
    'INSTALL-ALL-v034.sh', 'scripts/fresh-install.py',
    'scripts/01-install-nftables-v034.sh', 'scripts/04-install-docker-block-v034.sh',
    'scripts/verify-integrated-bundle.py', 'config/jail.local',
    'config/nginx-recon-optimized.local', 'config/f2b-anomaly-detection.local',
    'docs/INTEGRATED-VALIDATION.md', 'docs/FRESH-INSTALL.md', 'docs/DOCKER-NPM-LAB.md',
    'docs/REPORTING-ONLY-HOTFIX.md', 'examples/docker-npm-lab/compose.json',
    'examples/docker-npm-lab/compose.ipv6.json',
)


def build(output, integrated=False):
    root = Path(__file__).resolve().parents[1]
    repo = root.parents[1]
    def git(*args):
        return subprocess.check_output(['git', '-C', str(repo), *args], text=True).strip()
    if git('status', '--porcelain', '--untracked-files=no'):
        raise RuntimeError('Build only from a clean committed tracked checkout')
    policy_spec = importlib.util.spec_from_file_location('publication_policy', repo / 'scripts/check-publication-safety.py')
    policy = importlib.util.module_from_spec(policy_spec)
    policy_spec.loader.exec_module(policy)
    subprocess.run(['python3', str(repo / 'scripts/check-publication-safety.py')], check=True)
    commit = git('rev-parse', 'HEAD')
    spec = importlib.util.spec_from_file_location('upgrade', root / 'scripts/upgrade-v033-v034.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    mapping = module.install_map(root)
    files = set(mapping.values()) | {root / 'VERSION', root / 'scripts/upgrade-v033-v034.py',
             root / 'docs/UPGRADE-v033-v034.md', root / 'docs/MODULE-ARCHITECTURE.md',
             root / 'docs/ACCESS-FILTER-SAFETY.md'}
    if integrated:
        files.update(root / name for name in INTEGRATED_FILES)
        files.update((root / 'actions').glob('*.local'))
    for source in files:
        relative = str(source.relative_to(repo))
        if git('hash-object', relative) != git('rev-parse', 'HEAD:' + relative):
            raise RuntimeError('Payload is not the committed HEAD: ' + relative)
    known = {}
    for target, source in mapping.items():
        previous = root.parent / 'v0.33' / source.relative_to(root)
        if source.name == 'f2b-wrapper-v034.sh': previous = root.parent / 'v0.33/scripts/f2b-wrapper-v033.sh'
        digests = set()
        for path in (previous, source):
            relative = str(path.relative_to(repo))
            for revision in git('log', '--format=%H', '--', relative).splitlines():
                content = subprocess.run(['git', '-C', str(repo), 'show', revision + ':' + relative], capture_output=True)
                # Compatibility digests come only from canonical component
                # history, never deployment review exports. Old source text is
                # not copied into the package; policing its examples here would
                # incorrectly reject an otherwise recognized legacy install.
                if content.returncode == 0:
                    digests.add(hashlib.sha256(content.stdout).hexdigest())
        known[str(target)] = sorted(digests)
    manifest = {'schema': 1, 'release': module.RELEASE, 'source_commit': commit,
                'known_target_policy': 'canonical-source-history-v1',
                'filter_override_policy': module.FILTER_OVERRIDE_POLICY,
                'upgrade_from': ['0.33', '0.33-ipv6.1', '0.34-dev'], 'known_targets': known,
                'files': {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(files)},
                'targets': {str(p): str(s.relative_to(root)) for p, s in sorted(mapping.items())},
                'generated_targets': ['/etc/nftables.conf', '/etc/nftables.d/fail2ban-filter.nft', '/etc/nftables.d/docker-block.nft'],
                'optional_application_hardening': 'not included'}
    if integrated:
        manifest['bundle'] = {'kind': 'integrated-development-validation',
            'fresh_entrypoint': 'INSTALL-ALL-v034.sh', 'upgrade_entrypoint': 'scripts/upgrade-v033-v034.py',
            'required_files': sorted(INTEGRATED_FILES + tuple(str(p.relative_to(root)) for p in (root / 'actions').glob('*.local'))),
            'vm_acceptance': 'pending; namespace CI is not boot/packet evidence',
            'runtime_git_required': False}
    with tempfile.TemporaryDirectory(prefix='f2b-upgrade-build-') as directory:
        package = Path(directory) / (('f2b-integrated-v034-dev-' if integrated else 'f2b-upgrade-v033-v034-') + commit[:7])
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
            if path.is_file():
                text = policy.decode(path.read_bytes())
                hits = policy.findings(text, str(path.relative_to(package))) if text is not None else []
                if hits:
                    for label, line, kind in hits: print(f'{label}:{line}: {kind}')
                    raise RuntimeError('Publication gate rejected package; values suppressed')
        with output.open('xb') as raw, gzip.GzipFile(fileobj=raw, mode='wb', mtime=0, filename='') as compressed:
            with tarfile.open(fileobj=compressed, mode='w') as archive:
                for path in sorted(package.rglob('*')):
                    if not path.is_file(): continue
                    info = tarfile.TarInfo(str(path.relative_to(package.parent)))
                    data = path.read_bytes()
                    info.size, info.mode = len(data), 0o644
                    archive.addfile(info, io.BytesIO(data))
    digest = hashlib.sha256(output.read_bytes()).hexdigest()
    receipt = {'commit': commit, 'archive_name': output.name, 'bytes': output.stat().st_size,
               'sha256': digest, 'release': module.RELEASE, 'integrated': integrated}
    if integrated:
        output.with_name(output.name + '.sha256').write_text(digest + '  ' + output.name + '\n')
        output.with_name(output.name + '.json').write_text(json.dumps(receipt, indent=2, sort_keys=True) + '\n')
    print(json.dumps(receipt, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    parser.add_argument('--integrated', action='store_true', help='include complete fresh and upgrade validation entrypoints')
    args = parser.parse_args()
    build(args.output, integrated=args.integrated)
