#!/usr/bin/python3
"""Read-only offline inventory/dependency/syntax validation; never a host health check."""
import argparse
import importlib.util
import re
import sys
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
REQUIRED = {'INSTALL-ALL-v034.sh', 'scripts/fresh-install.py', 'scripts/upgrade-v033-v034.py',
            'scripts/01-install-nftables-v034.sh', 'scripts/04-install-docker-block-v034.sh',
            'scripts/f2b-wrapper-v034.sh', 'scripts/f2b-report-filter.py', 'scripts/f2b-save-owned-tables.py',
            'scripts/upgrade-v034dev-canary-227c393.py', 'config/jail.local',
            'config/nginx-recon-optimized.local', 'config/f2b-anomaly-detection.local',
            'actions/nftables.conf.local', 'actions/nftables-common.local'}


def verify(expected=None):
    spec = importlib.util.spec_from_file_location('bundle_upgrade', ROOT / 'scripts/upgrade-v033-v034.py')
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    module.validate_package(ROOT, module.install_map(ROOT))
    manifest = module.verify_package_manifest(ROOT)
    if manifest.get('bundle', {}).get('kind') != 'integrated-development-validation':
        raise ValueError('Not the integrated validation bundle')
    commit = manifest['source_commit']
    if not re.fullmatch('[0-9a-f]{40}', commit) or (expected and expected != commit):
        raise ValueError('Source commit mismatch')
    inventory = set(manifest['files'])
    required = REQUIRED | set(manifest['bundle']['required_files'])
    if not required <= inventory: raise ValueError('Missing integrated dependency inventory')
    if any(part in {'.git', '__pycache__'} for name in inventory for part in Path(name).parts):
        raise ValueError('Repository/cache files do not belong in the bundle')
    if set(manifest['known_targets']) != set(manifest['targets']): raise ValueError('Incomplete offline compatibility inventory')
    for target, digests in manifest['known_targets'].items():
        if not digests or not all(re.fullmatch('[0-9a-f]{64}', value) for value in digests):
            raise ValueError('Invalid canonical compatibility digest inventory')
    print('PASS: integrated offline inventory, dependencies and syntax; source=' + commit)
    print('Release 0.34-dev; VM/reboot/packet acceptance remains a separate operator gate')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument('--expected-commit')
    try: verify(parser.parse_args().expected_commit)
    except Exception as error:
        print('REFUSED:', error, file=sys.stderr); sys.exit(1)
