"""Package inventory/conflict/rollback regressions, without touching the host."""
import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('upgrade_package', ROOT / 'scripts/upgrade-v033-v034.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

original = '#!/usr/sbin/nft -f\nflush ruleset\ninclude "/etc/nftables.d/*.nft"\n# site rule\n'
safe = module.sanitized_nft_config(original)
assert '\nflush ruleset\n' not in safe and '# site rule' in safe
assert module.sanitized_nft_config(safe) == safe

with tempfile.TemporaryDirectory() as directory:
    directory = Path(directory).resolve()
    target = directory / 'site.local'
    source = directory / 'replacement'
    source.write_text('new known policy\n')
    target.write_text('old approved local repair\n')
    digest = hashlib.sha256(target.read_bytes()).hexdigest()
    manifest = {'known_targets': {str(target): [digest]}}
    with patch.object(module, 'verify_package_manifest', return_value=manifest):
        module.audit_targets(ROOT, {target: source})
        target.write_text('unknown site override\n')
        try: module.audit_targets(ROOT, {target: source})
        except module.UpgradeError as error: assert str(target) in str(error) and 'SHA256=' in str(error)
        else: raise AssertionError('Unknown .local was overwritten')
        assert target.read_text() == 'unknown site override\n'
        target.write_bytes(source.read_bytes())
        module.audit_targets(ROOT, {target: source})  # repeated apply

    old = directory / 'jail.d/existing.local'
    new = directory / 'jail.d/new.local'
    old.parent.mkdir()
    old.write_text('keep original\n')
    new.write_text('introduced by upgrade\n')
    backup = directory / 'backup'
    backup.mkdir()
    (backup / 'manifest.json').write_text(json.dumps({'members': [str(old.relative_to('/'))]}))
    module.restore_files(backup, {old: source, new: source})
    assert old.read_text() == 'keep original\n' and not new.exists()

    # Failure after the first installed file must reach rollback; a failed
    # rollback must be prominent, never reported as successful recovery.
    mapping = {directory / 'first': source, directory / 'second': source}
    calls = []
    def fail_second(source, target):
        calls.append(target)
        if len(calls) == 2: raise OSError('injected middle-of-deploy failure')
    with patch.object(module, 'require_root'), patch.object(module, 'acquire_upgrade_lock'), \
         patch.object(module, 'install_map', return_value=mapping), \
         patch.object(module, 'preflight', return_value=({'recidive': []}, {'nftables': []})), \
         patch.object(module, 'create_backup', return_value=backup), \
         patch.object(module, 'prepare_persistence'), patch.object(module, 'atomic_install', side_effect=fail_second), \
         patch.object(module, 'rollback') as rollback, patch.object(sys, 'argv', ['upgrade', '--apply']):
        assert module.main() == 1
        assert calls == list(mapping)
        rollback.assert_called_once_with(backup, mapping)
        calls.clear()
        rollback.side_effect = OSError('injected rollback failure')
        error = io.StringIO()
        with contextlib.redirect_stderr(error): assert module.main() == 1
        assert 'AUTOMATIC ROLLBACK ALSO FAILED' in error.getvalue()
        assert str(backup) in error.getvalue()

print('PASS: recognized local fixes, repeat apply, unknown override conflict, new-file rollback and double failure')
