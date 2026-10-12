"""Active-profile diagnostics with strict API and nft failures; no host writes."""
import importlib.util
from pathlib import Path
import subprocess
from types import SimpleNamespace
from unittest.mock import Mock, patch

spec = importlib.util.spec_from_file_location('diagnostic', Path(__file__).resolve().parents[1] / 'scripts/upgrade-v034dev-canary-227c393.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)

def refused(function):
    try: function()
    except (m.UpgradeError, RuntimeError): return
    raise AssertionError('Expected strict diagnostic failure')

def command(*parts, **kwargs):
    if parts == ('fail2ban-client', 'status'):
        return subprocess.CompletedProcess([], 0, 'Jail list: manualblock, recidive\n', '')
    if parts in {('fail2ban-client', 'get', 'manualblock', 'banip'),
                 ('fail2ban-client', 'get', 'recidive', 'banip')}:
        return subprocess.CompletedProcess([], 0, '', '')
    raise AssertionError('Unexpected disabled jail/API query')

document = {'nftables': [{'table': {'family': 'inet', 'name': 'fail2ban-filter'}}] + [
    {'set': {'family': 'inet', 'table': 'fail2ban-filter', 'name': name}}
    for name in ('f2b-recidive', 'f2b-recidive-v6')]}
sync = SimpleNamespace(readset=Mock(return_value={}))
loader = SimpleNamespace(loader=SimpleNamespace(exec_module=lambda module: None))
with patch.object(m, 'run', side_effect=command), patch.object(m, 'nft_json', return_value=document), \
     patch.object(m, 'effective_nft_actions', return_value={4: ('lazy-v4', ''), 6: ('lazy-v6', '')}), \
     patch.object(m.importlib.util, 'spec_from_file_location', return_value=loader), \
     patch.object(m.importlib.util, 'module_from_spec', return_value=sync):
    m.diagnose_sync(docker=True)
    with patch.object(m, 'run', side_effect=m.UpgradeError('Failed API read')):
        refused(m.diagnose_sync)
    with patch.object(m, 'run', return_value=subprocess.CompletedProcess([], 0, 'garbage', '')):
        refused(m.diagnose_sync)
    sync.readset.return_value = {'192.0.2.9': float('inf')}
    refused(m.diagnose_sync)
    sync.readset.side_effect = RuntimeError('nft read failed')
    refused(m.diagnose_sync)
    sync.readset.side_effect = None; sync.readset.return_value = {}
    with patch.object(m, 'nft_json', return_value={'nftables': []}):
        refused(m.diagnose_sync)

print('PASS: partial core profile, lazy empty action sets, strict ban/API/nft reads and stale membership failure')
