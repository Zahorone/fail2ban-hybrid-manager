"""Read-only membership: loaded action sets, stale sets, exact members and ranges."""
import copy
import importlib.util
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('diagnostic', ROOT / 'scripts/upgrade-v034dev-canary-227c393.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)

def refused(call):
    try: call()
    except (m.UpgradeError, RuntimeError, ValueError): return
    raise AssertionError('Expected strict read-only diagnostic failure')

bans = {'f2b-exploit-critical': ['192.0.2.17', '2001:db8::17'], 'recidive': []}
actions = {
    'f2b-exploit-critical': {'nftables': {
        'name': 'f2b-exploit-critical', 'addr_set': 'f2b-<name>',
        'addr_set?family=inet6': 'addr6-set-<name>', 'addr_type': 'ipv4_addr',
        'addr_type?family=inet6': 'ipv6_addr',
        'actionban': 'nft add element inet fail2ban-filter <addr_set> { <ip> }',
        'actionstart': 'nft add set inet fail2ban-filter <addr_set> { type <addr_type>; }'},
        'docker-sync-hook': {'actionban': '/usr/local/sbin/f2b-docker-hook ban <ip>'}},
    'recidive': {'nftables-recidive': {
        'table': 'fail2ban-filter', 'recidive_set': 'f2b-recidive',
        'recidive_set?family=inet6': 'f2b-recidive-v6',
        'actionban': 'nft add element inet <table> <recidive_set> { <ip> }',
        'actionstart': 'nft list set inet <table> <recidive_set>'}}
}
calls = []
def socket(command):
    calls.append(command)
    assert command[0] in {'status', 'get'}, 'Diagnostic attempted mutation'
    if command == ['status']: return [('Jail list', list(bans))]
    jail = command[1]
    if command[2] == 'banip': return bans[jail]
    if command[2] == 'actions': return list(actions[jail])
    if command[2] == 'actionproperties': return list(actions[jail][command[3]])
    if command[2] == 'action': return actions[jail][command[3]][command[4]]
    raise AssertionError(command)

def item(table, name, version, elements=()):
    return {'set': {'family': 'inet', 'table': table, 'name': name,
                    'type': 'ipv4_addr' if version == 4 else 'ipv6_addr', 'elem': list(elements)}}
document = {'nftables': [
    {'table': {'family': 'inet', 'name': table}} for table in ('fail2ban-filter', 'docker-block')]}
document['nftables'] += [
    item('fail2ban-filter', 'f2b-f2b-exploit-critical', 4, ['192.0.2.17']),
    item('fail2ban-filter', 'addr6-set-f2b-exploit-critical', 6, ['2001:db8::17']),
    item('fail2ban-filter', 'f2b-recidive', 4), item('fail2ban-filter', 'f2b-recidive-v6', 6),
    # Stale legacy aliases must not become the expected Docker union.
    item('fail2ban-filter', 'f2b-exploit-critical', 4, ['192.0.2.99']),
    item('fail2ban-filter', 'f2b-botnet-signatures', 4, ['192.0.2.98']),
    item('docker-block', 'docker-banned-ipv4', 4, ['192.0.2.17']),
    item('docker-block', 'docker-banned-ipv6', 6, ['2001:db8::17'])]
with patch.object(m, 'diagnostic_socket', side_effect=socket), patch.object(m, 'diagnostic_nft', return_value=document):
    m.diagnose_sync(docker=True)
    # Two loaded jails can intentionally share one effective set; compare union.
    bans['shared'] = ['192.0.2.18', '2001:db8::18']
    actions['shared'] = copy.deepcopy(actions['f2b-exploit-critical'])
    shared = copy.deepcopy(document)
    shared['nftables'][2]['set']['elem'].append('192.0.2.18')
    shared['nftables'][3]['set']['elem'].append('2001:db8::18')
    shared['nftables'][-2]['set']['elem'].append('192.0.2.18')
    shared['nftables'][-1]['set']['elem'].append('2001:db8::18')
    with patch.object(m, 'diagnostic_nft', return_value=shared): m.diagnose_sync(True)
    del bans['shared']; del actions['shared']
    # Equal counts, wrong member: neither count equality nor +/-1 is sufficient.
    altered = copy.deepcopy(document)
    altered['nftables'][2]['set']['elem'] = ['192.0.2.18']
    with patch.object(m, 'diagnostic_nft', return_value=altered): refused(m.diagnose_sync)
    # True extra Docker entries remain a mismatch; never silently prune them.
    altered = copy.deepcopy(document)
    altered['nftables'][-2]['set']['elem'].append('192.0.2.99')
    with patch.object(m, 'diagnostic_nft', return_value=altered): refused(lambda: m.diagnose_sync(True))
    with patch.object(m, 'diagnostic_socket', side_effect=RuntimeError('Failed API read')): refused(m.diagnose_sync)
    with patch.object(m, 'diagnostic_nft', side_effect=m.UpgradeError('Failed nft read')): refused(m.diagnose_sync)
    old = bans['f2b-exploit-critical']; bans['f2b-exploit-critical'] = ['not-an-address']
    refused(m.diagnose_sync); bans['f2b-exploit-critical'] = old
    # A zero-ban lazy action may lack both sets, but static recidive may not.
    bans['f2b-exploit-critical'] = []
    empty = copy.deepcopy(document)
    empty['nftables'] = [e for e in empty['nftables'] if e.get('set', {}).get('name') not in
                        {'f2b-f2b-exploit-critical', 'addr6-set-f2b-exploit-critical'}]
    for entry in empty['nftables']:
        if entry.get('set', {}).get('table') == 'docker-block': entry['set']['elem'] = []
    with patch.object(m, 'diagnostic_nft', return_value=empty): m.diagnose_sync(True)
    bans['f2b-exploit-critical'] = old
    with patch.object(m, 'diagnostic_nft', return_value={'nftables': []}): refused(m.diagnose_sync)

# Symbolic ranges: no enumeration even for an entire IPv6 /64.
assert m.diagnostic_ranges([{'range': ['192.0.2.1', '192.0.2.3']}], 4) == m.diagnostic_ranges(
    ['192.0.2.1', '192.0.2.2', '192.0.2.3'], 4)
assert m.diagnostic_ranges([{'prefix': {'addr': '2001:db8::', 'len': 64}}], 6) == [
    (int(m.ipaddress.ip_address('2001:db8::')), int(m.ipaddress.ip_address('2001:db8::ffff:ffff:ffff:ffff')))]
refused(lambda: m.diagnostic_compare('same count, different intervals',
        m.diagnostic_ranges([{'range': ['192.0.2.1', '192.0.2.3']}], 4),
        m.diagnostic_ranges([{'range': ['192.0.2.2', '192.0.2.4']}], 4)))
assert all(command[0] in {'status', 'get'} for command in calls)
refused(lambda: m.diagnostic_socket(['set', 'manualblock', 'unbanip', '192.0.2.17']))

spec = importlib.util.spec_from_file_location('hotfix', ROOT / 'scripts/install-diagnostic-hotfix.py')
hotfix = importlib.util.module_from_spec(spec); spec.loader.exec_module(hotfix)
generated = hotfix.checker_source().decode()
assert all(x not in generated for x in ('restore_bans(', 'reconcile(', 'hook_ban(', 'load_sync(', 'verify_npm_coverage('))
namespace = {'__name__': 'diagnostic_test'}; exec(compile(generated, '<generated-read-only>', 'exec'), namespace)
namespace['diagnostic_socket'] = socket; namespace['diagnostic_nft'] = lambda: document
namespace['diagnose_sync'](True)
# Exact patch scope across a legacy wrapper with a local diagnostic naming fix.
legacy = (ROOT.parent / 'v0.33/scripts/f2b-wrapper-v033.sh').read_text()
legacy += '\n# synthetic local edit outside diagnostics\n'
patched = hotfix.wrapper_source(legacy).decode()
masked_old, masked_new = legacy, patched
for name in ('f2b_sync_check', 'f2b_docker_verify'):
    masked_old = masked_old.replace(hotfix.function(masked_old, name), name, 1)
    masked_new = masked_new.replace(hotfix.function(masked_new, name), name, 1)
assert masked_old == masked_new
assert hotfix.function(legacy, 'manage_block_port') == hotfix.function(patched, 'manage_block_port')
assert hotfix.function(legacy, 'manage_unblock_port') == hotfix.function(patched, 'manage_unblock_port')
print('PASS: loaded effective sets, stale orphan exclusion, both-family exact membership, symbolic intervals and standalone read-only dependencies')
