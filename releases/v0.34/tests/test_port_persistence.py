"""Port persistence regressions; --net requires PRIVATE mount+network namespaces."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('ports', ROOT / 'scripts/f2b-save-owned-tables.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
parser = argparse.ArgumentParser(); parser.add_argument('--net', dest='network_test', action='store_true'); args = parser.parse_args()


def refused(call):
    try: call()
    except (m.PersistenceError, OSError): return
    raise AssertionError('Expected fail-closed refusal')


for elements in ('', 'elements = { 82 }', 'elements = {\n82, 10000\n}'): 
    valid = 'table inet docker-block {\n set docker-blocked-ports { type inet_service; ' + elements + '\n }\n set docker-banned-ipv4 { type ipv4_addr; }\n}\n'
    corrupt = valid.replace('\n }\n set docker-banned', '\n }\n } # known extra\n set docker-banned')
    fixed = m.repair_text(corrupt)
    assert fixed == corrupt.replace('} # known extra', ' # known extra', 1)
    refused(lambda: m.repair_text(valid))
refused(lambda: m.repair_text('flush ruleset\ntable inet docker-block {}'))
refused(lambda: m.repair_text('table inet unrelated { }'))
for port in ('0', '65536', '1; flush ruleset', 'foo'):
    refused(lambda: m.change_port(port, True))
source = (ROOT / 'scripts/f2b-wrapper-v034.sh').read_text()
for name in ('manage_block_port', 'manage_unblock_port'):
    function = re.search(r'^' + name + r'\(\) \{\n.*?^\}$', source, re.M | re.S)[0]
    assert 'sed ' not in function and 'f2b-save-owned-tables.py' in function
    assert '|| return $?' in function

if not args.network_test:
    print('PASS: known brace corruption recognition, refusal and wrapper error propagation contracts')
    raise SystemExit(0)
assert os.geteuid() == 0
assert os.readlink('/proc/self/ns/net') != os.readlink('/proc/1/ns/net')
assert os.readlink('/proc/self/ns/mnt') != os.readlink('/proc/1/ns/mnt')
m.run('mount', '--make-rprivate', '/')
with tempfile.TemporaryDirectory(prefix='f2b-ports-linux-') as temporary:
    temporary = Path(temporary)
    for directory in ('/etc', '/run', '/var/backups', '/usr/local'):
        private = temporary / directory.lstrip('/'); private.mkdir(parents=True)
        if directory == '/etc': shutil.copytree('/etc', private, dirs_exist_ok=True, symlinks=True)
        m.run('mount', '--bind', str(private), directory)
    Path('/run/lock').mkdir()
    m.DIRECTORY.mkdir(exist_ok=True)
    filter_text = '''table inet fail2ban-filter {
 set banned4 { type ipv4_addr; flags timeout; elements = { 192.0.2.17 timeout 1h }; }
 set banned6 { type ipv6_addr; flags timeout; elements = { 2001:db8::17 timeout 1h }; }
 chain input { type filter hook input priority -10; policy accept; ip saddr @banned4 drop; ip6 saddr @banned6 drop; }
}
'''
    def docker_text(body):
        return '''table inet docker-block {
 set docker-blocked-ports { type inet_service; flags interval; auto-merge;
''' + body + '''
 }
 set docker-banned-ipv4 { type ipv4_addr; flags timeout; elements = { 192.0.2.17 timeout 1h }; }
 set docker-banned-ipv6 { type ipv6_addr; flags timeout; elements = { 2001:db8::17 timeout 1h }; }
 chain prerouting { type filter hook prerouting priority -110; policy accept; ip saddr @docker-banned-ipv4 drop; ip6 saddr @docker-banned-ipv6 drop; tcp dport @docker-blocked-ports drop; }
}
'''
    foreign = Path('/etc/synthetic-foreign.nft')
    foreign.write_text('table ip synthetic_foreign { chain guard { counter drop; } }\n')
    m.CONFIG.write_text('include "/etc/synthetic-foreign.nft"\ninclude "/etc/nftables.d/fail2ban-filter.nft"\ninclude "/etc/nftables.d/docker-block.nft"\n')
    filter_file = m.DIRECTORY / 'fail2ban-filter.nft'
    target = m.DIRECTORY / 'docker-block.nft'
    for body in ('', 'elements = { 82 }', 'elements = {\n82, 83, 1001-1003\n}'):
        filter_file.write_text(filter_text); target.write_text(docker_text(body))
        # Only the already isolated TEST namespace is reset; never a host.
        m.run('nft', 'flush', 'ruleset')
        m.run('nft', '-f', str(m.CONFIG))
        before = m.stable(m.ruleset(), True)
        original_ports = m.ports()
        m.change_port('10000', True)
        assert m.ports() == original_ports | {10000}
        reboot = m.validate_global({})  # Actual load in a fresh, separate netns.
        assert m.ports(reboot) == m.ports()
        assert m.stable(m.ruleset(), True) == before
        m.change_port('10000', False)
        assert m.ports() == original_ports
        assert m.ports(m.validate_global({})) == original_ports
        assert foreign.read_text() == 'table ip synthetic_foreign { chain guard { counter drop; } }\n'
        files_before = {f: f.read_bytes() for f in (filter_file, target)}
        original_atomic = m.atomic; failed = [False]
        def fail_once(file, data):
            if file == target and not failed[0]:
                failed[0] = True; raise OSError('Synthetic second-file write failure')
            return original_atomic(file, data)
        with patch.object(m, 'atomic', side_effect=fail_once): refused(lambda: m.change_port('10000', True))
        assert m.ports() == original_ports
        assert all(f.read_bytes() == data for f, data in files_before.items())
        assert m.stable(m.ruleset(), True) == before
    # Known corrupted file: dry run leaves bytes/runtime untouched; apply changes
    # only the extra brace, and loads no rules into this test's live namespace.
    valid = target.read_text()
    corrupt = valid.replace('\n\tset docker-banned-ipv4', '\n}\n\tset docker-banned-ipv4', 1)
    assert corrupt != valid
    target.write_text(corrupt)
    before = m.stable(m.ruleset())
    m.repair_file(False); assert target.read_text() == corrupt
    m.repair_file(True)
    assert m.stable(m.ruleset()) == before
    assert m.ports(m.validate_global({})) == m.ports()
    # Simulate failed boot: runtime managed table absent. File repair must still
    # be possible, without starting services or loading that table into runtime.
    target.write_text(corrupt)
    m.run('nft', 'delete', 'table', 'inet', 'docker-block')
    offline = m.stable(m.ruleset())
    m.repair_file(False); m.repair_file(True)
    assert m.stable(m.ruleset()) == offline
    # Install to historical wrappers, keeping every other byte unchanged.
    hot_spec = importlib.util.spec_from_file_location('hotfix', ROOT / 'scripts/install-port-hotfix.py')
    hot = importlib.util.module_from_spec(hot_spec); hot_spec.loader.exec_module(hot)
    hot.WRAPPER.parent.mkdir(parents=True, exist_ok=True)
    hot.HELPER.parent.mkdir(parents=True, exist_ok=True)
    for old_wrapper in ((ROOT.parent / 'v0.33/scripts/f2b-wrapper-v033.sh').read_text(),
                        hot.legacy('releases/v0.34/scripts/f2b-wrapper-v034.sh')):
        old_wrapper += '\n# synthetic-local-wrapper-note\n'
        hot.WRAPPER.write_text(old_wrapper); hot.WRAPPER.chmod(0o755)
        planned = hot.plan(); assert hot.WRAPPER.read_text() == old_wrapper
        hot.apply(planned)
        patched = hot.WRAPPER.read_text()
        for name in ('manage_block_port', 'manage_unblock_port'):
            old_wrapper = old_wrapper.replace(hot.function(old_wrapper, name), hot.function(patched, name), 1)
        assert old_wrapper == patched
        assert m.stable(m.ruleset()) == offline
    hot.plan()  # repeat preflight is supported without version-upgrade side effects
    print('PASS: real port block/unblock, empty/inline/multiline/ranges, fresh-netns persistence load, ban/foreign preservation, write-failure rollback, known repair and scoped v0.33 hotfix')
