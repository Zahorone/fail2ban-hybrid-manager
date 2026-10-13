"""Static lab exposure/pinning contract; optional real Compose config, never up."""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess

parser = argparse.ArgumentParser()
parser.add_argument('--require-compose', action='store_true')
args = parser.parse_args()
root = Path(__file__).resolve().parents[1]
folder = root / 'examples/docker-npm-lab'
base = json.loads((folder / 'compose.json').read_text())
extra = json.loads((folder / 'compose.ipv6.json').read_text())
assert set(base['services']) == {'npm', 'backend'}
for service in base['services'].values():
    assert re.fullmatch(r'[a-z0-9/.-]+:[0-9][a-z0-9.-]*@sha256:[0-9a-f]{64}', service['image'])
    assert service['platform'] == 'linux/arm64'
    assert not service.get('privileged') and 'network_mode' not in service
    assert 'environment' not in service and 'build' not in service
assert 'ports' not in base['services']['backend']
ports = base['services']['npm']['ports']
assert len(ports) == 2
assert ports[0] == {'target': 81, 'published': '81', 'host_ip': '127.0.0.1', 'protocol': 'tcp'}
assert ports[1]['target'] == 80 and ports[1]['published'] == '8088'
assert ports[1]['host_ip'].startswith('${F2B_LAB_BIND4:?')
assert all('/var/run/docker.sock' not in v for v in base['services']['npm']['volumes'])
assert all(v.startswith('/opt/f2b-npm-lab/') for v in base['services']['npm']['volumes'])
assert extra['networks']['default']['enable_ipv6'] is True
assert len(extra['services']['npm']['ports']) == 1
assert extra['services']['npm']['ports'][0]['host_ip'].startswith('${F2B_LAB_BIND6:?')
document = (root / 'docs/DOCKER-NPM-LAB.md').read_text()
assert 'Do not rerun fresh install' in document
assert 'fallback_http_access.log' in document
assert 'separate client' in document and 'not tested' in document
for block in re.findall(r'```sh\n(.*?)```', document, re.S):
    subprocess.run(['bash', '-n'], input=block, text=True, check=True)

if shutil.which('docker') is None:
    if args.require_compose: raise SystemExit('Docker Compose CLI required for CI config validation')
    print('PASS: static lab contracts; Compose unavailable locally (not a runtime test)')
else:
    environment = {k: v for k, v in os.environ.items() if not k.startswith('F2B_LAB_BIND')}
    command = ['docker', 'compose', '-f', str(folder / 'compose.json')]
    absent = subprocess.run([*command, 'config'], env=environment, capture_output=True)
    assert absent.returncode != 0, 'Missing explicit bind must not become a wildcard'
    environment.update(F2B_LAB_BIND4='192.0.2.10', F2B_LAB_BIND6='2001:db8::10')
    for files in ([], ['-f', str(folder / 'compose.ipv6.json')]):
        result = subprocess.run([*command, *files, 'config', '--format', 'json'],
                                env=environment, capture_output=True, text=True, check=True)
        rendered = json.loads(result.stdout)
        bindings = rendered['services']['npm']['ports']
        assert len(bindings) == (3 if files else 2)
        assert {(p['host_ip'], int(p['target'])) for p in bindings} == (
            {('127.0.0.1', 81), ('192.0.2.10', 80)} |
            ({('2001:db8::10', 80)} if files else set()))
        assert not rendered['services']['backend'].get('ports')
    print('PASS: Compose parses pinned ARM64 lab, exact private binds and IPv6 merge; no containers started')
