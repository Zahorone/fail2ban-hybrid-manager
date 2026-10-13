"""NPM standard/proxy format, exact source capture and HTTP-only coverage."""
import configparser
import importlib.util
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('verifier', ROOT / 'scripts/upgrade-v034dev-canary-227c393.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
for jail in ('f2b-exploit-critical', 'f2b-webshell-sweep'):
    parser = configparser.ConfigParser(); parser.read(ROOT / 'filters' / (jail + '.conf'))
    def expressions(key):
        return [re.compile(v.replace('<HOST>', r'(?P<ip>[0-9.]+|[0-9A-Fa-f:]+)'))
                for v in parser['Definition'][key].splitlines() if v.strip()]
    fail, ignore = expressions('failregex'), expressions('ignoreregex')
    for label, expected in (('attacks', 4), ('benign', 0)):
        fixture = ROOT / 'tests/fixtures' / ('npm216-' + jail + '-' + label + '.log')
        hits = []
        for line in fixture.read_text().splitlines():
            matches = [p.search(line) for p in fail if p.search(line)]
            if not any(p.search(line) for p in ignore):
                hits.extend(matches[:1])
                for match in matches:
                    assert match['ip'] in {'192.0.2.17', '2001:db8::17'}
                    assert '[Client ' + match['ip'] + ']' in line
        assert len(hits) == expected
        if '--require-fail2ban' in sys.argv: assert shutil.which('fail2ban-regex')
        if shutil.which('fail2ban-regex'):
            result = subprocess.run(['fail2ban-regex', str(fixture), str(ROOT / 'filters' / (jail + '.conf'))],
                                    capture_output=True, text=True, check=True)
            match = re.search(r'Lines:\s+\d+ lines,\s+\d+ ignored,\s+(\d+) matched', result.stdout)
            assert match and int(match[1]) == expected, result.stdout
with tempfile.TemporaryDirectory(prefix='f2b-npm216-') as temporary:
    folder = Path(temporary)
    for name in ('fallback_http_access.log', 'fallback_http_error.log', 'fallback_error.log',
                 'proxy-host-1_access.log', 'dead-host-2_access.log', 'redirection-host-3_error.log',
                 'fallback_stream_access.log', 'backend.log', 'custom_error.log'):
        (folder / name).touch()
    logs = m.npm_logs(folder)
    assert len(logs['access']) == 3 and len(logs['error']) == 3
    assert not any('stream' in f or 'backend' in f or 'custom' in f for group in logs.values() for f in group)
    sync = SimpleNamespace(call=lambda c: logs['error'])
    try: m.verify_npm_coverage(['f2b-exploit-critical'], sync)
    except m.UpgradeError: pass
    else: raise AssertionError('Error-only critical jail must not pass coverage')
    sync.call = lambda c: logs['access'] + logs['error']
    m.verify_npm_coverage(['f2b-exploit-critical'], sync)
    sync.call = lambda c: [str(folder / 'fallback_stream_access.log')]
    try: m.verify_npm_coverage(['f2b-webshell-sweep'], sync)
    except m.UpgradeError: pass
    else: raise AssertionError('Stream is not an HTTP access source')
print('PASS: NPM 2.16 standard/proxy IPv4/IPv6, source capture, benign exclusions and access/error coverage')
