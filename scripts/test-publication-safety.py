"""Synthetic policy tests; intentionally no production denylist or literals."""
import hashlib
import importlib.util
import ipaddress
import json
from pathlib import Path

spec = importlib.util.spec_from_file_location("privacy", Path(__file__).with_name("check-publication-safety.py"))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

safe = ('192.0.2.7 198.51.100.8 203.0.113.9 2001:db8::7 127.0.0.1 ::1 '
        '172.18.0.1 admin@example.invalid https://github.com/example/project '
        'http://app.example.test https://example.com /home/user/file /home/runner/work')
assert not module.findings(safe, "synthetic-safe")
assert module.findings("synthetic", "releases/v" + "0.40/scripts/installer.py")[0][2] == "local-only-development-version"
public_ip = str(ipaddress.ip_address((8 << 24) + (8 << 16) + (8 << 8) + 8))
cases = [(public_ip, "non-documentation-public-IP"),
         ("site." + "net", "non-example-domain-review"),
         ("ghp_" + "x" * 30, "credential-token"),
         ("-----BEGIN " + "PRIVATE KEY-----", "private-key"),
         ("/home/" + "operator" + "/file", "private-home-path"),
         ("/var/backups/deployment-" + "20300101-120000", "deployment-backup-path"),
         (json.dumps({"/etc/fail2ban/filter.d/synthetic.conf": [hashlib.sha256(b"synthetic").hexdigest()]}),
          "literal-deployment-hash-map")]
for value, kind in cases:
    result = module.findings(value, "synthetic-only")
    assert any(row[2] == kind for row in result), kind
    rendered = "\n".join(f"{path}:{line}: {category}" for path, line, category in result)
    assert value not in rendered, "Sensitive match echoed into output"
print("PASS: generic publication rules and value-free diagnostics")
