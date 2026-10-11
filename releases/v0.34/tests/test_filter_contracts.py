"""Merged effective filter semantics, independent of marker trust or file hashes."""
import configparser
import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("filter_upgrade", ROOT / "scripts/upgrade-v033-v034.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
commands = []
for jail in ("f2b-exploit-critical", "f2b-webshell-sweep"):
    parser = configparser.ConfigParser()
    parser.read(ROOT / "filters" / (jail + ".conf"))
    for key in ("failregex", "ignoreregex"):
        commands.append(["multi-set", jail, "add" + key, [line for line in parser["Definition"][key].splitlines() if line.strip()]])
assert not module.filter_contract_conflicts(commands)
for jail, key, replacement in (
        ("f2b-exploit-critical", "addfailregex", [r'^.* "/this_is_a_new_hello_world\.php" \[Client <HOST>\]']),
        ("f2b-exploit-critical", "addignoreregex", [".*"]),
        ("f2b-webshell-sweep", "addignoreregex", []),
        ("f2b-webshell-sweep", "addignoreregex", [r".*wp-content/.*"]),
):
    altered = [[*command[:3], replacement] if command[1:3] == [jail, key] else command for command in commands]
    conflicts = module.filter_contract_conflicts(altered)
    assert conflicts and f"/etc/fail2ban/filter.d/{jail}.local" in conflicts[0], conflicts
assert module.FILTER_OVERRIDE_POLICY["mode"] == "preserve-and-validate-effective"
assert not module.FILTER_OVERRIDE_POLICY["marker_is_authentication"]
mapping = module.install_map(ROOT)
assert all(not str(path).startswith("/etc/apache2") for path in mapping)
assert all(str(path) not in module.FILTER_OVERRIDE_POLICY["paths"] for path in mapping)
print("PASS: override coexistence contract detects stale/suppressing overrides and preserves module boundaries")
