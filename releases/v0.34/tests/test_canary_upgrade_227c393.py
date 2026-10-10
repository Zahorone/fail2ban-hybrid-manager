import importlib.util
import pathlib
import sys


ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/upgrade-v034dev-canary-227c393.py"
spec = importlib.util.spec_from_file_location("canary_227c393", SCRIPT)
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)

mapping = module.install_map(ROOT)
assert set(mapping) == {
    pathlib.Path("/etc/fail2ban/filter.d/f2b-exploit-critical.conf"),
    pathlib.Path("/etc/fail2ban/filter.d/f2b-webshell-sweep.conf"),
    pathlib.Path("/etc/fail2ban/jail.d/99-webshell-sweep.local"),
    pathlib.Path("/usr/local/bin/f2b"),
}
assert all(source.is_file() for source in mapping.values())
assert pathlib.Path("/etc/fail2ban/jail.local") not in mapping
assert pathlib.Path("/etc/nftables.conf") not in mapping
assert not any(target.suffix == ".local" for target in mapping if target.parent.name == "filter.d")

source = SCRIPT.read_text()
assert "flush ruleset" not in source
assert '"restart", "docker"' not in source
assert '"restart", "nftables"' not in source
assert module.TARGET_CHANGESET == "227c393"
assert module.BACKUP_LABEL == "v034dev-to-227c393"

print("PASS: 227c393 canary updater has narrow, non-destructive scope")
