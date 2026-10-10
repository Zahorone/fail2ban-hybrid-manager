import importlib.util
import pathlib
import sys
import tempfile


ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/upgrade-v033-v034.py"
spec = importlib.util.spec_from_file_location("upgrade_v034", SCRIPT)
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)


status = """Status
|- Number of jail:\t3
`- Jail list:\tsshd, recidive, nginx-php-errors
"""
assert module.parse_jails(status) == ["sshd", "recidive", "nginx-php-errors"]
assert module.valid_ip("192.0.2.1")
assert module.valid_ip("2001:db8::1")
assert not module.valid_ip("not-an-address")

base = {
    "nftables": [
        {"metainfo": {"json_schema_version": 1}},
        {"table": {"family": "inet", "name": "fail2ban-filter"}},
        {"rule": {"family": "inet", "table": "fail2ban-filter", "handle": 1}},
        {"table": {"family": "inet", "name": "filter"}},
        {"rule": {"family": "inet", "table": "filter", "handle": 8,
                  "counter": {"packets": 10, "bytes": 500}, "verdict": "accept"}},
    ]
}
counters_changed = {
    "nftables": [
        {"metainfo": {"json_schema_version": 2}},
        {"table": {"family": "inet", "name": "fail2ban-filter"}},
        {"rule": {"family": "inet", "table": "fail2ban-filter", "handle": 99}},
        {"table": {"family": "inet", "name": "filter"}},
        {"rule": {"family": "inet", "table": "filter", "handle": 9,
                  "counter": {"packets": 11, "bytes": 600}, "verdict": "accept"}},
    ]
}
assert module.external_nft_digest(base) == module.external_nft_digest(counters_changed)
counters_changed["nftables"][-1]["rule"]["verdict"] = "drop"
assert module.external_nft_digest(base) != module.external_nft_digest(counters_changed)

mapping = module.install_map(ROOT)
assert pathlib.Path("/etc/fail2ban/jail.local") not in mapping
assert pathlib.Path("/etc/fail2ban/action.d/nftables-common.local") not in mapping
assert pathlib.Path("/etc/nftables.conf") not in mapping
assert pathlib.Path("/usr/local/bin/f2b") in mapping
assert pathlib.Path("/etc/fail2ban/jail.d/99-webshell-sweep.local") in mapping
assert pathlib.Path("/etc/fail2ban/filter.d/f2b-webshell-sweep.conf") in mapping

with tempfile.TemporaryDirectory() as directory:
    directory = pathlib.Path(directory)
    source = directory / "source"
    target = directory / "target"
    source.write_text("new version\n")
    target.write_text("old version\n")
    module.atomic_install(source, target)
    assert target.read_text() == "new version\n"
    assert target.stat().st_mode & 0o777 == 0o644

with tempfile.TemporaryDirectory() as directory:
    backup = pathlib.Path(directory)
    payload = backup / "manifest.json"
    payload.write_text('{"paths": []}\n')
    import hashlib
    digest = hashlib.sha256(payload.read_bytes()).hexdigest()
    (backup / "SHA256SUMS").write_text(f"{digest}  manifest.json\n")
    module.verify_backup(backup)
    payload.write_text("corrupt\n")
    try:
        module.verify_backup(backup)
    except module.UpgradeError:
        pass
    else:
        raise AssertionError("Corrupt backup passed checksum verification")

print("PASS: upgrade parsing, scope and external-firewall integrity checks")
