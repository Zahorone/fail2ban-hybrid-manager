import importlib.util
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile


ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/upgrade-v034dev-canary-227c393.py"
spec = importlib.util.spec_from_file_location("canary_227c393", SCRIPT)
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)

standard_db = "/var/lib/fail2ban/fail2ban.sqlite3"
assert module.validate_dbfile("Current database file is:\n`- /var/lib/fail2ban/fail2ban.sqlite3\n") == standard_db
assert module.validate_dbfile(standard_db + "\n") == standard_db
assert module.validate_dbfile("None\n") is None
assert module.validate_dbfile("Current database file is:\n`- None\n") is None
for output in ("/srv/custom.sqlite3", "Current database file is:\n`- /srv/custom.sqlite3\n"):
    try:
        module.validate_dbfile(output)
    except module.UpgradeError as error:
        assert "Custom dbfile" in str(error)
    else:
        raise AssertionError("Custom database escaped backup protection")
for output in ("", "NOK: database unavailable", "Current database file is:\n", standard_db + "\nNone"):
    try:
        module.validate_dbfile(output)
    except module.UpgradeError as error:
        assert "Unrecognized" in str(error)
    else:
        raise AssertionError("Ambiguous database response was accepted")

mapping = module.install_map(ROOT)
assert set(mapping) == {
    pathlib.Path("/etc/fail2ban/filter.d/f2b-exploit-critical.conf"),
    pathlib.Path("/etc/fail2ban/filter.d/f2b-webshell-sweep.conf"),
    pathlib.Path("/etc/fail2ban/jail.d/99-webshell-sweep.local"),
    pathlib.Path("/usr/local/bin/f2b"),
    pathlib.Path("/usr/local/sbin/f2b-ipv6-sync.py"),
    pathlib.Path("/usr/local/sbin/f2b-docker-hook"),
    pathlib.Path("/usr/local/libexec/f2b-runtime-verify.py"),
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

# A newly enabled zero-ban jail uses actionstart-on-demand: rendered actions
# are valid even though neither runtime nft set exists immediately after reload.
class Result:
    def __init__(self, stdout="", returncode=0):
        self.stdout, self.stderr, self.returncode = stdout, "", returncode

commands = []
active = ""
hook_command = f"/usr/local/sbin/f2b-docker-hook ban <ip> {module.JAIL} <bantime>"
props = {
    "name": module.JAIL, "addr_set": "f2b-<name>",
    "addr_set?family=inet6": "addr6-set-<name>",
    "addr_type": "ipv4_addr", "addr_type?family=inet6": "ipv6_addr",
    "addr_family": "ip", "addr_family?family=inet6": "ip6",
    "actionban": "nft add element inet fail2ban-filter <addr_set> \\{ <ip> \\}",
    "actionstart": "nft add set inet fail2ban-filter <addr_set> { type <addr_type>; }\nnft add rule inet fail2ban-filter f2b-input <addr_family> saddr @<addr_set> drop",
}
def fake_run(*args, check=True):
    commands.append(args)
    tail = args[1:]
    if tail == ("get", module.JAIL, "actions"):
        return Result(f"The jail {module.JAIL} has the following actions:\nnftables-multiport, docker-sync-hook, sendmail-whois-lines\n")
    if tail == ("-d",):
        return Result(repr(["multi-set", module.JAIL, "action", "nftables-multiport", list(props.items())])+"\n")
    if tail[-1:] == ("actionban",):
        if args[-2] == "docker-sync-hook": return Result(hook_command+"\n")
        return Result(props["actionban"]+"\n")
    if tail[:4] == ("list", "set", "inet", "fail2ban-filter"):
        return Result(returncode=1)
    if tail == ("get", module.JAIL, "banip"):
        return Result(active)
    if tail == ("list", "chain", "inet", "fail2ban-filter", "f2b-input"):
        return Result("", returncode=1)
    raise AssertionError(args)

real_run = module.run
module.run = fake_run
rendered = module.verify_nft_lifecycle(module.JAIL)
assert module.action_names(module.JAIL) == ["nftables-multiport", "docker-sync-hook", "sendmail-whois-lines"]
module.verify_docker_hook(module.JAIL)
hook_command = ""
try:
    module.verify_docker_hook(module.JAIL)
except module.UpgradeError as error:
    assert "Unexpected Docker hook" in str(error)
else:
    raise AssertionError("Empty Docker hook was accepted")
assert rendered[4][0] == f"f2b-{module.JAIL}"
assert rendered[6][0] == f"addr6-set-{module.JAIL}"
for active in ("192.0.2.8", "2001:db8::8"):
    try:
        module.verify_nft_lifecycle(module.JAIL)
    except module.UpgradeError as error:
        assert "missing nft set" in str(error)
    else:
        raise AssertionError("Missing set for a genuinely banned address was accepted")
active = ""
base_run = module.run
def orphan_set_run(*args, check=True):
    if args[1:5] == ("list", "set", "inet", "fail2ban-filter"):
        return Result("set exists")
    return base_run(*args, check=check)
module.run = orphan_set_run
try:
    module.verify_nft_lifecycle(module.JAIL)
except module.UpgradeError as error:
    assert "not referenced by f2b-input" in str(error)
else:
    raise AssertionError("An existing set without an input-chain reference was accepted")
module.run = real_run

# Read-only verification must report missing Docker members without executing
# a helper, sync command or ban. Apply reconciliation may repair real bans.
from unittest.mock import patch
calls = []
present = False
def docker_run(*args, check=True):
    global present
    calls.append(args)
    if args[:3] == ("nft", "get", "element"):
        if not present and check: raise module.UpgradeError("missing Docker member")
        return Result(returncode=0 if present else 1)
    if args[:2] == ("/usr/local/sbin/f2b-docker-hook", "ban"):
        present = True
        return Result()
    raise AssertionError(args)

with patch.object(module, "snapshot_bans", return_value={module.JAIL: ["2001:db8::8"]}), \
     patch.object(module, "action_names", return_value=["docker-sync-hook"]), \
     patch.object(module, "scalar", return_value="31536000"), \
     patch.object(module, "run", side_effect=docker_run):
    try:
        module.verify_docker_membership()
    except module.UpgradeError:
        pass
    else:
        raise AssertionError("Missing Docker member accepted")
    assert all(call[0] == "nft" for call in calls)
    module.verify_docker_membership(reconcile=True)
    assert ("/usr/local/sbin/f2b-docker-hook", "ban", "2001:db8::8", module.JAIL, "31536000") in calls

# Exercise the exact minimal-package layout through preflight, apply and rollback
# without touching the host or invoking Fail2Ban/nftables.
with tempfile.TemporaryDirectory() as directory:
    temporary = pathlib.Path(directory)
    package = temporary / "f2b-v034-canary-227c393"
    (package / "scripts").mkdir(parents=True)
    (package / "payload").mkdir()
    shutil.copy2(SCRIPT, package / "scripts" / SCRIPT.name)
    shutil.copy2(ROOT / "filters/f2b-exploit-critical.conf", package / "payload/f2b-exploit-critical.conf")
    shutil.copy2(ROOT / "filters/f2b-webshell-sweep.conf", package / "payload/f2b-webshell-sweep.conf")
    shutil.copy2(ROOT / "config/webshell-sweep.local", package / "payload/99-webshell-sweep.local")
    shutil.copy2(ROOT / "scripts/f2b-wrapper-v034.sh", package / "payload/f2b")
    shutil.copy2(ROOT / "scripts/f2b-ipv6-sync.py", package / "payload/f2b-ipv6-sync.py")
    shutil.copy2(ROOT / "scripts/f2b-docker-hook.sh", package / "payload/f2b-docker-hook")

    fixture = temporary / "root"
    old = {
        "etc/fail2ban/filter.d/f2b-exploit-critical.conf": b"old critical\n",
        "usr/local/bin/f2b": b"old wrapper\n",
        "etc/fail2ban/jail.local": b"local settings stay\n",
        "etc/fail2ban/filter.d/site-highrisk.local": b"local override stays\n",
        "var/lib/fail2ban/fail2ban.sqlite3": b"database stays\n",
    }
    for name, content in old.items():
        path = fixture / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    state = fixture / "run/f2b-canary"
    state.mkdir(parents=True)
    (state / "bans.json").write_text(json.dumps({"sshd": ["192.0.2.8"], "recidive": ["2001:db8::8"]}))
    (state / "nft.json").write_text('{"nftables": []}\n')

    command = [sys.executable, str(package / "scripts" / SCRIPT.name), "--fixture-root", str(fixture)]
    before = {name: (fixture / name).read_bytes() for name in old}
    dry = subprocess.run(command, text=True, capture_output=True, check=True)
    assert "No changes made" in dry.stdout
    assert before == {name: (fixture / name).read_bytes() for name in old}

    applied = subprocess.run(command + ["--apply"], text=True, capture_output=True, check=True)
    backup = pathlib.Path(next(line.split(": ", 1)[1] for line in applied.stdout.splitlines() if line.startswith("Backup complete:")))
    assert (fixture / "etc/fail2ban/jail.local").read_bytes() == old["etc/fail2ban/jail.local"]
    assert (fixture / "etc/fail2ban/filter.d/site-highrisk.local").read_bytes() == old["etc/fail2ban/filter.d/site-highrisk.local"]
    assert (fixture / "var/lib/fail2ban/fail2ban.sqlite3").read_bytes() == old["var/lib/fail2ban/fail2ban.sqlite3"]
    assert (fixture / "etc/fail2ban/jail.d/99-webshell-sweep.local").is_file()

    subprocess.run(command + ["--rollback", str(backup)], text=True, capture_output=True, check=True)
    assert before == {name: (fixture / name).read_bytes() for name in old}
    assert not (fixture / "etc/fail2ban/jail.d/99-webshell-sweep.local").exists()
    assert not (fixture / "etc/fail2ban/filter.d/f2b-webshell-sweep.conf").exists()

print("PASS: 227c393 minimal canary preflight, apply and rollback")
