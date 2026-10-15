#!/usr/bin/env python3
"""Transactional v0.33 -> v0.34 upgrade without a global firewall reload."""

from __future__ import annotations

import argparse
import ast
from contextlib import closing
import datetime as dt
import fcntl
import hashlib
import importlib.util
import ipaddress
import itertools
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
from typing import Iterable

sys.dont_write_bytecode = True


RELEASE = "0.34-dev"
FILTER_OVERRIDE_POLICY = {
    "mode": "preserve-and-validate-effective",
    "marker": "scan-review-20261011",
    "paths": ["/etc/fail2ban/filter.d/f2b-exploit-critical.local",
              "/etc/fail2ban/filter.d/f2b-webshell-sweep.local"],
    "contract": "scan-review-20261011-v1",
    "access_contract": "npm-access-v1",
    "marker_is_authentication": False,
    "apache": "outside-manager-transaction",
}
OWNED_NFT_TABLES = {"fail2ban-filter", "docker-block"}
SYSTEM_BACKUP_PATHS = (
    Path("etc/fail2ban"),
    Path("etc/nftables.conf"),
    Path("etc/nftables.d"),
    Path("etc/systemd/system/nftables.service.d"),
    Path("etc/systemd/system/docker.service.d"),
    Path("etc/systemd/system/fail2ban.service.d"),
    Path("etc/systemd/system/cron.service.d"),
    Path("usr/local/bin/f2b"),
    Path("usr/local/bin/nft-save-tables.sh"),
    Path("usr/local/sbin/f2b-docker-hook"),
    Path("usr/local/sbin/f2b-ipv6-sync.py"),
    Path("usr/local/libexec/f2b-report-filter.py"),
    Path("usr/local/libexec/f2b-runtime-verify.py"),
    Path("etc/f2b"),
    Path("var/lib/fail2ban"),
    Path("etc/cron.d/f2b-v034-sync"),
    Path("usr/local/sbin/f2b-save-owned-tables.py"),
)


class UpgradeError(RuntimeError):
    pass


def run(*args: str, check: bool = True, input_text: str | None = None, timeout: float | None = None) -> subprocess.CompletedProcess:
    result = subprocess.run(args, input=input_text, text=True, capture_output=True, timeout=timeout)
    if check and result.returncode:
        raise UpgradeError(
            f"command failed ({result.returncode}): {' '.join(args)}\n"
            f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )
    return result


def require_root() -> None:
    if os.geteuid() != 0:
        raise UpgradeError("Run with sudo; no changes made.")


def acquire_upgrade_lock():
    lock = open("/run/lock/f2b-upgrade.lock", "a")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        lock.close()
        raise UpgradeError("Another upgrade/rollback or scheduled sync is running")
    return lock


def require_commands(commands: Iterable[str]) -> None:
    missing = [command for command in commands if shutil.which(command) is None]
    if missing:
        raise UpgradeError("Missing required commands: " + ", ".join(missing))


def package_root() -> Path:
    return Path(__file__).resolve().parents[1]


def install_map(root: Path) -> dict[Path, Path]:
    mapping: dict[Path, Path] = {}
    for source in sorted((root / "filters").glob("*.conf")):
        mapping[Path("/etc/fail2ban/filter.d") / source.name] = source
    # Never deploy *.local action files: those are site configuration. The
    # production preflight verifies their effective result instead.
    for name in ("nftables-recidive.conf", "nftables-multiport.conf", "docker-sync-hook.conf"):
        mapping[Path("/etc/fail2ban/action.d") / name] = root / "actions" / name
    mapping.update(
        {
            Path("/etc/fail2ban/jail.d/99-php-errors-mail.local"): root / "config/php-errors-mail.local",
            Path("/etc/fail2ban/jail.d/99-recidive-mail.local"): root / "config/recidive-mail.local",
            Path("/etc/fail2ban/jail.d/99-exploit-critical-rce.local"): root / "config/exploit-critical-rce.local",
            Path("/etc/fail2ban/jail.d/99-webshell-sweep.local"): root / "config/webshell-sweep.local",
            Path("/usr/local/bin/f2b"): root / "scripts/f2b-wrapper-v034.sh",
            Path("/usr/local/sbin/f2b-docker-hook"): root / "scripts/f2b-docker-hook.sh",
            Path("/usr/local/sbin/f2b-ipv6-sync.py"): root / "scripts/f2b-ipv6-sync.py",
            Path("/usr/local/libexec/f2b-report-filter.py"): root / "scripts/f2b-report-filter.py",
            Path("/usr/local/libexec/f2b-runtime-verify.py"): root / "scripts/upgrade-v034dev-canary-227c393.py",
            Path("/usr/local/sbin/f2b-save-owned-tables.py"): root / "scripts/f2b-save-owned-tables.py",
            Path("/etc/cron.d/f2b-v034-sync"): root / "config/upgrade-sync.cron",
            Path("/etc/f2b/reporting.ini.example"): root / "config/reporting.ini.example",
            Path("/etc/systemd/system/nftables.service.d/90-f2b-preserve-runtime.conf"):
                root / "config/nftables-preserve-runtime.conf",
        }
    )
    return mapping


def file_mode(target: Path) -> int:
    return 0o755 if str(target).startswith(("/usr/local/bin/", "/usr/local/sbin/", "/usr/local/libexec/")) else 0o644


def validate_package(root: Path, mapping: dict[Path, Path]) -> None:
    verify_package_manifest(root)
    version = (root / "VERSION").read_text().strip()
    if version != RELEASE:
        raise UpgradeError(f"Package VERSION is {version!r}, expected {RELEASE!r}")
    missing = [str(source) for source in mapping.values() if not source.is_file()]
    if missing:
        raise UpgradeError("Missing package files:\n" + "\n".join(missing))
    for script in (root / "scripts").glob("*.sh"):
        run("bash", "-n", str(script))
    for script in (root / "scripts").glob("*.py"):
        try:
            compile(script.read_text(), str(script), "exec")
        except SyntaxError as error:
            raise UpgradeError(f"Python syntax error in {script}: {error}") from error
    for path in root.rglob("*"):
        if path.is_file() and path.suffix in {".sh", ".nft", ".conf", ".local"}:
            if re.search(r"^\s*flush\s+ruleset(?:\s|$)", path.read_text(errors="replace"), re.MULTILINE):
                raise UpgradeError(f"Unsafe global flush found in package: {path}")


def verify_package_manifest(root: Path) -> dict:
    manifest_path = root / "UPGRADE-MANIFEST.json"
    if not manifest_path.is_file():
        raise UpgradeError("Use the complete built upgrade package: UPGRADE-MANIFEST.json is missing")
    manifest = json.loads(manifest_path.read_text())
    if manifest.get("schema") != 1 or manifest.get("release") != RELEASE:
        raise UpgradeError("Unsupported package manifest")
    if manifest.get("filter_override_policy") != FILTER_OVERRIDE_POLICY:
        raise UpgradeError("Package filter override policy mismatch")
    expected = manifest["files"]
    if any(p.is_symlink() for p in root.rglob('*')):
        raise UpgradeError('Package symlinks are forbidden')
    actual = {str(p.relative_to(root)) for p in root.rglob("*") if p.is_file()}
    if actual != set(expected) | {"UPGRADE-MANIFEST.json", "SHA256SUMS"}:
        raise UpgradeError("Package file inventory does not match manifest")
    for name, digest in expected.items():
        relative = Path(name)
        if relative.is_absolute() or ".." in relative.parts:
            raise UpgradeError("Unsafe package path")
        path = root / relative
        if path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise UpgradeError("Package checksum mismatch: " + name)
    summed = []
    for line in (root / "SHA256SUMS").read_text().splitlines():
        digest, name = line.split("  ", 1)
        if name not in actual or hashlib.sha256((root / name).read_bytes()).hexdigest() != digest:
            raise UpgradeError("Package SHA256SUMS mismatch: " + name)
        summed.append(name)
    if len(summed) != len(set(summed)) or set(summed) != actual - {'SHA256SUMS'}:
        raise UpgradeError('Package SHA256SUMS inventory mismatch')
    return manifest


def read_local_review(path: Path, root: Path, mapping: dict[Path, Path], manifest: dict) -> dict:
    """Explicit private per-deployment approval; never embedded in a package."""
    path = path.absolute()
    if path.is_symlink() or path.parent.resolve() != path.parent:
        raise UpgradeError("Local review must be a regular file without symlink parents")
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o077:
        raise UpgradeError("Local review must be root-owned and readable/writable only by root")
    if root.resolve() in path.resolve().parents:
        raise UpgradeError("Local review must be outside the generic package")
    value = json.loads(path.read_text())
    if (not isinstance(value, dict) or value.get("schema") != 1 or value.get("reviewed") is not True
            or value.get("package_commit") != manifest.get("source_commit")):
        raise UpgradeError("Local review must explicitly approve this exact package commit")
    targets = value.get("targets")
    if not isinstance(targets, dict) or not targets:
        raise UpgradeError("Local review must specify non-empty exact target SHA256 values")
    for target, digest in targets.items():
        if Path(target) not in mapping or not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise UpgradeError("Invalid local review target or SHA256: " + target)
        current = hashlib.sha256(Path(target).read_bytes()).hexdigest() if Path(target).is_file() else None
        installed = hashlib.sha256(mapping[Path(target)].read_bytes()).hexdigest()
        if current not in {digest, installed}:
            raise UpgradeError("Local reviewed contents changed or disappeared: " + target)
    return targets


def audit_targets(root: Path, mapping: dict[Path, Path], review_file: Path | None = None) -> None:
    manifest = verify_package_manifest(root)
    known = manifest["known_targets"]
    approved = read_local_review(review_file, root, mapping, manifest) if review_file else {}
    conflicts = []
    for target, source in mapping.items():
        if target.is_symlink() or target.parent.resolve() != target.parent:
            conflicts.append(str(target) + ": symlink target/parent requires manual review")
        elif target.exists() and target.read_bytes() != source.read_bytes():
            digest = hashlib.sha256(target.read_bytes()).hexdigest()
            if digest not in known.get(str(target), []) and approved.get(str(target)) != digest:
                conflicts.append(str(target) + ": unknown local contents SHA256=" + digest)
    if conflicts:
        raise UpgradeError("Local target conflicts (nothing overwritten):\n" + "\n".join(conflicts))
    print("PASS: managed target conflicts checked; other jail.local/*.local/whitelists remain unchanged")


def sanitized_nft_config(text: str) -> str:
    # Remove only the dangerous command created by the old installer. Never
    # execute this file during upgrade, and preserve all other site statements.
    return re.sub(r"^[ \t]*flush[ \t]+ruleset[ \t]*;?[ \t]*(?:#.*)?$",
                  "# v0.34 upgrade: global ruleset flush removed", text, flags=re.MULTILINE)


def prepare_persistence(mapping: dict[Path, Path], directory: Path) -> None:
    path = Path("/etc/nftables.conf")
    if not path.is_file(): raise UpgradeError("Missing /etc/nftables.conf")
    text = sanitized_nft_config(path.read_text())
    if re.search(r"\bflush\s+ruleset\b", re.sub(r"#.*", "", text)):
        raise UpgradeError("Unrecognized global flush in /etc/nftables.conf; manual review required")
    for table in sorted(OWNED_NFT_TABLES):
        target = Path("/etc/nftables.d") / (table + ".nft")
        if str(target) not in text and '/etc/nftables.d/*.nft' not in text:
            raise UpgradeError("Missing persistence include for " + str(target))
        # Save only our own live table; no foreign table or Docker NAT content.
        destination = directory / target.name
        destination.write_text(run("nft", "-s", "list", "table", "inet", table).stdout)
        mapping[target] = destination
    candidate = directory / "nftables.conf"
    candidate.write_text(text)
    mapping[path] = candidate


def parse_jails(status: str) -> list[str]:
    for line in status.splitlines():
        if "Jail list:" in line:
            return [item.strip() for item in line.split("Jail list:", 1)[1].split(",") if item.strip()]
    return []


def valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def snapshot_bans() -> dict[str, list[str]]:
    status = run("fail2ban-client", "status").stdout
    jails = parse_jails(status)
    if not jails:
        raise UpgradeError("Fail2Ban returned no enabled jails")
    snapshot: dict[str, list[str]] = {}
    for jail in jails:
        output = run("fail2ban-client", "get", jail, "banip").stdout
        snapshot[jail] = sorted({value for value in output.split() if valid_ip(value)})
    return snapshot


def snapshot_ban_times(timeout=None) -> dict:
    # Use typed socket responses via the distribution Python, not CLI cosmetics.
    output = run("/usr/bin/python3", str(package_root() / "scripts/f2b-ipv6-sync.py"), "export", timeout=timeout).stdout
    value = json.loads(output)
    if not isinstance(value, dict): raise UpgradeError("Invalid timed ban snapshot")
    return value


def restore_missing_bans(snapshot: dict[str, list[str]]) -> None:
    live_jails = set(parse_jails(run("fail2ban-client", "status").stdout))
    missing_jails = set(snapshot).difference(live_jails)
    if missing_jails:
        raise UpgradeError("Jails disappeared after reload: " + ", ".join(sorted(missing_jails)))
    for jail, previous in snapshot.items():
        current = {
            value
            for value in run("fail2ban-client", "get", jail, "banip").stdout.split()
            if valid_ip(value)
        }
        for address in sorted(set(previous).difference(current)):
            run("fail2ban-client", "set", jail, "banip", address)


def assert_bans_preserved(snapshot: dict[str, list[str]]) -> None:
    for jail, previous in snapshot.items():
        current = {
            value
            for value in run("fail2ban-client", "get", jail, "banip").stdout.split()
            if valid_ip(value)
        }
        missing = set(previous).difference(current)
        if missing:
            raise UpgradeError(f"{jail}: missing bans after restore: {', '.join(sorted(missing))}")


def nft_ruleset() -> dict:
    try:
        return json.loads(run("nft", "-j", "list", "ruleset").stdout)
    except json.JSONDecodeError as error:
        raise UpgradeError(f"Cannot parse nftables JSON: {error}") from error


def external_nft_digest(document: dict) -> str:
    def stable(value):
        if isinstance(value, dict):
            return {
                key: stable(item)
                for key, item in value.items()
                if key not in {"handle", "packets", "bytes", "expires"}
            }
        if isinstance(value, list):
            return [stable(item) for item in value]
        return value

    kept = []
    for item in document.get("nftables", []):
        payload = next((value for key, value in item.items() if key != "metainfo"), None)
        owner = (payload.get("name") if "table" in item else payload.get("table")) if isinstance(payload, dict) else None
        if isinstance(payload, dict) and payload.get("family") == "inet" and owner in OWNED_NFT_TABLES:
            continue
        if "metainfo" not in item:
            kept.append(stable(item))
    encoded = json.dumps(kept, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def project_nft_elements(document: dict) -> dict[str, list[str]]:
    elements: dict[str, list[str]] = {}
    for item in document.get("nftables", []):
        payload = item.get("set")
        if not isinstance(payload, dict) or payload.get("table") not in OWNED_NFT_TABLES:
            continue
        name = payload.get("name")
        if name:
            elements[f"{payload.get('family', 'inet')}:{payload['table']}:{name}"] = payload.get("elem", [])
    return elements


def validate_live_firewall() -> None:
    required = (
        ("fail2ban-filter", "f2b-recidive"),
        ("fail2ban-filter", "f2b-recidive-v6"),
        ("docker-block", "docker-banned-ipv4"),
        ("docker-block", "docker-banned-ipv6"),
    )
    for table, name in required:
        run("nft", "list", "set", "inet", table, name)
    for chain in ("f2b-input", "f2b-forward"):
        rules = run("nft", "list", "chain", "inet", "fail2ban-filter", chain).stdout
        for expression in ("ip saddr @f2b-recidive", "ip6 saddr @f2b-recidive-v6"):
            if expression not in rules:
                raise UpgradeError(f"Missing {expression!r} in {chain}")
    docker = run("nft", "list", "chain", "inet", "docker-block", "prerouting").stdout
    for expression in ("hook prerouting", "ip saddr @docker-banned-ipv4 drop", "ip6 saddr @docker-banned-ipv6 drop"):
        if expression not in docker: raise UpgradeError("Missing Docker enforcement: " + expression)


def validate_candidate(root: Path, mapping: dict[Path, Path]) -> None:
    with tempfile.TemporaryDirectory(prefix="f2b-v034-candidate-") as temporary:
        candidate = Path(temporary) / "fail2ban"
        shutil.copytree("/etc/fail2ban", candidate, symlinks=True)
        for target, source in mapping.items():
            prefix = Path("/etc/fail2ban")
            try:
                relative = target.relative_to(prefix)
            except ValueError:
                continue
            destination = candidate / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, destination)
        run("fail2ban-client", "-c", str(candidate), "-t")
        dump = run("fail2ban-client", "-c", str(candidate), "-d").stdout
        validate_effective_dump(dump)


def validate_effective_dump(dump: str) -> None:
    commands = []
    for line in dump.splitlines():
        if line.startswith("["):
            try: commands.append(ast.literal_eval(line))
            except (ValueError, SyntaxError): raise UpgradeError("Unrecognized Fail2Ban config dump")
    settings = {(c[1], c[2]): c[3] for c in commands if len(c) == 4 and c[0] == "set"}
    jails = {c[1] for c in commands if c[0] == "add"}
    conflicts = []
    for jail, key, value in (("f2b-webshell-sweep", "findtime", 30),
                             ("f2b-webshell-sweep", "maxretry", 3),
                             ("f2b-webshell-sweep", "bantime", 31536000),
                             ("f2b-exploit-critical", "maxretry", 1),
                             ("f2b-exploit-critical", "bantime", 31536000)):
        if str(settings.get((jail, key))) != str(value):
            conflicts.append(f"[{jail}] {key}: effective {settings.get((jail,key))!r}, required {value}")
    critical = [c[3] for c in commands if len(c) == 4 and c[0] in {"set", "multi-set"} and c[1:3] == ["f2b-exploit-critical", "addfailregex"]]
    if "this_is_a_new_hello_world" not in repr(critical): conflicts.append("[f2b-exploit-critical] failregex: new IOC missing")
    actions = {(c[1], c[3]): dict(c[4]) for c in commands if len(c) == 5 and c[0] == "multi-set" and c[2] == "action"}
    verifier = load_verifier()
    verifier.action_names = lambda jail: [name for owner, name in actions if owner == jail]
    def candidate_run(*args, **kwargs):
        if args == ("fail2ban-client", "-d"): return subprocess.CompletedProcess(args, 0, dump, "")
        if len(args) == 6 and args[:2] == ("fail2ban-client", "get") and args[3] == "action":
            return subprocess.CompletedProcess(args, 0, actions[(args[2], args[4])][args[5]], "")
        raise UpgradeError("Unexpected candidate verification command")
    verifier.run = candidate_run
    for jail in sorted(jails):
        if jail == "recidive":
            props = actions.get((jail, "nftables-recidive"), {})
            if props.get("recidive_set") != "f2b-recidive" or props.get("recidive_set?family=inet6") != "f2b-recidive-v6":
                conflicts.append("[recidive] action: both managed family sets are required")
            continue
        try:
            if set(verifier.effective_nft_actions(jail)) != {4, 6}:
                conflicts.append(f"[{jail}] action: missing IPv4/IPv6 nft action")
        except Exception as error: conflicts.append(f"[{jail}] action: {error}")
    if "recidive" not in jails: conflicts.append("[recidive] enabled: rollback fallback is required")
    for jail in ("nginx-php-errors", "f2b-webshell-sweep", "f2b-exploit-critical"):
        hook = actions.get((jail, "docker-sync-hook"), {})
        if hook.get("actionban") != f"/usr/local/sbin/f2b-docker-hook ban <ip> {jail} <bantime>":
            conflicts.append(f"[{jail}] docker-sync-hook: missing or customized ban command")
    php_mail = actions.get(("nginx-php-errors", "sendmail-whois-lines"), {})
    if "-a" not in php_mail.get("grepopts", "").split(): conflicts.append("[nginx-php-errors] mail: binary-safe grep option missing")
    # Check the merged fail/ignore expressions, not just IOC presence. A local
    # ignoreregex can otherwise silently neutralize every new protection.
    host = r"(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9A-Fa-f:]+)"
    for jail, attack_path in (("f2b-exploit-critical", "/this_is_a_new_hello_world.php"),
                              ("f2b-webshell-sweep", "/shell.php")):
        expressions = {"addfailregex": [], "addignoreregex": []}
        for command in commands:
            if len(command) == 4 and command[0] in {"set", "multi-set"} and command[1] == jail and command[2] in expressions:
                value = command[3]
                expressions[command[2]].extend(value if isinstance(value, list) else [value])
        try:
            compiled = {key: [re.compile(value.replace("<HOST>", host)) for value in values] for key, values in expressions.items()}
            def matches(line):
                return any(p.search(line) for p in compiled["addfailregex"]) and not any(p.search(line) for p in compiled["addignoreregex"])
            for address in ("192.0.2.7", "2001:db8::7"):
                attack = f'[10/Oct/2026:12:00:00 +0200] - 404 404 - GET https example.invalid "{attack_path}" [Client {address}]'
                if not matches(attack): conflicts.append(f"[{jail}] effective filter/ignoreregex suppresses synthetic IOC for {address}")
            benign = '[10/Oct/2026:12:00:00 +0200] - 200 200 - GET https example.invalid "/wp-content/plugins/wp-file-manager/file_folder_manager.php" [Client 192.0.2.7]'
            if matches(benign): conflicts.append(f"[{jail}] effective filter matches benign WordPress request")
        except (re.error, TypeError) as error:
            conflicts.append(f"[{jail}] cannot verify effective expressions: {error}")
    conflicts.extend(filter_contract_conflicts(commands))
    conflicts.extend(access_filter_contract_conflicts(commands))
    if conflicts: raise UpgradeError("Effective configuration conflicts; inspect jail.local, jail.d/*.local and filter/action *.local:\n" + "\n".join(conflicts))


def filter_contract_cases():
    """Managed semantic interface, independent of site override file hashes."""
    credentials = [f"/.aws/{name}{suffix}" for name, suffix in itertools.product(
        ("credentials", "config"), ("", ".bak", ".old", ".save", ".orig", "~"))]
    credentials += ["/.boto", "/.s3cfg", "/.codeium/auth.json", "/.tabnine/credentials", "/rclone.conf"]
    credentials += [f"/{prefix}{name}.json" for prefix, name in itertools.product(
        ("", "config/", "keys/"), ("gcp-credentials", "google-credentials", "firebase-credentials",
                                    "google-service-account", "service-account", "firebase-admin"))]
    traversal = [f"/userfiles{endpoint}?{param}={dot}{sep}{dot}{sep}{target}"
                 for endpoint, param, dot, sep, target in itertools.product(
                     ("", "/x"), ("path", "file", "filename", "download"),
                     ("..", "%2e%2e", ".%2e", "%2e."), ("/", "%2f"),
                     (".env", ".env.local", "proc/self/environ", "proc%2fself%2fcmdline"))]
    core = [f"/{prefix}{name}{query}" for prefix, name, query in itertools.product(
        ("", "blog/", "tenant/a/"), ("index.php", "wp-login.php", "wp-admin/admin-ajax.php", "wp-cron.php"), ("", "?x=1"))]
    benign = ["/search?q=../../.env", "/userfiles?path=../../images/a.jpg", "/userfiles?path=.env",
              "/firebase.json", "/google-services.json", "/push_config.json", "/graphql",
              "/.claude/settings.json", "/docs/service-account.json", "/config.php", "/solr/admin/cores"]
    for target in credentials + traversal:
        yield "f2b-exploit-critical", target, 404, True
    for target, status in itertools.product(
            ("/wp-content/plugins/hellopress/wp_filemanager.php", "/this_is_a_new_hello_world.php"), (301, 404, 444)):
        yield "f2b-exploit-critical", target, status, True
    for target in core + benign:
        yield "f2b-exploit-critical", target, 404, False
    for target in core:
        yield "f2b-webshell-sweep", target, 404, False
    for target, status in itertools.product(
            ("/blog/not-wp-login.php", "/wp-content/plugins/evil/payload.phtml", "/tenant/a/payload.php"), (200, 301, 404, 444)):
        yield "f2b-webshell-sweep", target, status, status == 404


def filter_contract_conflicts(commands):
    compiled = {}
    conflicts = []
    for jail in ("f2b-exploit-critical", "f2b-webshell-sweep"):
        expressions = {"addfailregex": [], "addignoreregex": []}
        try:
            for command in commands:
                if len(command) == 4 and command[0] in {"set", "multi-set"} and command[1] == jail and command[2] in expressions:
                    values = command[3] if isinstance(command[3], list) else [command[3]]
                    expressions[command[2]].extend(re.compile(value.replace("<HOST>", r"(?:[0-9.]+|[0-9A-Fa-f:]+)")) for value in values)
            compiled[jail] = expressions
        except (re.error, TypeError) as error:
            conflicts.append(f"[{jail}] cannot compile effective filter: {error}")
    for jail, target, status, expected in filter_contract_cases():
        if jail not in compiled: continue
        expressions = compiled[jail]
        for host, method in itertools.product(("192.0.2.7", "2001:db8::7"), ("GET", "HEAD")):
            line = f'[11/Oct/2026:12:00:00 +0000] - {status} {status} - {method} https example.invalid "{target}" [Client {host}]'
            actual = (any(p.search(line) for p in expressions["addfailregex"]) and
                      not any(p.search(line) for p in expressions["addignoreregex"]))
            if actual != expected:
                reason = "suppresses required probe" if expected else "matches excluded request"
                conflicts.append(f"[{jail}] {reason}: {method} {target} status={status} client={host}; "
                                 f"inspect /etc/fail2ban/filter.d/{jail}.local and jail/filter overrides")
                if len(conflicts) >= 10: return conflicts + ["Further contract conflicts omitted; no overrides changed"]
    return conflicts


def validate_live_filter_contracts():
    output = run("/usr/bin/python3", str(package_root() / "scripts/f2b-ipv6-sync.py"), "filter-contract").stdout
    commands = json.loads(output)
    if not isinstance(commands, list) or len(commands) not in {4, 6, 8, 10, 12}:
        raise UpgradeError("Invalid live filter contract response")
    conflicts = filter_contract_conflicts(commands) + access_filter_contract_conflicts(commands)
    if conflicts: raise UpgradeError("Live Fail2Ban filter contract failed:\n" + "\n".join(conflicts))
    print("PASS: live daemon critical/sweep/access semantic contracts, IPv4/IPv6")


def access_filter_contract_cases():
    """Bounded attacks and benign access requests; no site-specific defaults."""
    benign = ("/", "/admin", "/test", "/hello", "/random", "/foo/bar", "/wp-admin",
              "/wp-login.php", "/wp-json", "/wp-json/wp/v2/posts", "/wp-admin/admin-ajax.php",
              "/health", "/status", "/ping", "/heartbeat", "/index.php/login",
              "/booking/reschedule/abc", "/assets/vendor/jquery/jquery.min.js",
              "/.well-known/acme-challenge/token", "/download/a%2fb", "/search?q=caf%C3%A9",
              "/docs/bot/crawler/spider/sqlmap", "/news?test=foo&hello=world")
    jails = ("f2b-botnet-signatures", "f2b-fuzzing-payloads", "f2b-web-medium", "nginx-recon-bonus")
    for jail, target, status, method in itertools.product(jails, benign, (200, 404, 429, 444), ("GET", "HEAD")):
        yield jail, target, status, method, "OAI-SearchBot/1.0", False
    for tool in ("sqlmap/1.8", "Nikto/2.5", "Nmap Scripting Engine", "nuclei/3.0", "ffuf/2.0"):
        yield "f2b-botnet-signatures", "/", 404, "GET", tool, True
    for target in ("/x?file=%2e%2e%2fetc/passwd", "/../../etc/passwd", "/x%00.php",
                   "/x?file=%5c%5cwindows", "/%252e%252e%252fetc/passwd"):
        yield "f2b-fuzzing-payloads", target, 404, "GET", "Mozilla/5.0", True
    for jail, target in itertools.product(("f2b-web-medium", "nginx-recon-bonus"),
                                         ("/.git/config", "/.env", "/.env.local", "/wp-config.php", "/shell.php")):
        yield jail, target, 404, "GET", "Mozilla/5.0", True


def access_filter_contract_conflicts(commands):
    compiled = {}
    enabled = {command[1] for command in commands if len(command) >= 3 and command[0] in {"add", "set", "multi-set"}}
    for jail, *_ in access_filter_contract_cases():
        if jail not in enabled: continue
        if jail in compiled: continue
        expressions = {"addfailregex": [], "addignoreregex": []}
        try:
            for command in commands:
                if len(command) == 4 and command[0] in {"set", "multi-set"} and command[1] == jail and command[2] in expressions:
                    values = command[3] if isinstance(command[3], list) else [command[3]]
                    expressions[command[2]].extend(re.compile(value.replace("<HOST>", r"(?:[0-9.]+|[0-9A-Fa-f:]+)")) for value in values)
            compiled[jail] = expressions
        except (re.error, TypeError) as error:
            return [f"[{jail}] cannot compile effective access filter: {error}"]
    conflicts = []
    filters = {"nginx-recon-bonus": "nginx-recon-optimized"}
    for jail, target, status, method, ua, expected in access_filter_contract_cases():
        if jail not in compiled: continue
        expressions = compiled[jail]
        for host in ("192.0.2.7", "2001:db8::7"):
            line = (f'[11/Oct/2026:12:00:00 +0000] - {status} {status} - {method} https example.invalid "{target}" '
                    f'[Client {host}] [Length 10] [Gzip -] [Sent-to backend] "{ua}" "-"')
            actual = (any(p.search(line) for p in expressions["addfailregex"]) and
                      not any(p.search(line) for p in expressions["addignoreregex"]))
            if actual != expected:
                conflicts.append(f"[{jail}] access contract expected match={expected}: {method} {target} "
                                 f"status={status} client={host}; inspect /etc/fail2ban/filter.d/"
                                 f"{filters.get(jail, jail)}.local and jail/filter overrides")
                if len(conflicts) >= 10: break
        if len(conflicts) >= 10: break
    return conflicts


def boot_contract():
    spec = importlib.util.spec_from_file_location('f2b_boot_contract', Path(__file__).with_name('boot-contract.py'))
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def check_boot():
    try: return boot_contract().check(run)
    except (ValueError, OSError) as error: raise UpgradeError(str(error)) from error


def create_backup(
    backup_base: Path,
    bans: dict[str, list[str]],
    nft_doc: dict,
    label: str = "v033-to-v034",
) -> Path:
    timestamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S-%f")
    backup = backup_base / f"{label}-{timestamp}"
    backup.mkdir(parents=True, mode=0o700)
    (backup / 'unit-enabled-states.json').write_text(json.dumps(boot_contract().enabled_states(run), sort_keys=True) + '\n')
    existing = [str(path) for path in SYSTEM_BACKUP_PATHS if (Path("/") / path).exists()]
    if existing:
        run(
            "tar", "--acls", "--xattrs", "--numeric-owner",
            "--exclude=*.sqlite3-wal", "--exclude=*.sqlite3-shm", "-cpf",
            str(backup / "system-files.tar"), "-C", "/", *existing,
        )
    with tempfile.TemporaryDirectory(prefix="f2b-db-backup-") as temporary:
        for database in Path("/var/lib/fail2ban").glob("*.sqlite3"):
            relative = database.relative_to("/")
            destination = Path(temporary) / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            backup_sqlite(database, destination)
            run("tar", "-rpf", str(backup / "system-files.tar"), "-C", temporary, str(relative))
    with tarfile.open(backup / "system-files.tar") as archive:
        members = [member.name for member in archive.getmembers()]
    (backup / "manifest.json").write_text(json.dumps({"schema": 1, "release": RELEASE,
        "paths": existing, "members": members, "targets": [str(p) for p in install_map(package_root())] +
        ["/etc/nftables.conf", "/etc/nftables.d/fail2ban-filter.nft", "/etc/nftables.d/docker-block.nft"]}, indent=2) + "\n")
    (backup / "fail2ban-bans.json").write_text(json.dumps(bans, indent=2) + "\n")
    (backup / "fail2ban-ban-times.json").write_text(json.dumps(snapshot_ban_times(), indent=2) + "\n")
    (backup / "nft-ruleset.json").write_text(json.dumps(nft_doc, indent=2) + "\n")
    (backup / "nft-ruleset.txt").write_text(run("nft", "-s", "list", "ruleset").stdout)
    for table in sorted(OWNED_NFT_TABLES):
        (backup / (table + ".nft")).write_text(run("nft", "-s", "list", "table", "inet", table).stdout)
    (backup / "fail2ban-dump.txt").write_text(run("fail2ban-client", "-d").stdout)
    (backup / "services.txt").write_text(
        run("systemctl", "is-active", "fail2ban", "nftables", "docker", check=False).stdout
    )
    (backup / "root-crontab.txt").write_text(run("crontab", "-l", check=False).stdout)
    checksums = []
    for path in sorted(backup.iterdir()):
        if path.is_file() and path.name != "SHA256SUMS":
            checksums.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}")
    (backup / "SHA256SUMS").write_text("\n".join(checksums) + "\n")
    return backup


def backup_sqlite(database: Path, destination: Path) -> None:
    with closing(sqlite3.connect(f"file:{database}?mode=ro", uri=True)) as source:
        with closing(sqlite3.connect(destination)) as target:
            source.backup(target)
    shutil.copystat(database, destination)
    if os.geteuid() == 0:
        metadata = database.stat()
        os.chown(destination, metadata.st_uid, metadata.st_gid)


def verify_backup(backup: Path) -> None:
    checksum_file = backup / "SHA256SUMS"
    if not checksum_file.is_file():
        raise UpgradeError(f"Missing backup checksums: {checksum_file}")
    for line in checksum_file.read_text().splitlines():
        expected, name = line.split("  ", 1)
        path = backup / name
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise UpgradeError(f"Backup checksum failed: {path}")


def atomic_install(source: Path, target: Path) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, staged_name = tempfile.mkstemp(prefix=f".{target.name}.v034-", dir=target.parent)
    staged = Path(staged_name)
    try:
        with os.fdopen(fd, "wb") as output, source.open("rb") as input_file:
            shutil.copyfileobj(input_file, output)
            output.flush()
            os.fsync(output.fileno())
        os.chmod(staged, file_mode(target))
        if os.geteuid() == 0:
            os.chown(staged, 0, 0)
        os.replace(staged, target)
    finally:
        staged.unlink(missing_ok=True)


def deploy(mapping: dict[Path, Path]) -> None:
    for target, source in mapping.items():
        atomic_install(source, target)


def restore_files(backup: Path, mapping: dict[Path, Path]) -> None:
    manifest = json.loads((backup / "manifest.json").read_text())
    # Top-level backup roots are not an inventory of their child files.
    # Remove exactly new managed targets, including nested jail.d files.
    existed = {str(Path("/") / path) for path in manifest["members"]}
    for target in mapping:
        if str(target) not in existed:
            target.unlink(missing_ok=True)
    archive = backup / "system-files.tar"
    if archive.exists():
        run("tar", "--acls", "--xattrs", "--numeric-owner", "-xpf", str(archive), "-C", "/")


def verify_after(bans: dict[str, list[str]], before_nft: dict) -> None:
    check_boot()
    run("fail2ban-client", "-t")
    run("fail2ban-client", "ping")
    restore_missing_bans(bans)
    assert_bans_preserved(bans)
    after_nft = nft_ruleset()
    if external_nft_digest(after_nft) != external_nft_digest(before_nft):
        raise UpgradeError("An nftables table outside fail2ban-filter/docker-block changed")
    validate_live_firewall()
    run("/usr/bin/python3", "/usr/local/sbin/f2b-ipv6-sync.py", "check")
    version = run("/usr/local/bin/f2b", "version", "--short").stdout.strip()
    if version != RELEASE:
        raise UpgradeError(f"Installed wrapper reports {version!r}, expected {RELEASE!r}")
    verify_release_runtime(bans, before_nft)
    validate_live_filter_contracts()
    validate_effective_dump(run("fail2ban-client", "-d").stdout)
    verifier = load_verifier()
    for jail in parse_jails(run("fail2ban-client", "status").stdout):
        if jail != "recidive": verifier.verify_nft_lifecycle(jail)
    run("/usr/bin/python3", "/usr/local/sbin/f2b-save-owned-tables.py")
    if external_nft_digest(nft_ruleset()) != external_nft_digest(before_nft):
        raise UpgradeError("Foreign firewall changed after persistence")


def load_verifier():
    script = package_root() / "scripts/upgrade-v034dev-canary-227c393.py"
    spec = importlib.util.spec_from_file_location("f2b_v034_runtime_checks", script)
    if spec is None or spec.loader is None: raise UpgradeError("Cannot load runtime verifier")
    verifier = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(verifier)
    return verifier


def verify_release_runtime(bans: dict[str, list[str]], before_nft: dict) -> None:
    # Use the same verifier exercised by the successful v0.34-dev canary.
    # Any exception stays inside main's transaction and triggers rollback.
    script = package_root() / "scripts/upgrade-v034dev-canary-227c393.py"
    spec = importlib.util.spec_from_file_location("f2b_v034_runtime_checks", script)
    if spec is None or spec.loader is None:
        raise UpgradeError(f"Cannot load runtime verifier: {script}")
    verifier = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(verifier)
    verifier.verify_live(package_root(), bans, before_nft)


def native_tickets(database: Path, now: float) -> dict:
    """Read-only recognized schema; no ticket insert/re-add or TTL correction."""
    if database.is_symlink() or not database.is_file(): raise UpgradeError('Native rollback database missing/unsafe')
    with closing(sqlite3.connect(database.as_uri() + '?mode=ro', uri=True, timeout=2)) as connection:
        if connection.execute('PRAGMA integrity_check').fetchone() != ('ok',):
            raise UpgradeError('Native rollback database integrity failed')
        if connection.execute('SELECT version FROM fail2banDb').fetchall() != [(4,)]:
            raise UpgradeError('Native rollback requires reviewed Fail2Ban DB schema 4')
        rows = connection.execute('SELECT jail, ip, timeofban, bantime FROM bips').fetchall()
    result = {}
    for jail, address, started, duration in rows:
        if not isinstance(jail, str) or not valid_ip(address) or type(started) is not int or type(duration) is not int or duration < -1:
            raise UpgradeError('Unrecognized native rollback ticket; no changes made')
        if duration == -1 or started + duration > now:
            result.setdefault(jail, {})[address] = None if duration == -1 else started + duration
    return result


def rollback_expectations(backup: Path, compare_live=True) -> tuple[set, dict]:
    jails = set(json.loads((backup / 'fail2ban-bans.json').read_text()))
    if not jails: raise UpgradeError('Backup has no expected rollback jails')
    with tempfile.TemporaryDirectory(prefix='f2b-rollback-db-check-') as temporary:
        database = Path(temporary) / 'native.sqlite3'
        with tarfile.open(backup / 'system-files.tar') as archive:
            member = archive.getmember('var/lib/fail2ban/fail2ban.sqlite3')
            if not member.isfile(): raise UpgradeError('Backup database is not a regular file')
            with archive.extractfile(member) as source, database.open('xb') as destination:
                shutil.copyfileobj(source, destination)
        now = time.time()
        expected = native_tickets(database, now)
        if set(expected) - jails: raise UpgradeError('Backup active tickets refer to unavailable rollback jails')
        if compare_live and native_tickets(Path('/var/lib/fail2ban/fail2ban.sqlite3'), now) != expected:
            raise UpgradeError('Rollback refused BEFORE stop: current DB tickets differ from backup (new/revoked/retimed/new-jail ban). '
                               'No re-add or implicit DB migration is allowed; preserve state/backup for reviewed recovery')
    return jails, expected


def timed_records(records):
    result = {}
    for jail, lines in records.items():
        if not isinstance(lines, list): raise UpgradeError('Invalid native restore response')
        result[jail] = {}
        for line in lines:
            match = re.fullmatch(r'(\S+)\s+(.+?) \+ (-?\d+) = (.+)', line)
            if not match or not valid_ip(match[1]): raise UpgradeError('Invalid native restore ticket response')
            result[jail][match[1]] = None if int(match[3]) == -1 else dt.datetime.strptime(match[4], '%Y-%m-%d %H:%M:%S').timestamp()
    return result


def wait_rollback_ready(jails: set, expected: dict, timeout=60):
    """Read-only bounded socket -> exact jails -> native DB tickets/expiry gate."""
    deadline = time.monotonic() + timeout
    phase = 'socket/ping'
    while time.monotonic() < deadline:
        try:
            phase = 'socket/ping'
            budget = lambda: max(.01, min(3, deadline - time.monotonic()))
            ping = run('fail2ban-client', 'ping', check=False, timeout=budget())
            if ping.returncode == 0 and ping.stdout.strip() == 'Server replied: pong':
                phase = 'exact jail registration'
                status = run('fail2ban-client', 'status', check=False, timeout=budget())
                if status.returncode == 0 and set(parse_jails(status.stdout)) == jails:
                    phase = 'native DB ban restore/absolute expiry'
                    live = timed_records(snapshot_ban_times(timeout=budget()))
                    now = time.time()
                    complete = set(live) == jails
                    for jail, tickets in expected.items():
                        for address, expiry in tickets.items():
                            if expiry is not None and expiry <= now:
                                complete &= address not in live.get(jail, {})
                                continue
                            actual = live.get(jail, {}).get(address, 'missing')
                            if expiry is None:
                                complete &= actual is None
                            else:
                                complete &= type(actual) in {int, float} and abs(actual - expiry) <= 1
                    if complete and time.monotonic() <= deadline: return
        except (subprocess.TimeoutExpired, UpgradeError, ValueError):
            pass
        time.sleep(min(.2, max(0, deadline - time.monotonic())))
    raise UpgradeError('Rollback readiness timeout: ' + phase + '; no banip writes performed. '
                       'File/DB/firewall restore may already be complete; retain backup and run read-only audit, do not blindly rerun')


def rollback(backup: Path, mapping: dict[Path, Path] | None = None) -> None:
    if not backup.is_dir() or not (backup / "manifest.json").is_file():
        raise UpgradeError(f"Invalid backup directory: {backup}")
    verify_backup(backup)
    manifest = json.loads((backup / "manifest.json").read_text())
    if manifest.get("schema") != 1 or not isinstance(manifest.get("targets"), list) or not isinstance(manifest.get("members"), list):
        raise UpgradeError("Incompatible backup manifest; no rollback changes made")
    mapping = {Path(p): Path(p) for p in manifest["targets"]}
    jails, expected = rollback_expectations(backup)
    # Restoring SQLite files requires stopping Fail2Ban, never Docker/nftables.
    run("systemctl", "stop", "fail2ban")
    # Recheck after stop to catch tickets committed while shutdown was pending.
    # On mismatch leave the private backup/live DB intact; do not overwrite it.
    try: rollback_expectations(backup)
    except Exception as error:
        raise UpgradeError('Tickets changed during shutdown: service is stopped but live DB/files were NOT restored/overwritten. '
                           'Retain state and backup for reviewed recovery; no re-add attempted') from error
    restore_files(backup, mapping)
    for suffix in ("-wal", "-shm"):
        for sidecar in Path("/var/lib/fail2ban").glob("*.sqlite3" + suffix):
            sidecar.unlink(missing_ok=True)
    run("systemctl", "daemon-reload")
    states = backup / 'unit-enabled-states.json'
    if states.exists():
        try: boot_contract().restore_enabled(run, json.loads(states.read_text()))
        except ValueError as error: raise UpgradeError(str(error)) from error
    else:
        print('LEGACY BACKUP: enabled states were not recorded; no enable/disable attempted')
    run("fail2ban-client", "-t")
    # Restore the original owned firewall, including IPv6 elements and local
    # blocked ports, in one transaction. Never submit the full ruleset backup.
    commands = []
    for table in sorted(OWNED_NFT_TABLES):
        if run("nft", "list", "table", "inet", table, check=False).returncode == 0:
            commands.append("delete table inet " + table)
        commands.append((backup / (table + ".nft")).read_text())
    run("nft", "-f", "-", input_text="\n".join(commands) + "\n")
    run("systemctl", "start", "fail2ban")
    wait_rollback_ready(jails, expected)
    before = json.loads((backup / "nft-ruleset.json").read_text())
    if external_nft_digest(nft_ruleset()) != external_nft_digest(before):
        raise UpgradeError("Foreign firewall changed during rollback; not automatically overwritten")


def audit_rollback(backup: Path):
    """Read-only completion audit, including backups from immutable 1964009."""
    verify_backup(backup)
    jails, expected = rollback_expectations(backup, compare_live=False)
    run('fail2ban-client', '-t', timeout=10)
    wait_rollback_ready(jails, expected)
    with tarfile.open(backup / 'system-files.tar') as archive:
        members = {member.name: member for member in archive if member.isfile()}
        for name, member in members.items():
            if name.startswith(('etc/fail2ban/', 'usr/local/')):
                path = Path('/') / name
                if path.is_symlink() or not path.is_file() or path.read_bytes() != archive.extractfile(member).read():
                    raise UpgradeError('Rollback audit: original configuration/managed bytes differ; retain private evidence')
        manifest = json.loads((backup / 'manifest.json').read_text())
        for target in manifest['targets']:
            if str(Path(target).relative_to('/')) not in members and Path(target).exists():
                raise UpgradeError('Rollback audit: introduced managed target remains; no cleanup attempted')
    before = json.loads((backup / 'nft-ruleset.json').read_text())
    if external_nft_digest(nft_ruleset()) != external_nft_digest(before):
        raise UpgradeError('Rollback audit: foreign firewall differs; nothing overwritten')
    validate_live_firewall()
    check_boot()
    states = backup / 'unit-enabled-states.json'
    if states.exists():
        if boot_contract().enabled_states(run) != json.loads(states.read_text()):
            raise UpgradeError('Rollback audit: enabled states differ; no repair attempted')
    else: print('NOT VERIFIED: legacy backup did not record original enabled states; inspect locally')
    print('PASS: read-only rollback audit (config/managed bytes, exact jails, native ticket expiry, required infrastructure, foreign rules). '
          'No re-add, no lifecycle change; not reboot/packet acceptance')


def validate_dbfile(output):
    """Accept a plain value or Fail2Ban 1.0.2's labelled tree output."""
    value = output.strip()
    formatted = re.fullmatch(r"Current database file is:\n[ \t]*[`|]-[ \t]+([^\r\n]+)", value)
    if formatted: value = formatted[1].strip()
    if value == "None": return None
    if not re.fullmatch(r"/[^\r\n]+", value):
        raise UpgradeError("Unrecognized Fail2Ban dbfile response")
    if value != "/var/lib/fail2ban/fail2ban.sqlite3":
        raise UpgradeError("Custom dbfile requires an explicit backup plan: " + value)
    return value


def validate_multiport(multiport: Path) -> None:
    multiport_text = multiport.read_text(errors="replace") if multiport.is_file() else ""
    if "before = nftables.conf" not in multiport_text or "type = multiport" not in multiport_text:
        # The unmodified v0.33 bundle used a fixed IPv4-only action. Migrate
        # that exact known file; unknown site-edited actions require review.
        legacy_digest = "d62391daee1c28514c3dd8e64940683645d0ee7e3c757a4819875a7146d6140b"
        if hashlib.sha256(multiport.read_bytes()).hexdigest() != legacy_digest:
            raise UpgradeError("Unknown local nftables-multiport.conf; review migration before apply")


def preflight(root: Path, mapping: dict[Path, Path], review_file: Path | None = None) -> tuple[dict[str, list[str]], dict]:
    require_commands(("bash", "crontab", "fail2ban-client", "nft", "systemctl", "tar", "/usr/bin/python3", "/usr/bin/flock", "/usr/bin/logger"))
    if not Path("/etc/fail2ban/jail.local").is_file():
        raise UpgradeError("Missing /etc/fail2ban/jail.local")
    current = run("fail2ban-client", "-t", check=False)
    if current.returncode:
        raise UpgradeError("Current configuration cannot be restarted safely for rollback; repair before upgrade:\n" + current.stdout + current.stderr)
    validate_multiport(Path("/etc/fail2ban/action.d/nftables-multiport.conf"))
    if run("fail2ban-client", "ping").stdout.strip() != "Server replied: pong":
        raise UpgradeError("Fail2Ban is not responding")
    validate_dbfile(run("fail2ban-client", "get", "dbfile").stdout)
    validate_package(root, mapping)
    check_boot()
    audit_targets(root, mapping, review_file)
    run("systemctl", "is-active", "--quiet", "cron")
    version = run("/usr/local/bin/f2b", "version", "--short").stdout.strip().lstrip("v")
    if version not in {"0.33", "0.33-ipv6.1", RELEASE}: raise UpgradeError("Unsupported installed wrapper version: " + version)
    snapshot_ban_times()
    with tempfile.TemporaryDirectory(prefix="f2b-persistence-preflight-") as temporary:
        prepare_persistence(dict(mapping), Path(temporary))
    cron = run("crontab", "-l", check=False).stdout
    if re.search(r"(?m)^[^#\n]*(?:flush\s+ruleset|systemctl\s+(?:restart|reload)\s+(?:nftables|docker)|nft\s+-f)", cron):
        raise UpgradeError("Root crontab contains a firewall reload/flush command; review it before apply")
    for path in sorted(Path("/etc/fail2ban").rglob("*.local")):
        if path not in mapping:
            print("PRESERVED local override: " + str(path))
            if str(path) in FILTER_OVERRIDE_POLICY["paths"]:
                digest = hashlib.sha256(path.read_bytes()).hexdigest()
                marker = FILTER_OVERRIDE_POLICY["marker"] in path.read_text(errors="replace")
                print(f"COEXISTENCE: {path} SHA256={digest} scan-review marker={marker}; "
                      "contents preserved, compatibility requires effective contract checks")
    validate_live_firewall()
    validate_candidate(root, mapping)
    bans = snapshot_bans()
    nft_doc = nft_ruleset()
    return bans, nft_doc


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--apply", action="store_true", help="perform the upgrade after preflight")
    mode.add_argument("--rollback", type=Path, metavar="BACKUP", help="restore a backup created by this tool")
    mode.add_argument('--audit-rollback', type=Path, metavar='BACKUP', help='read-only completion audit; no rollback or ban writes')
    parser.add_argument("--backup-dir", type=Path, default=Path("/var/backups/f2b-v034"))
    parser.add_argument("--local-review", type=Path, help="private root-only approvals outside this package, bound to its exact commit")
    args = parser.parse_args()
    try:
        require_root()
        root = package_root()
        mapping = install_map(root)
        if args.audit_rollback:
            audit_rollback(args.audit_rollback)
            return 0
        # Mutating modes exclude concurrent upgrades and the new cron job.
        # Dry-run preflight does not create a lock or installed files.
        operation_lock = None
        if args.apply or args.rollback:
            operation_lock = acquire_upgrade_lock()
        if args.rollback:
            rollback(args.rollback, mapping)
            print(f"PASS: rollback restored {args.rollback}")
            return 0
        bans, before_nft = preflight(root, mapping, args.local_review)
        print(f"PASS: preflight; {len(bans)} jails and {sum(map(len, bans.values()))} active bans captured")
        if not args.apply:
            print("No changes made. Re-run with --apply only in the approved maintenance window.")
            return 0
        backup = create_backup(args.backup_dir, bans, before_nft)
        print(f"Backup complete: {backup}")
        try:
            with tempfile.TemporaryDirectory(prefix="f2b-persistence-") as temporary:
                prepare_persistence(mapping, Path(temporary))
                deploy(mapping)
            run("systemctl", "daemon-reload")
            run("fail2ban-client", "-t")
            run("fail2ban-client", "reload")
            verify_after(bans, before_nft)
        except Exception as original:
            try:
                rollback(backup, mapping)
            except Exception as rollback_error:
                raise UpgradeError(
                    f"Upgrade failed: {original}\nAUTOMATIC ROLLBACK ALSO FAILED: {rollback_error}\n"
                    f"Backup: {backup}"
                ) from original
            raise UpgradeError(
                f"Upgrade failed and was rolled back: {original}\nBackup: {backup}"
            ) from original
        print(f"PASS: upgraded to {RELEASE}; backup: {backup}")
        print("Docker and nftables services were not restarted. No nftables ruleset was loaded or flushed.")
        return 0
    except (OSError, UpgradeError, sqlite3.Error, tarfile.TarError, KeyError, json.JSONDecodeError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
