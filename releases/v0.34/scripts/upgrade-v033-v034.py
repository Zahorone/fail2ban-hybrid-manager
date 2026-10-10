#!/usr/bin/env python3
"""Transactional v0.33 -> v0.34 upgrade without a global firewall reload."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from typing import Iterable


RELEASE = "0.34-dev"
OWNED_NFT_TABLES = {"fail2ban-filter", "docker-block"}
SYSTEM_BACKUP_PATHS = (
    Path("etc/fail2ban"),
    Path("etc/nftables.conf"),
    Path("etc/nftables.d"),
    Path("etc/systemd/system/nftables.service.d"),
    Path("etc/systemd/system/docker.service.d"),
    Path("usr/local/bin/f2b"),
    Path("usr/local/bin/nft-save-tables.sh"),
    Path("usr/local/sbin/f2b-docker-hook"),
    Path("usr/local/sbin/f2b-ipv6-sync.py"),
    Path("usr/local/libexec/f2b-report-filter.py"),
    Path("etc/f2b"),
    Path("var/lib/fail2ban"),
)


class UpgradeError(RuntimeError):
    pass


def run(*args: str, check: bool = True, input_text: str | None = None) -> subprocess.CompletedProcess:
    result = subprocess.run(args, input=input_text, text=True, capture_output=True)
    if check and result.returncode:
        raise UpgradeError(
            f"command failed ({result.returncode}): {' '.join(args)}\n"
            f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )
    return result


def require_root() -> None:
    if os.geteuid() != 0:
        raise UpgradeError("Run with sudo; no changes made.")


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
    for name in ("nftables-recidive.conf",):
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
            Path("/etc/f2b/reporting.ini.example"): root / "config/reporting.ini.example",
            Path("/etc/systemd/system/nftables.service.d/90-f2b-preserve-runtime.conf"):
                root / "config/nftables-preserve-runtime.conf",
        }
    )
    return mapping


def file_mode(target: Path) -> int:
    return 0o755 if str(target).startswith(("/usr/local/bin/", "/usr/local/sbin/", "/usr/local/libexec/")) else 0o644


def validate_package(root: Path, mapping: dict[Path, Path]) -> None:
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
        if isinstance(payload, dict) and payload.get("table") in OWNED_NFT_TABLES:
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
        if "f2b-recidive-v6" not in dump:
            raise UpgradeError("Candidate does not resolve the IPv6 recidive set")


def create_backup(
    backup_base: Path,
    bans: dict[str, list[str]],
    nft_doc: dict,
    label: str = "v033-to-v034",
) -> Path:
    timestamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    backup = backup_base / f"{label}-{timestamp}"
    backup.mkdir(parents=True, mode=0o700)
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
            with sqlite3.connect(f"file:{database}?mode=ro", uri=True) as source:
                with sqlite3.connect(destination) as target:
                    source.backup(target)
            run("tar", "-rpf", str(backup / "system-files.tar"), "-C", temporary, str(relative))
    (backup / "manifest.json").write_text(
        json.dumps({"release": RELEASE, "paths": existing}, indent=2) + "\n"
    )
    (backup / "fail2ban-bans.json").write_text(json.dumps(bans, indent=2) + "\n")
    (backup / "nft-ruleset.json").write_text(json.dumps(nft_doc, indent=2) + "\n")
    (backup / "nft-ruleset.txt").write_text(run("nft", "-s", "list", "ruleset").stdout)
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
    existed = {str(Path("/") / path) for path in manifest["paths"]}
    for target in mapping:
        if str(target) not in existed:
            target.unlink(missing_ok=True)
    archive = backup / "system-files.tar"
    if archive.exists():
        run("tar", "--acls", "--xattrs", "--numeric-owner", "-xpf", str(archive), "-C", "/")


def verify_after(bans: dict[str, list[str]], before_nft: dict) -> None:
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


def rollback(backup: Path, mapping: dict[Path, Path] | None = None) -> None:
    if not backup.is_dir() or not (backup / "manifest.json").is_file():
        raise UpgradeError(f"Invalid backup directory: {backup}")
    verify_backup(backup)
    mapping = mapping or install_map(package_root())
    bans = json.loads((backup / "fail2ban-bans.json").read_text())
    # Restoring SQLite files requires stopping Fail2Ban, never Docker/nftables.
    run("systemctl", "stop", "fail2ban")
    restore_files(backup, mapping)
    for suffix in ("-wal", "-shm"):
        for sidecar in Path("/var/lib/fail2ban").glob("*.sqlite3" + suffix):
            sidecar.unlink(missing_ok=True)
    run("systemctl", "daemon-reload")
    run("fail2ban-client", "-t")
    run("systemctl", "start", "fail2ban")
    run("fail2ban-client", "ping")
    restore_missing_bans(bans)
    assert_bans_preserved(bans)


def preflight(root: Path, mapping: dict[Path, Path]) -> tuple[dict[str, list[str]], dict]:
    require_commands(("bash", "crontab", "fail2ban-client", "nft", "systemctl", "tar"))
    if not Path("/etc/fail2ban/jail.local").is_file():
        raise UpgradeError("Missing /etc/fail2ban/jail.local")
    multiport = Path("/etc/fail2ban/action.d/nftables-multiport.conf")
    multiport_text = multiport.read_text(errors="replace") if multiport.is_file() else ""
    if "before = nftables.conf" not in multiport_text or "type = multiport" not in multiport_text:
        raise UpgradeError("Active nftables-multiport.conf is not the upstream family-aware shim")
    if run("fail2ban-client", "ping").stdout.strip() != "Server replied: pong":
        raise UpgradeError("Fail2Ban is not responding")
    if re.search(
        r"^\s*flush\s+ruleset(?:\s|$)",
        Path("/etc/nftables.conf").read_text(errors="replace"),
        re.MULTILINE,
    ):
        raise UpgradeError("/etc/nftables.conf contains global flush ruleset")
    validate_package(root, mapping)
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
    parser.add_argument("--backup-dir", type=Path, default=Path("/var/backups/f2b-v034"))
    args = parser.parse_args()
    try:
        require_root()
        root = package_root()
        mapping = install_map(root)
        if args.rollback:
            rollback(args.rollback, mapping)
            print(f"PASS: rollback restored {args.rollback}")
            return 0
        bans, before_nft = preflight(root, mapping)
        print(f"PASS: preflight; {len(bans)} jails and {sum(map(len, bans.values()))} active bans captured")
        if not args.apply:
            print("No changes made. Re-run with --apply only in the approved maintenance window.")
            return 0
        backup = create_backup(args.backup_dir, bans, before_nft)
        print(f"Backup complete: {backup}")
        try:
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
    except (OSError, UpgradeError, json.JSONDecodeError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
