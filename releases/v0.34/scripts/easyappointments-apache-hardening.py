#!/usr/bin/env python3
"""Optional transactional Apache hardening for Easy!Appointments.

The default mode is read-only preflight. --apply installs only the two managed
Apache snippets and their conf-enabled symlinks. Any failed config test, reload
or HTTP verification restores their exact prior state.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import os
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


SCRIPT = Path(__file__).resolve()
RELEASE_ROOT = SCRIPT.parents[1]
NAMES = (
    "easyappointments-private-vendor.conf",
    "easyappointments-private-storage.conf",
)
PRIVATE_DIRS = ("backups", "logs", "sessions", "cache")
SCRIPT_SUFFIXES = ("php", "phtml", "php.jpg")


@dataclasses.dataclass
class ProbeState:
    marker: str
    created: list[Path]
    public_status: dict[str, int]
    upload_text_status: int


def run(*args: str) -> None:
    subprocess.run(args, check=True)


def render(template: str, app_root: Path) -> bytes:
    source = (RELEASE_ROOT / "apache" / template).read_text()
    return source.replace("/var/www/html/easyappointments", str(app_root)).encode()


def targets(conf_available: Path, conf_enabled: Path) -> list[tuple[Path, Path]]:
    return [(conf_available / name, conf_enabled / name) for name in NAMES]


def canonical_target(path: Path) -> Path:
    """Resolve the parent without following the managed entry's symlink."""
    return path.parent.resolve() / path.name


def validate_backend_url(value: str) -> str:
    parsed = urllib.parse.urlsplit(value)
    if parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
        raise ValueError("backend URL must be loopback HTTP, for example http://127.0.0.1:8080")
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise ValueError("backend URL must not contain a path, query or fragment")
    return value.rstrip("/")


def http_status(base: str, path: str) -> int:
    request = urllib.request.Request(base + path, method="GET")
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status
    except urllib.error.HTTPError as error:
        return error.code


def check_layout(app_root: Path) -> None:
    required = [app_root / "vendor", app_root / "storage" / "uploads"]
    required += [app_root / "storage" / name for name in PRIVATE_DIRS]
    missing = [str(path) for path in required if not path.is_dir()]
    if missing:
        raise RuntimeError("missing Easy!Appointments directories: " + ", ".join(missing))
    upload_htaccess = app_root / "storage" / "uploads" / ".htaccess"
    if upload_htaccess.exists() or upload_htaccess.is_symlink():
        raise RuntimeError(f"refusing to override existing upload policy: {upload_htaccess}")


def check_managed_scope(app_root: Path, conf_available: Path, conf_enabled: Path) -> None:
    for name, (available, enabled) in zip(NAMES, targets(conf_available, conf_enabled)):
        expected = render(name, app_root)
        if available.exists() and available.read_bytes() != expected:
            raise RuntimeError(f"refusing to replace unknown configuration: {available}")
        if enabled.exists() or enabled.is_symlink():
            if not enabled.is_symlink() or enabled.resolve(strict=False) != available.resolve():
                raise RuntimeError(f"refusing to replace unknown enabled entry: {enabled}")


def snapshot_entry(path: Path, backup: Path, key: str) -> dict[str, str | bool]:
    if path.is_symlink():
        return {"kind": "symlink", "target": os.readlink(path)}
    if path.exists():
        destination = backup / key
        shutil.copy2(path, destination)
        return {"kind": "file", "backup": destination.name}
    return {"kind": "missing"}


def make_backup(conf_available: Path, conf_enabled: Path, backup_root: Path) -> Path:
    backup_root.mkdir(parents=True, exist_ok=True)
    backup = Path(tempfile.mkdtemp(prefix="easyappointments-apache-", dir=backup_root))
    entries: dict[str, dict[str, str | bool]] = {}
    for available, enabled in targets(conf_available, conf_enabled):
        available = canonical_target(available)
        enabled = canonical_target(enabled)
        entries[str(available)] = snapshot_entry(available, backup, "available-" + available.name)
        entries[str(enabled)] = snapshot_entry(enabled, backup, "enabled-" + enabled.name)
    manifest = {
        "version": 1,
        "conf_available": str(conf_available.resolve()),
        "conf_enabled": str(conf_enabled.resolve()),
        "entries": entries,
    }
    (backup / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return backup


def remove_entry(path: Path) -> None:
    if path.is_symlink() or path.is_file():
        path.unlink()
    elif path.exists():
        raise RuntimeError(f"refusing to remove non-file entry: {path}")


def restore_backup(backup: Path, *, configtest: bool = True, reload_apache: bool = True) -> None:
    manifest = json.loads((backup / "manifest.json").read_text())
    if manifest.get("version") != 1:
        raise RuntimeError("unsupported or missing backup manifest version")
    conf_available = Path(manifest["conf_available"])
    conf_enabled = Path(manifest["conf_enabled"])
    expected = {
        str(path)
        for pair in targets(conf_available, conf_enabled)
        for path in pair
    }
    if set(manifest.get("entries", {})) != expected:
        raise RuntimeError("backup manifest contains unexpected restore targets")
    for raw_path, state in manifest["entries"].items():
        path = Path(raw_path)
        remove_entry(path)
        if state["kind"] == "file":
            path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(backup / state["backup"], path)
        elif state["kind"] == "symlink":
            path.parent.mkdir(parents=True, exist_ok=True)
            path.symlink_to(state["target"])
    if configtest:
        run("apache2ctl", "configtest")
    if reload_apache:
        run("systemctl", "reload", "apache2")


def atomic_write(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix="." + path.name + ".", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o644)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def install(app_root: Path, conf_available: Path, conf_enabled: Path) -> None:
    conf_enabled.mkdir(parents=True, exist_ok=True)
    for name, (available, enabled) in zip(NAMES, targets(conf_available, conf_enabled)):
        atomic_write(available, render(name, app_root))
        remove_entry(enabled)
        enabled.symlink_to(available)


def prepare_http_probes(app_root: Path, backend: str) -> ProbeState:
    marker = "f2b-hardening-" + next(tempfile._get_candidate_names())
    created: list[Path] = []
    public_paths = ("/", "/index.php/login", "/assets/vendor/jquery/jquery.min.js")
    try:
        for directory in PRIVATE_DIRS:
            path = app_root / "storage" / directory / f"{marker}.txt"
            path.write_text("harmless hardening test marker\n")
            created.append(path)
        for suffix in (*SCRIPT_SUFFIXES, "txt"):
            path = app_root / "storage" / "uploads" / f"{marker}.{suffix}"
            path.write_text("harmless hardening test marker\n")
            created.append(path)
        public_status = {path: http_status(backend, path) for path in public_paths}
        upload_text_status = http_status(backend, f"/storage/uploads/{marker}.txt")
        return ProbeState(marker, created, public_status, upload_text_status)
    except Exception:
        cleanup_http_probes(created)
        raise


def cleanup_http_probes(created: list[Path]) -> None:
    for path in created:
        try:
            path.unlink()
        except FileNotFoundError:
            pass


def verify_http(backend: str, probes: ProbeState) -> None:
    marker = probes.marker
    forbidden = [
        "/vendor/composer/installed.json",
        "/vendor/composer/installed.json?probe=1",
        "/vendor/autoload.php",
    ]
    forbidden += [f"/storage/{directory}/{marker}.txt" for directory in PRIVATE_DIRS]
    forbidden += [f"/storage/uploads/{marker}.{suffix}" for suffix in SCRIPT_SUFFIXES]
    for path in forbidden:
        status = http_status(backend, path)
        if status != 403:
            raise RuntimeError(f"expected HTTP 403 for {path}, got {status}")
    encoded = http_status(backend, "/vendor%2fcomposer/installed.json")
    if encoded not in {403, 404}:
        raise RuntimeError(f"expected HTTP 403/404 for encoded vendor path, got {encoded}")
    for path, before in probes.public_status.items():
        after = http_status(backend, path)
        if after != before:
            raise RuntimeError(f"public route changed status: {path}: {before} -> {after}")
    # Upload text is deliberately not denied. Its status must remain the same
    # as before installation; no claim is made that it must be public.
    text_after = http_status(backend, f"/storage/uploads/{marker}.txt?probe=1")
    if probes.upload_text_status != text_after:
        raise RuntimeError(
            "upload text status changed: "
            f"{probes.upload_text_status} -> {text_after}"
        )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--apply", action="store_true")
    mode.add_argument("--rollback", type=Path, metavar="BACKUP")
    parser.add_argument("--app-root", type=Path, default=Path("/var/www/html/easyappointments"))
    parser.add_argument("--backend-url", default="http://127.0.0.1:8080")
    parser.add_argument("--conf-available", type=Path, default=Path("/etc/apache2/conf-available"), help=argparse.SUPPRESS)
    parser.add_argument("--conf-enabled", type=Path, default=Path("/etc/apache2/conf-enabled"), help=argparse.SUPPRESS)
    parser.add_argument("--backup-root", type=Path, default=Path("/var/backups"), help=argparse.SUPPRESS)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        backend = validate_backend_url(args.backend_url)
        if args.rollback:
            if os.geteuid() != 0:
                raise RuntimeError("rollback requires root")
            restore_backup(args.rollback)
            print(f"PASS: restored {args.rollback}")
            return 0
        check_layout(args.app_root)
        check_managed_scope(args.app_root, args.conf_available, args.conf_enabled)
        run("apache2ctl", "configtest")
        print("PASS: preflight; Easy!Appointments layout and Apache configuration are valid")
        if not args.apply:
            print("No changes made. Re-run with --apply only after reviewing the application paths.")
            return 0
        if os.geteuid() != 0:
            raise RuntimeError("apply requires root")
        probes = prepare_http_probes(args.app_root, backend)
        try:
            backup = make_backup(args.conf_available, args.conf_enabled, args.backup_root)
            print(f"Backup: {backup}")
            try:
                install(args.app_root, args.conf_available, args.conf_enabled)
                run("apache2ctl", "configtest")
                run("systemctl", "reload", "apache2")
                verify_http(backend, probes)
            except Exception:
                restore_backup(backup)
                raise
        finally:
            cleanup_http_probes(probes.created)
        print("PASS: optional Easy!Appointments Apache hardening installed and verified")
        return 0
    except Exception as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
