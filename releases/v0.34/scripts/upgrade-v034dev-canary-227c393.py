#!/usr/bin/env python3
"""Canary update of an existing v0.34-dev host to changeset 227c393."""

from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[1]
BASE_SCRIPT = Path(__file__).with_name("upgrade-v033-v034.py")
SPEC = importlib.util.spec_from_file_location("f2b_upgrade_v034_base", BASE_SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"Cannot load {BASE_SCRIPT}")
base = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = base
SPEC.loader.exec_module(base)

TARGET_CHANGESET = "227c393"
BACKUP_LABEL = f"v034dev-to-{TARGET_CHANGESET}"
JAIL = "f2b-webshell-sweep"


def install_map(root: Path) -> dict[Path, Path]:
    """Return the deliberately narrow canary payload."""
    return {
        Path("/etc/fail2ban/filter.d/f2b-exploit-critical.conf"):
            root / "filters/f2b-exploit-critical.conf",
        Path("/etc/fail2ban/filter.d/f2b-webshell-sweep.conf"):
            root / "filters/f2b-webshell-sweep.conf",
        Path("/etc/fail2ban/jail.d/99-webshell-sweep.local"):
            root / "config/webshell-sweep.local",
        Path("/usr/local/bin/f2b"): root / "scripts/f2b-wrapper-v034.sh",
    }


def scalar(jail: str, setting: str) -> str:
    output = base.run("fail2ban-client", "get", jail, setting).stdout.strip()
    match = re.search(r"(-?\d+)\s*$", output)
    if not match:
        raise base.UpgradeError(f"Cannot read {jail}.{setting}: {output!r}")
    return match.group(1)


def verify_filter_fixtures(root: Path) -> None:
    cases = (
        (root / "tests/fixtures/webshell-sweep-attacks.log", root / "filters/f2b-webshell-sweep.conf", 26),
        (root / "tests/fixtures/webshell-sweep-benign.log", root / "filters/f2b-webshell-sweep.conf", 0),
    )
    for log, filter_file, expected in cases:
        output = base.run("fail2ban-regex", str(log), str(filter_file)).stdout
        found = re.search(r"Lines:\s+\d+ lines,\s+\d+ ignored,\s+(\d+) matched", output)
        if not found or int(found.group(1)) != expected:
            raise base.UpgradeError(
                f"Unexpected fixture result for {log.name}: expected {expected} matches"
            )
    critical = (root / "filters/f2b-exploit-critical.conf").read_text()
    if "/this_is_a_new_hello_world\\.php" not in critical:
        raise base.UpgradeError("Packaged critical filter is missing the hello-world IOC")


def preflight(root: Path, mapping: dict[Path, Path]) -> tuple[dict[str, list[str]], dict]:
    forbidden = {
        Path("/etc/fail2ban/jail.local"),
        Path("/etc/nftables.conf"),
        Path("/var/lib/fail2ban/fail2ban.sqlite3"),
    }
    if forbidden.intersection(mapping) or any(
        target.parent == Path("/etc/fail2ban/filter.d") and target.suffix == ".local"
        for target in mapping
    ):
        raise base.UpgradeError("Canary payload would overwrite local configuration or state")
    base.require_commands(("fail2ban-regex",))
    version = base.run("/usr/local/bin/f2b", "version", "--short").stdout.strip()
    if version != base.RELEASE:
        raise base.UpgradeError(
            f"This updater requires {base.RELEASE!r}, installed wrapper reports {version!r}"
        )
    bans, nft_doc = base.preflight(root, mapping)
    verify_filter_fixtures(root)
    return bans, nft_doc


def verify_canary(root: Path) -> None:
    jails = set(base.parse_jails(base.run("fail2ban-client", "status").stdout))
    if JAIL not in jails:
        raise base.UpgradeError(f"New jail is not active: {JAIL}")
    expected = {"findtime": "30", "maxretry": "3", "bantime": "31536000"}
    for setting, value in expected.items():
        actual = scalar(JAIL, setting)
        if actual != value:
            raise base.UpgradeError(f"{JAIL}.{setting} is {actual!r}, expected {value!r}")

    failregex = base.run("fail2ban-client", "get", "f2b-exploit-critical", "failregex").stdout
    if "this_is_a_new_hello_world" not in failregex:
        raise base.UpgradeError("Effective critical jail is missing the hello-world IOC")

    for set_name in (JAIL, f"{JAIL}-v6"):
        base.run("nft", "list", "set", "inet", "fail2ban-filter", set_name)
    input_chain = base.run("nft", "list", "chain", "inet", "fail2ban-filter", "f2b-input").stdout
    for expression in (f"ip saddr @{JAIL}", f"ip6 saddr @{JAIL}-v6"):
        if expression not in input_chain:
            raise base.UpgradeError(f"Missing {expression!r} in f2b-input")

    actions = base.run("fail2ban-client", "get", JAIL, "actions").stdout
    if "docker-sync-hook" not in actions:
        raise base.UpgradeError(f"{JAIL} does not have the docker-sync-hook action")
    if JAIL not in Path("/usr/local/bin/f2b").read_text(errors="replace"):
        raise base.UpgradeError("Installed wrapper is not aware of the webshell-sweep jail")
    base.run("/usr/local/bin/f2b", "sync", "docker")
    verify_filter_fixtures(root)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--apply", action="store_true", help="apply after a successful preflight")
    mode.add_argument("--rollback", type=Path, metavar="BACKUP", help="restore this tool's backup")
    parser.add_argument("--backup-dir", type=Path, default=Path("/var/backups/f2b-v034-canary"))
    args = parser.parse_args()
    try:
        base.require_root()
        mapping = install_map(ROOT)
        if args.rollback:
            base.rollback(args.rollback, mapping)
            print(f"PASS: rollback restored {args.rollback}")
            return 0
        bans, before_nft = preflight(ROOT, mapping)
        print(
            f"PASS: read-only preflight for {TARGET_CHANGESET}; {len(bans)} jails and "
            f"{sum(map(len, bans.values()))} active bans captured"
        )
        if not args.apply:
            print("No changes made. Re-run with --apply only in the approved canary window.")
            return 0
        backup = base.create_backup(args.backup_dir, bans, before_nft, BACKUP_LABEL)
        print(f"Backup complete: {backup}")
        try:
            base.deploy(mapping)
            base.run("fail2ban-client", "-t")
            base.run("fail2ban-client", "reload")
            verify_canary(ROOT)
            base.verify_after(bans, before_nft)
        except Exception as original:
            try:
                base.rollback(backup, mapping)
            except Exception as rollback_error:
                raise base.UpgradeError(
                    f"Canary update failed: {original}\nAUTOMATIC ROLLBACK ALSO FAILED: "
                    f"{rollback_error}\nBackup: {backup}"
                ) from original
            raise base.UpgradeError(
                f"Canary update failed and was rolled back: {original}\nBackup: {backup}"
            ) from original
        print(f"PASS: v0.34-dev canary updated through {TARGET_CHANGESET}; backup: {backup}")
        print("Docker and nftables services were not restarted. No nftables ruleset was loaded or flushed.")
        return 0
    except (OSError, base.UpgradeError, json.JSONDecodeError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
