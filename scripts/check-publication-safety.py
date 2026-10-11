#!/usr/bin/env python3
"""Heuristic publication gate. Reports locations/types, never matched values.

No server-specific denylist. Historical findings require separate remediation;
the normal CI gate scans the current tracked tree, not immutable old commits.
"""
import argparse
import ipaddress
from pathlib import Path
import re
import subprocess
import sys
import tarfile

ROOT = Path(__file__).resolve().parents[1]
DOC_NETS = tuple(ipaddress.ip_network(value) for value in (
    "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32"))
IP4 = re.compile(r"(?<![\w.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![\w.])")
IP6 = re.compile(r"(?<![\w:])(?:[0-9a-fA-F]{0,4}:){2,}[0-9a-fA-F:.]*(?![\w:])")
DOMAIN = re.compile(r"(?<![\w.-])(?:[A-Za-z0-9-]+\.)+(?:com|net|org|io|dev|sk|eu|cloud|app|invalid|test|local)\b", re.I)
# Public software/documentation providers, not private deployment endpoints.
PUBLIC_PROVIDERS = ("github.com", "githubusercontent.com", "github.io", "shields.io",
    "nginxproxymanager.com", "fail2ban.org", "python.org", "debian.org", "ubuntu.com",
    "netfilter.org", "nftables.org", "opensource.org", "spdx.org", "gnu.org",
    "docker.com", "docker.io", "readthedocs.io", "letsencrypt.org", "ietf.org", "buymeacoffee.com")
PATTERNS = {
    "private-key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    "credential-token": re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|AKIA[A-Z0-9]{16})\b"),
    "private-home-path": re.compile(r"/(?:Users|home)/(?!USER\b|user\b|example\b|runner\b|<)[A-Za-z0-9_.-]+/"),
    "deployment-backup-path": re.compile(r"/var/backups/[A-Za-z0-9_./-]*20[0-9]{6}-[0-9]{6}"),
    "literal-deployment-hash-map": re.compile(r'''["']/((?:etc|usr/local)/[^"']+)["']\s*:\s*\[?["'][0-9a-f]{64}["']'''),
}


def findings(text, label):
    result = []
    if re.search(r"(?:^|/)v0\.40(?:-dev)?/", label):
        result.append((label, 1, "local-only-development-version"))
    for number, line in enumerate(text.splitlines(), 1):
        kinds = {kind for kind, pattern in PATTERNS.items() if pattern.search(line)}
        for pattern in (IP4, IP6):
            for match in pattern.finditer(line):
                try: address = ipaddress.ip_address(match[0])
                except ValueError: continue
                documented = any(address.version == net.version and address in net for net in DOC_NETS)
                if address.is_global and not documented: kinds.add("non-documentation-public-IP")
        for match in DOMAIN.finditer(line):
            domain = match[0].lower()
            allowed = (domain in {"example.com", "example.net", "example.org"} or
                domain.endswith((".invalid", ".test", ".local", ".example.com", ".example.net", ".example.org")) or
                any(domain == provider or domain.endswith("." + provider) for provider in PUBLIC_PROVIDERS))
            if not allowed: kinds.add("non-example-domain-review")
        for kind in sorted(kinds): result.append((label, number, kind))
    return result


def git(*args):
    return subprocess.check_output(["git", "-C", str(ROOT), *args])


def decode(data):
    if b"\0" in data: return None
    try: return data.decode("utf-8")
    except UnicodeError: return None


def tracked(staged=False):
    if staged:
        paths = git("diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z").decode().split("\0")
    else: paths = git("ls-files", "-z").decode().split("\0")
    for name in paths:
        if not name: continue
        if staged: data = git("show", ":" + name)
        else:
            path = ROOT / name
            if not path.is_file() or path.is_symlink(): continue
            data = path.read_bytes()
        text = decode(data)
        if text is not None: yield name, text


def history():
    objects = git("rev-list", "--objects", "--all").decode().splitlines()
    # One batch process avoids a command per blob. Read only; no Git rewriting.
    process = subprocess.Popen(["git", "-C", str(ROOT), "cat-file", "--batch"], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    try:
        for entry in objects:
            oid, _, name = entry.partition(" ")
            if not name: continue
            process.stdin.write((oid + "\n").encode()); process.stdin.flush()
            header = process.stdout.readline().decode().split()
            data = process.stdout.read(int(header[2])); process.stdout.read(1)
            if header[1] != "blob": continue
            text = decode(data)
            if text is not None: yield "history:" + oid[:12] + ":" + name, text
    finally:
        process.stdin.close(); process.stdout.close(); process.wait()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--staged", action="store_true")
    mode.add_argument("--history", action="store_true")
    mode.add_argument("--archive", type=Path)
    mode.add_argument("--stdin-label", help="scan PR/API/log text from stdin without echoing it")
    parser.add_argument("--report-limit", type=int, default=80)
    args = parser.parse_args()
    if args.stdin_label: records = [(args.stdin_label, sys.stdin.read())]
    elif args.history: records = history()
    elif args.archive:
        records = []
        with tarfile.open(args.archive) as archive:
            for member in archive.getmembers():
                if not member.isfile(): continue
                text = decode(archive.extractfile(member).read())
                if text is not None: records.append(("archive:" + member.name, text))
    else: records = tracked(args.staged)
    results = [hit for name, text in records for hit in findings(text, name)]
    for name, number, kind in results[:args.report_limit]: print(f"{name}:{number}: {kind}")
    print(f"Publication safety: {len(results)} location/type findings (values suppressed)")
    return 1 if results else 0


if __name__ == "__main__":
    raise SystemExit(main())
