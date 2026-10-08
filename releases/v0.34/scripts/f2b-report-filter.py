#!/usr/bin/env python3
"""Remove explicitly trusted service probes from reporting, never from bans."""

from __future__ import annotations

import argparse
import configparser
import ipaddress
import re
import sys
from dataclasses import dataclass
from pathlib import Path


CLIENT_RE = re.compile(r"\[Client (?P<ip>[0-9A-Fa-f:.]+)\]")
REQUEST_RE = re.compile(
    r"\b(?P<method>GET|HEAD|POST|PUT|PATCH|DELETE|OPTIONS)\s+"
    r"(?P<scheme>https?|wss?)\s+(?P<host>[^\s\"]+)\s+\"(?P<path>[^\"]*)\"",
    re.IGNORECASE,
)
STATUS_RE = re.compile(
    r"\s(?P<status>[1-5][0-9]{2})(?:\s+[1-5][0-9]{2})?\s+-\s+"
    r"(?:GET|HEAD|POST|PUT|PATCH|DELETE|OPTIONS)\s+",
    re.IGNORECASE,
)
DANGEROUS_RE = re.compile(
    r"(?:\.\./|%2e%2e|union(?:\s|%20)+select|/\.git(?:/|$)|"
    r"auto_prepend_file|allow_url_include|base64_decode|shell_exec|"
    r"(?:^|[?&])(?:cmd|exec|system)=)",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class ProbeRule:
    network: ipaddress.IPv4Network | ipaddress.IPv6Network
    method: str
    host: str
    status: int
    paths: frozenset[str]

    def matches(self, line: str) -> bool:
        if DANGEROUS_RE.search(line):
            return False
        client = CLIENT_RE.search(line)
        request = REQUEST_RE.search(line)
        status = STATUS_RE.search(line)
        if not (client and request and status):
            return False
        try:
            source = ipaddress.ip_address(client.group("ip"))
        except ValueError:
            return False
        return (
            source in self.network
            and request.group("method").upper() == self.method
            and request.group("host").rstrip(".").lower() == self.host
            and int(status.group("status")) == self.status
            and request.group("path") in self.paths
        )


def load_rules(path: Path) -> list[ProbeRule]:
    if not path.is_file():
        return []
    parser = configparser.ConfigParser(interpolation=None)
    parser.read(path)
    rules: list[ProbeRule] = []
    for section in parser.sections():
        if not section.lower().startswith("trusted-probe"):
            continue
        required = {"source", "method", "host", "status", "paths"}
        missing = required.difference(parser[section])
        if missing:
            raise ValueError(f"{section}: missing {', '.join(sorted(missing))}")
        network = ipaddress.ip_network(parser[section]["source"], strict=False)
        method = parser[section]["method"].strip().upper()
        host = parser[section]["host"].strip().rstrip(".").lower()
        status = int(parser[section]["status"])
        paths = frozenset(
            item.strip() for item in parser[section]["paths"].split(",") if item.strip()
        )
        if not host or not paths or method not in {
            "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"
        } or not 100 <= status <= 599:
            raise ValueError(f"{section}: invalid method, host, status, or paths")
        rules.append(ProbeRule(network, method, host, status, paths))
    return rules


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default="/etc/f2b/reporting.ini")
    args = parser.parse_args()
    try:
        rules = load_rules(Path(args.config))
    except (OSError, ValueError, configparser.Error) as exc:
        print(f"f2b-report-filter: {exc}", file=sys.stderr)
        return 2
    for line in sys.stdin:
        if not any(rule.matches(line) for rule in rules):
            sys.stdout.write(line)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
