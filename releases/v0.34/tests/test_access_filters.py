"""Strict NPM access fields: benign apps/statuses/UA vs bounded attack probes."""
import configparser
import importlib.util
import itertools
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("access_upgrade", ROOT / "scripts/upgrade-v033-v034.py")
upgrade = importlib.util.module_from_spec(spec)
spec.loader.exec_module(upgrade)
FILTERS = {"f2b-botnet-signatures": "f2b-botnet-signatures", "f2b-fuzzing-payloads": "f2b-fuzzing-payloads",
           "f2b-web-medium": "f2b-web-medium", "nginx-recon-bonus": "nginx-recon-optimized"}
commands, cases = [], {jail: [[], []] for jail in FILTERS}
for jail, name in FILTERS.items():
    parser = configparser.ConfigParser()
    parser.read(ROOT / "filters" / (name + ".conf"))
    for key in ("failregex", "ignoreregex"):
        commands.append(["multi-set", jail, "add" + key, [line for line in parser["Definition"][key].splitlines() if line.strip()]])
assert not upgrade.access_filter_contract_conflicts(commands)
assert not upgrade.access_filter_contract_conflicts([])  # do not enable intentionally disabled optional jails


def log(target="/", host="192.0.2.7", status=404, method="GET", ua="Mozilla/5.0", referer="-", proxy=True):
    fields = f"- {status} {status}" if proxy else str(status)
    sent = " [Sent-to backend.example.invalid]" if proxy else ""
    return (f'[11/Oct/2026:12:00:00 +0000] {fields} - {method} https app.example.invalid "{target}" '
            f'[Client {host}] [Length 10] [Gzip -]{sent} "{ua}" "{referer}"')


for jail, target, status, method, ua, expected in upgrade.access_filter_contract_cases():
    for host, proxy in itertools.product(("192.0.2.7", "2001:db8::7"), (True, False)):
        cases[jail][0 if expected else 1].append(log(target, host, status, method, ua, proxy=proxy))
for host, proxy in itertools.product(("192.0.2.7", "2001:db8::7"), (True, False)):
    for tool in ("Masscan/1.0", "zgrab/0.x", "gobuster/3.0", "dirbuster", "feroxbuster/2.0", "wpscan/3.8", "acunetix", "nessus", "MtmKilledYou"):
        cases["f2b-botnet-signatures"][0].append(log(host=host, ua=tool, proxy=proxy))
    for ua in ("Googlebot/2.1", "bingbot/2.0", "OAI-SearchBot/1.0", "crawler", "spider", "UptimeRobot/2.0", "my-nikto-docs-client"):
        # Exact tool tokens, not substrings of a custom identifier.
        cases["f2b-botnet-signatures"][1].append(log(host=host, ua=ua, proxy=proxy))
    cases["f2b-botnet-signatures"][1] += [log("/sqlmap/nikto/nuclei", host, proxy=proxy),
        log(host=host, referer="https://docs.example.invalid/sqlmap", proxy=proxy)]
    for target in ("/a%2eb", "/a%2fb", "/a%252fb", "/search?q=100%25", "/index.php?q=hello%20world", "/[hello.world]", "/~"):
        cases["f2b-fuzzing-payloads"][1].append(log(target, host, proxy=proxy))
    for target in ("/backup/.svn/entries", "/.npmrc", "/composer.lock", "/package-lock.json", "/yarn.lock", "/settings.php.bak"):
        cases["nginx-recon-bonus"][0].append(log(target, host, proxy=proxy))
    cases["nginx-recon-bonus"][1].append(log("/.well-known/acme-challenge/composer.lock", host, proxy=proxy))
    for jail in FILTERS:
        cases[jail][1].append(log("/news", host, referer="https://docs.example.invalid/.git/config", proxy=proxy))
        cases[jail][1].append(f'2026/10/11 12:00:00 [error] limiting requests, excess: 1 by zone "api", client: {host}, request: "GET / HTTP/1.1"')

executable = shutil.which("fail2ban-regex")
assert executable or "--require-fail2ban" not in sys.argv, "CI requires real fail2ban-regex"
with tempfile.TemporaryDirectory(prefix="f2b-access-regression-") as directory:
    for jail, name in FILTERS.items():
        fail = [re.compile(value.replace("<HOST>", r"(?:[0-9.]+|[0-9A-Fa-f:]+)")) for cmd in commands if cmd[1:3] == [jail, "addfailregex"] for value in cmd[3]]
        ignore = [re.compile(value.replace("<HOST>", r"(?:[0-9.]+|[0-9A-Fa-f:]+)")) for cmd in commands if cmd[1:3] == [jail, "addignoreregex"] for value in cmd[3]]
        def matches(line):
            return any(p.search(line) for p in fail) and not any(p.search(line) for p in ignore)
        for index, label in enumerate(("attacks", "benign")):
            lines = cases[jail][index]
            assert all(matches(line) == (index == 0) for line in lines), [line for line in lines if matches(line) != (index == 0)]
            if executable:
                fixture = Path(directory) / (name + "-" + label + ".log")
                fixture.write_text("\n".join(lines) + "\n")
                output = subprocess.run([executable, str(fixture), str(ROOT / "filters" / (name + ".conf"))],
                                        check=True, capture_output=True, text=True).stdout
                summary = re.search(r"Lines:\s+\d+ lines,\s+\d+ ignored,\s+(\d+) matched", output)
                assert summary and int(summary[1]) == (len(lines) if index == 0 else 0), output
        print(f"PASS: {name}: {len(cases[jail][0])} attacks, {len(cases[jail][1])} benign; real regex={bool(executable)}")

# Effective overrides cannot silently reinstate historical blanket matching.
for jail in FILTERS:
    broad = [command if command[1:3] != [jail, "addfailregex"] else [*command[:3], [r'^.*\[Client <HOST>\]']]
             for command in commands]
    assert upgrade.access_filter_contract_conflicts(broad)
