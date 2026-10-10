import configparser
import datetime
import pathlib
import re
import shutil
import subprocess


ROOT = pathlib.Path(__file__).resolve().parents[1]
FILTER = ROOT / "filters/f2b-webshell-sweep.conf"
JAIL = ROOT / "config/webshell-sweep.local"
ATTACKS = ROOT / "tests/fixtures/webshell-sweep-attacks.log"
BENIGN = ROOT / "tests/fixtures/webshell-sweep-benign.log"
CRITICAL = ROOT / "filters/f2b-exploit-critical.conf"


def load_filter(path):
    parser = configparser.ConfigParser(interpolation=configparser.BasicInterpolation())
    parser.read(path)
    host = r"(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9A-Fa-f:]+)"
    fail = [re.compile(item.replace("<HOST>", host)) for item in parser["Definition"]["failregex"].splitlines() if item]
    ignore = [re.compile(item.replace("<HOST>", host)) for item in parser["Definition"].get("ignoreregex", "").splitlines() if item]
    return fail, ignore


def matching(line, rules):
    fail, ignore = rules
    return not any(item.search(line) for item in ignore) and any(item.search(line) for item in fail)


sweep_rules = load_filter(FILTER)
critical_rules = load_filter(CRITICAL)
attacks = ATTACKS.read_text().splitlines()
benign = BENIGN.read_text().splitlines()
assert len(attacks) == 26
assert all(matching(line, sweep_rules) for line in attacks)
assert not any(matching(line, sweep_rules) for line in benign), [
    line for line in benign if matching(line, sweep_rules)
]

# The exact IOC is one-shot critical for either address family.
hello_v4 = '[10/Oct/2026:12:00:00 +0200] - 404 404 - GET https x "/this_is_a_new_hello_world.php?x=1" [Client 198.51.100.7]'
hello_v6 = '[10/Oct/2026:12:00:01 +0200] - 404 404 - HEAD https x "/this_is_a_new_hello_world.php" [Client 2001:db8::7]'
assert matching(hello_v4, critical_rules)
assert matching(hello_v6, critical_rules)

# The previous precise hellopress IOC remains covered; the legitimate plugin
# path is not a one-shot critical match.
hellopress = '[10/Oct/2026:12:00:02 +0200] - 404 404 - GET https x "/wp-content/plugins/hellopress/wp_filemanager.php" [Client 198.51.100.8]'
legitimate_plugin = '[10/Oct/2026:12:00:03 +0200] - 200 200 - GET https x "/wp-content/plugins/wp-file-manager/file_folder_manager.php" [Client 198.51.100.8]'
unrelated_wp_filemanager = '[10/Oct/2026:12:00:04 +0200] - 404 404 - GET https x "/unrelated/wp_filemanager.php" [Client 198.51.100.8]'
assert matching(hellopress, critical_rules)
assert not matching(legitimate_plugin, critical_rules)
assert not matching(unrelated_wp_filemanager, critical_rules)

jail_parser = configparser.ConfigParser(interpolation=None)
jail_parser.read(JAIL)
jail = jail_parser["f2b-webshell-sweep"]
assert jail.getint("findtime") == 30
assert jail.getint("maxretry") == 3
assert jail.getint("bantime") == 31536000
assert "error" not in jail["logpath"]
for name in ("proxy-host-*_access.log", "fallback_access.log", "fallback_http_access.log", "dead-host_access.log"):
    assert name + " tail" in jail["logpath"]

# Model Fail2Ban's three hits in a 30-second sliding window for both families.
stamp = re.compile(r"^\[(?P<date>\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2}) [^]]+].*\[Client (?P<ip>[^]]+)]")
events = {}
ban_at = {}
for line in [attacks[0], attacks[1], attacks[2], attacks[-3], attacks[-2], attacks[-1]]:
    found = stamp.search(line)
    assert found
    when = datetime.datetime.strptime(found.group("date"), "%d/%b/%Y:%H:%M:%S").timestamp()
    ip = found.group("ip")
    recent = [value for value in events.get(ip, []) if when - value <= 30]
    assert len(recent) < 2 or ip not in ban_at
    recent.append(when)
    events[ip] = recent
    if len(recent) == 3:
        ban_at[ip] = when
assert set(ban_at) == {"20.205.114.149", "2001:db8::149"}

if shutil.which("fail2ban-regex"):
    for fixture, expected in ((ATTACKS, 26), (BENIGN, 0)):
        result = subprocess.run(
            ["fail2ban-regex", str(fixture), str(FILTER)],
            text=True,
            capture_output=True,
            check=True,
        )
        summary = re.search(r"Lines:\s+\d+ lines,\s+\d+ ignored,\s+(\d+) matched", result.stdout)
        assert summary and int(summary.group(1)) == expected, result.stdout

print("PASS: WordPress-safe 404 webshell sweep and one-shot hello-world IOC")
