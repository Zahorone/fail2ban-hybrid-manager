import pathlib
import re


ROOT = pathlib.Path(__file__).resolve().parents[1]

for path in list((ROOT / "scripts").glob("*.sh")) + [ROOT / "INSTALL-ALL-v034.sh"]:
    source = path.read_text()
    assert not re.search(r"^\s*flush\s+ruleset(?:\s|$)", source, re.MULTILINE), path
    assert not re.search(
        r"^\s*flush\s+table\s+inet\s+(?:fail2ban-filter|docker-block)(?:\s|$)",
        source,
        re.MULTILINE,
    ), path

multiport = (ROOT / "actions/nftables-multiport.conf").read_text()
assert "before = nftables.conf" in multiport
assert "type = multiport" in multiport
assert "actionban" not in multiport

common = (ROOT / "actions/nftables-common.local").read_text()
assert "[Init?family=inet6]" in common
assert "addr_set = f2b-<name>-v6" in common

jail = (ROOT / "config/jail.local").read_text()
assert "188.121.168.64" not in jail

installer = (ROOT / "scripts/02-install-jails-v034.sh").read_text()
assert "99-php-errors-mail.local" in installer
assert "99-recidive-mail.local" in installer
assert "jail.local.v034-dist" in installer
assert "Existing jail.local preserved" in installer

wrapper = (ROOT / "scripts/f2b-wrapper-v034.sh").read_text()
assert wrapper.count("filter_npm_report_logs") >= 3
assert 'grep -v "172.18.0.1"' not in wrapper
assert "404 (scanner probes)" not in wrapper
assert "Active attack in progress" not in wrapper

print("PASS: v0.34 static safety and integration checks")
