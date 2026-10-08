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

upgrade = (ROOT / "scripts/upgrade-v033-v034.py").read_text()
assert 'Path("/etc/fail2ban/jail.local")' not in upgrade.split("def install_map", 1)[1].split("def file_mode", 1)[0]
assert 'Path("/etc/nftables.conf")' not in upgrade.split("def install_map", 1)[1].split("def file_mode", 1)[0]
assert 'run("systemctl", "restart", "docker")' not in upgrade
assert 'run("systemctl", "restart", "nftables")' not in upgrade

main_installer = (ROOT / "INSTALL-ALL-v034.sh").read_text()
assert "Existing installation detected" in main_installer

easy = (ROOT / "scripts/easyappointments-apache-hardening.py").read_text()
assert "easyappointments-apache-hardening.py" not in main_installer
assert 'default=Path("/var/www/html/easyappointments")' in easy
assert 'default="http://127.0.0.1:8080"' in easy
assert 'run("apache2ctl", "configtest")' in easy
assert 'run("systemctl", "reload", "apache2")' in easy
assert "restore_backup(backup)" in easy
assert "harmless hardening test marker" in easy
assert 'Path("/etc/apache2/conf-available")' in easy

storage_hardening = (ROOT / "apache/easyappointments-private-storage.conf").read_text()
assert "Options -Indexes -ExecCGI" in storage_hardening
assert r"php[0-9]*|phtml|phar|cgi|pl|py|sh" in storage_hardening
assert "/assets/vendor" not in storage_hardening

exploit_filter = (ROOT / "filters/f2b-exploit-critical.conf").read_text()
exploit_jail = (ROOT / "config/exploit-critical-rce.local").read_text()
assert exploit_filter.count("ignoreregex =") == 1
assert "%%%%32%%65" in exploit_filter
assert "request:" in exploit_filter
assert "authorized_keys" in exploit_filter
assert "wp_filemanager" in exploit_filter
assert "(?:uploads?|files?|images?)" in exploit_filter
assert "maxretry = 1" in exploit_jail
assert "bantime = 31536000" in exploit_jail
assert "/opt/rustnpm/data/logs/*_error.log tail" in exploit_jail
assert "99-exploit-critical-rce.local" in upgrade
assert "99-exploit-critical-rce.local" in installer

print("PASS: v0.34 static safety and integration checks")
