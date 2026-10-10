import pathlib
import re
import shutil
import subprocess
import tempfile


ROOT = pathlib.Path(__file__).resolve().parents[1]
FILTER = ROOT / "filters/nginx-php-errors.conf"
MAIL_OVERRIDE = ROOT / "config/php-errors-mail.local"

override = MAIL_OVERRIDE.read_text()
assert 'grepopts="-a -m <grepmax>"' in override

malicious = (
    b'2026/10/08 12:00:00 [error] client: 198.51.100.7, server: app, '
    b'PHP message: shell_exec($_GET["cmd"]), request: "GET / HTTP/1.1"\n'
)
malicious_reverse_order = (
    b'2026/10/08 12:00:00 [error] FastCGI sent in stderr: "PHP message: '
    b'auto_prepend_file=/tmp/payload" while reading response header, '
    b'client: 2001:db8::7, server: app, request: "GET / HTTP/2.0"\n'
)
benign_fatal = (
    b'2026/10/08 12:00:01 [error] client: 198.51.100.8, server: app, '
    b'PHP message: PHP Fatal error: Uncaught TypeError in /srv/app.php:10\n'
)
benign_warning = (
    b'2026/10/08 12:00:02 [error] client: 198.51.100.9, server: app, '
    b'PHP message: PHP Warning: Undefined array key "name" in /srv/app.php:20\n'
)

with tempfile.TemporaryDirectory() as directory:
    log = pathlib.Path(directory) / "error.log"
    log.write_bytes(
        b"binary-prefix\x00\n" + malicious + malicious_reverse_order
        + benign_fatal + benign_warning
    )

    evidence = subprocess.run(
        ["grep", "-a", "-m", "1000", "-wF", "198.51.100.7", str(log)],
        capture_output=True,
        check=True,
    )
    assert malicious.strip() in evidence.stdout

    if shutil.which("fail2ban-regex"):
        checked = subprocess.run(
            ["fail2ban-regex", str(log), str(FILTER), "--print-all-matched",
             "--print-no-missed", "--print-no-ignored"],
            text=True,
            capture_output=True,
            check=True,
        )
        # The CLI normally prints missed lines as well. Restrict evidence to
        # matches and require exactly the two malicious records, so ordinary
        # PHP errors appearing in diagnostics cannot cause false test failures.
        summary = re.search(r"Lines:\s+5 lines,\s+0 ignored,\s+(\d+) matched,\s+(\d+) missed", checked.stdout)
        assert summary and summary.groups() == ("2", "3"), checked.stdout
        assert "198.51.100.7" in checked.stdout
        assert "2001:db8::7" in checked.stdout
        assert "198.51.100.8" not in checked.stdout
        assert "198.51.100.9" not in checked.stdout

print("PASS: binary-safe mail evidence and exploit-only PHP matching")
