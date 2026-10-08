import importlib.util
import pathlib
import subprocess
import sys
import tempfile


ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/f2b-report-filter.py"
spec = importlib.util.spec_from_file_location("report_filter", SCRIPT)
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)


trusted = (
    '[08/Oct/2026:12:00:00 +0200] - 404 404 - GET https '
    'rustdesk.example.invalid "/api/heartbeat" [Client 192.0.2.10] "RustDesk" "-"\n'
)
wrong_source = trusted.replace("192.0.2.10", "192.0.2.11")
wrong_host = trusted.replace("rustdesk.example.invalid", "other.example.invalid")
wrong_method = trusted.replace(" GET ", " POST ")
wrong_status = trusted.replace(" 404 404 ", " 200 200 ")
exploit = trusted.replace(
    '"/api/heartbeat"', '"/api/heartbeat?cmd=cat+/etc/passwd"'
)
ipv6_trusted = trusted.replace("192.0.2.10", "2001:db8::10")

with tempfile.TemporaryDirectory() as directory:
    config = pathlib.Path(directory) / "reporting.ini"
    config.write_text(
        '[trusted-probe "rustdesk-v4"]\n'
        'source = 192.0.2.10/32\nmethod = GET\n'
        'host = rustdesk.example.invalid\nstatus = 404\n'
        'paths = /api/heartbeat, /api/sysinfo, /api/audit/conn\n\n'
        '[trusted-probe "rustdesk-v6"]\n'
        'source = 2001:db8::/64\nmethod = GET\n'
        'host = rustdesk.example.invalid\nstatus = 404\n'
        'paths = /api/heartbeat\n'
    )
    payload = trusted + ipv6_trusted + wrong_source + wrong_host + wrong_method + wrong_status + exploit
    result = subprocess.run(
        [str(SCRIPT), "--config", str(config)],
        input=payload,
        text=True,
        capture_output=True,
        check=True,
    )
    assert trusted not in result.stdout
    assert ipv6_trusted not in result.stdout
    for line in (wrong_source, wrong_host, wrong_method, wrong_status, exploit):
        assert line in result.stdout

    missing_config = pathlib.Path(directory) / "missing.ini"
    passthrough = subprocess.run(
        [str(SCRIPT), "--config", str(missing_config)],
        input=trusted,
        text=True,
        capture_output=True,
        check=True,
    )
    assert passthrough.stdout == trusted

print("PASS: reporting exclusions require source, method, host, status and safe exact path")
