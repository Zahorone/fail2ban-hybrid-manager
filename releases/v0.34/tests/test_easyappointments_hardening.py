import importlib.util
import json
import pathlib
import sys
import tempfile


ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "easyappointments_hardening",
    ROOT / "scripts" / "easyappointments-apache-hardening.py",
)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def layout(root: pathlib.Path) -> None:
    (root / "vendor").mkdir(parents=True)
    for name in (*MODULE.PRIVATE_DIRS, "uploads"):
        (root / "storage" / name).mkdir(parents=True)


with tempfile.TemporaryDirectory() as raw:
    base = pathlib.Path(raw)
    app = base / "easyappointments"
    available = base / "available"
    enabled = base / "enabled"
    backups = base / "backups"
    available.mkdir()
    enabled.mkdir()
    layout(app)

    MODULE.check_layout(app)
    MODULE.check_managed_scope(app, available, enabled)
    MODULE.install(app, available, enabled)
    MODULE.check_managed_scope(app, available, enabled)

    vendor = (available / MODULE.NAMES[0]).read_text()
    storage = (available / MODULE.NAMES[1]).read_text()
    assert f'<Directory "{app}/vendor">' in vendor
    assert "/assets/vendor" not in vendor
    assert "AllowOverride None" in vendor
    assert "Require all denied" in vendor
    assert f'<Directory "{app}/storage/uploads">' in storage
    assert "Options -Indexes -ExecCGI" in storage
    assert r"php[0-9]*|phtml|phar|cgi|pl|py|sh" in storage
    assert r"(?:\.|$)" in storage

    backup = MODULE.make_backup(available, enabled, backups)
    manifest = json.loads((backup / "manifest.json").read_text())
    assert manifest["version"] == 1
    assert len(manifest["entries"]) == 4
    (available / MODULE.NAMES[0]).write_text("changed\n")
    (enabled / MODULE.NAMES[0]).unlink()
    MODULE.restore_backup(backup, configtest=False, reload_apache=False)
    assert (available / MODULE.NAMES[0]).read_text() == vendor
    assert (enabled / MODULE.NAMES[0]).is_symlink()

    (available / MODULE.NAMES[0]).write_text("foreign configuration\n")
    try:
        MODULE.check_managed_scope(app, available, enabled)
    except RuntimeError as error:
        assert "unknown configuration" in str(error)
    else:
        raise AssertionError("foreign Apache config was accepted")

    (available / MODULE.NAMES[0]).write_bytes(MODULE.render(MODULE.NAMES[0], app))
    (app / "storage" / "uploads" / ".htaccess").write_text("deny from all\n")
    try:
        MODULE.check_layout(app)
    except RuntimeError as error:
        assert "upload policy" in str(error)
    else:
        raise AssertionError("upload .htaccess was accepted")

    (app / "storage" / "uploads" / ".htaccess").unlink()
    statuses = {
        "/": 200,
        "/index.php/login": 200,
        "/assets/vendor/jquery/jquery.min.js": 200,
    }
    original_http_status = MODULE.http_status
    MODULE.http_status = lambda _base, path: statuses.get(path, 200)
    probes = MODULE.prepare_http_probes(app, "http://127.0.0.1:8080")
    assert all(path.exists() for path in probes.created)
    MODULE.cleanup_http_probes(probes.created)
    assert all(not path.exists() for path in probes.created)
    MODULE.http_status = original_http_status

assert MODULE.validate_backend_url("http://127.0.0.1:8080") == "http://127.0.0.1:8080"
for unsafe in ("https://127.0.0.1:8080", "http://example.com:8080", "http://127.0.0.1:80/path"):
    try:
        MODULE.validate_backend_url(unsafe)
    except ValueError:
        pass
    else:
        raise AssertionError(f"unsafe backend URL accepted: {unsafe}")

print("PASS: optional Easy!Appointments Apache hardening tests")
