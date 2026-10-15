"""Full file transaction with real Fail2Ban/nft, PRIVATE mount/net namespaces.

systemd/cron are deliberately simulated: this is NOT a VM/reboot test.
"""
import hashlib
import contextlib
import io
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import time
import sys
import re
import sqlite3
import datetime as dt
from scan_review_fixture import overrides
from unittest.mock import patch

# Importing the archived updater for fault injection must not add a .pyc to
# the immutable package inventory before its own bytecode policy takes effect.
sys.dont_write_bytecode = True

REPO = Path(__file__).resolve().parents[3]


def run(*args, check=True):
    result = subprocess.run(args, check=False, text=True, capture_output=True)
    if check and result.returncode:
        raise AssertionError(f'{args}:\n{result.stdout}\n{result.stderr}')
    return result


def wait(predicate):
    for _ in range(150):
        if predicate(): return
        time.sleep(.1)
    raise AssertionError('Timed out waiting for real daemon')


run('mount', '--make-rprivate', '/')
run('mount', '-t', 'tmpfs', 'tmpfs', '/run')
Path('/run/lock').mkdir()
with tempfile.TemporaryDirectory(prefix='f2b-full-upgrade-') as temporary:
    temporary = Path(temporary)
    with tarfile.open('/tmp/f2b-complete-upgrade.tar.gz') as archive:
        archive.extractall(temporary / 'package')
    package = next((temporary / 'package').iterdir())
    script = package / 'scripts/upgrade-v033-v034.py'
    legacy = REPO / 'releases/v0.33'
    if '--pristine' in sys.argv:
        data = subprocess.check_output(['git', '-C', str(REPO), 'archive', 'a88bacb', 'releases/v0.33'])
        with tarfile.open(fileobj=io.BytesIO(data)) as archive:
            archive.extractall(temporary / 'pristine')
        legacy = temporary / 'pristine/releases/v0.33'
    private_etc = temporary / 'private-etc'
    shutil.copytree('/etc', private_etc, symlinks=True)
    run('mount', '--bind', str(private_etc), '/etc')
    # Clone just fixture-owned paths and bind them privately, never the host.
    bind_targets = ('/etc/fail2ban', '/etc/nftables.d', '/etc/cron.d', '/etc/systemd/system',
                    '/usr/local', '/etc/f2b', '/var/lib/fail2ban', '/var/log', '/opt/rustnpm/data/logs')
    for name in bind_targets:
        target = Path(name)
        clone = temporary / 'root' / target.relative_to('/')
        clone.mkdir(parents=True)
        if name == '/etc/fail2ban': shutil.copytree(target, clone, dirs_exist_ok=True)
        target.mkdir(parents=True, exist_ok=True)
        run('mount', '--bind', str(clone), name)
    for name in ('bin', 'sbin', 'libexec'): (Path('/usr/local') / name).mkdir()
    for source in (legacy / 'filters').glob('*.conf'):
        shutil.copy2(source, Path('/etc/fail2ban/filter.d') / source.name)
    for source in (legacy / 'actions').iterdir():
        shutil.copy2(source, Path('/etc/fail2ban/action.d') / source.name)
    shutil.copy2(legacy / 'config/jail.local', '/etc/fail2ban/jail.local')
    shutil.copy2(legacy / 'scripts/f2b-wrapper-v033.sh', '/usr/local/bin/f2b')
    shutil.copy2(legacy / 'scripts/f2b-docker-hook.sh', '/usr/local/sbin/f2b-docker-hook')
    Path('/usr/local/bin/f2b').chmod(0o755)
    Path('/usr/local/sbin/f2b-docker-hook').chmod(0o755)
    # Synthetic, independent site override must survive every transaction.
    site = Path('/etc/fail2ban/filter.d/site-preserved.local')
    site.write_text('[Definition]\n# namespace fixture only\n')
    whitelist = Path('/etc/fail2ban/jail.d/98-synthetic-whitelist.local')
    whitelist.write_text('[DEFAULT]\nignoreip = 127.0.0.0/8 ::1 192.0.2.123 2001:db8::123\n[manualblock]\nbantime = 7200\n')
    whitelist_before = whitelist.read_bytes()
    reporting_config = Path('/etc/f2b/reporting.ini')
    reporting_config.write_text('[reporting]\nfail2ban_timezone = UTC\nsample_limit = 10\n')
    reporting_before = reporting_config.read_bytes()
    is_dev = '--v034dev' in sys.argv
    if is_dev:
        spec = importlib.util.spec_from_file_location('baseline_v034', script)
        baseline = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(baseline)
        for target, source in baseline.install_map(package).items():
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
            target.chmod(baseline.file_mode(target))
    preserved_overrides = {}
    if '--scan-review' in sys.argv:
        for name, contents in overrides(REPO / 'releases/v0.34').items():
            path = Path('/etc/fail2ban/filter.d') / name
            path.write_text(contents)
            preserved_overrides[path] = path.read_bytes()
    apache = Path('/etc/apache2/conf-available/easyappointments-private-config.conf')
    apache.parent.mkdir(parents=True, exist_ok=True)
    apache.write_bytes((REPO / 'releases/v0.34/apache/easyappointments-private-config.conf').read_bytes())
    apache_link = Path('/etc/apache2/conf-enabled/easyappointments-private-config.conf')
    apache_link.parent.mkdir(parents=True, exist_ok=True)
    apache_link.symlink_to(apache)
    apache_before = apache.read_bytes()

    saved_expiry = {}
    def assert_site_protections():
        for (family, name), contents in foreign_additional.items():
            assert run('nft', '-s', 'list', 'table', family, name).stdout == contents
        if saved_expiry:
            records = json.loads(run('/usr/bin/python3', str(package / 'scripts/f2b-ipv6-sync.py'), 'export').stdout)['manualblock']
            ends = {line.split()[0]: dt.datetime.strptime(line.rsplit(' = ', 1)[1], '%Y-%m-%d %H:%M:%S').timestamp() for line in records}
            assert all(address in ends and abs(ends[address] - expiry) <= 2 for address, expiry in saved_expiry.items()), 'Ban expiry reset/shortened'
        assert whitelist.read_bytes() == whitelist_before
        assert reporting_config.read_bytes() == reporting_before
        database = Path('/var/lib/fail2ban/fail2ban.sqlite3')
        if database.exists():
            # sqlite's context manager ends a transaction; it does NOT close
            # the handle, which otherwise pins our private DB mount at cleanup.
            with contextlib.closing(sqlite3.connect('file:' + str(database) + '?mode=ro', uri=True)) as connection:
                assert connection.execute('PRAGMA integrity_check').fetchone()[0] == 'ok'
        assert all(path.read_bytes() == contents for path, contents in preserved_overrides.items())
        assert apache.read_bytes() == apache_before and apache_link.is_symlink() and apache_link.resolve() == apache
        if not preserved_overrides: return
        for name, rows, count in (
            ('f2b-exploit-critical', [('/.aws/credentials.bak', 404), ('/userfiles?path=../../proc/self/environ', 404),
                                     ('/this_is_a_new_hello_world.php', 301), ('/search?q=../../.env', 404)], 6),
            ('f2b-webshell-sweep', [('/blog/wp-login.php', 404), ('/tenant/a/wp-admin/admin-ajax.php', 404),
                                  ('/blog/not-wp-login.php', 404), ('/wp-content/plugins/evil/payload.phtml', 404)], 4),
        ):
            # terminy-like rollback has no sweep jail/filter; the preserved .local
            # remains ready for a later managed sweep installation.
            filter_path = Path('/etc/fail2ban/filter.d') / (name + '.conf')
            if not filter_path.exists(): continue
            lines = [f'[11/Oct/2026:10:00:00 +0000] - {status} {status} - GET https example.invalid "{target}" [Client {ip}]'
                     for target, status in rows for ip in ('192.0.2.7', '2001:db8::7')]
            fixture = temporary / (name + '.log')
            fixture.write_text('\n'.join(lines) + '\n')
            output = run('fail2ban-regex', str(fixture), str(filter_path)).stdout
            matched = re.search(r'Lines:\s+\d+ lines,\s+\d+ ignored,\s+(\d+) matched', output)
            assert matched and int(matched[1]) == count, output
    original_jail = Path('/etc/fail2ban/jail.local').read_bytes()
    private_review = temporary / 'synthetic-private-review.json'
    reviewed_original = None
    if '--local-review-fixture' in sys.argv:
        target = Path('/etc/fail2ban/filter.d/nginx-recon-optimized.conf')
        target.write_bytes(target.read_bytes() + b'\n# synthetic installation-specific comment\n')
        reviewed_original = target.read_bytes()
        private_review.write_text(json.dumps({'schema': 1, 'reviewed': True,
            'package_commit': json.loads((package / 'UPGRADE-MANIFEST.json').read_text())['source_commit'],
            'targets': {str(target): hashlib.sha256(target.read_bytes()).hexdigest()}}))
        private_review.chmod(0o600)
    for name in ('auth.log', 'fail2ban.log', 'fail2ban-blocked-ips.txt'):
        (Path('/var/log') / name).touch()
    for name in ('fallback_access.log', 'fallback_http_access.log', 'dead-host_access.log',
                 'proxy-host-1_access.log', 'fallback_error.log', 'proxy-host-1_error.log'):
        (Path('/opt/rustnpm/data/logs') / name).touch()
    nft_config = Path('/etc/nftables.conf')
    nft_config.write_text('flush ruleset\ninclude "/etc/nftables.d/fail2ban-filter.nft"\ninclude "/etc/nftables.d/docker-block.nft"\n')
    # Executable stubs model only daemon lifecycle/cron availability. No real
    # host service is stopped, started or daemon-reloaded in this namespace.
    stubs = temporary / 'bin'
    stubs.mkdir()
    systemctl = stubs / 'systemctl'
    systemctl.write_text('#!/bin/sh\ncase "$*" in\n'
        'show*--property=UnitFileState*) echo enabled;;\n'
        'show*--property=NeedDaemonReload*) echo no;;\n'
        'show*--property=ActiveState*) echo active;;\n'
        'show*--property=Requires*|show*--property=After*) echo nftables.service;;\n'
        'show*--property=ExecStart*) echo "/usr/sbin/nft -f /etc/nftables.conf";;\n'
        '"stop fail2ban") exec fail2ban-client stop;;\n'
        '"start fail2ban") (sleep 1; fail2ban-client -x start) >/dev/null 2>&1 & exit 0;;\n'
        '"daemon-reload"|"is-active --quiet cron") exit 0;;\n'
        '"is-active fail2ban nftables docker") printf "active\\nactive\\nactive\\n";;\n'
        '*) echo "Forbidden systemctl: $*" >&2; exit 99;;\nesac\n')
    cron = stubs / 'crontab'
    cron.write_text('#!/bin/sh\n[ "$1" = -l ] || exit 99\n# no original root cron in fixture\nexit 0\n')
    for path in stubs.iterdir(): path.chmod(0o755)
    import os
    os.environ['PATH'] = str(stubs) + ':' + os.environ['PATH']
    # Real foreign NAT sentinel and owned legacy tables, including IPv6 hooks.
    run('nft', 'add', 'table', 'ip', 'foreign-nat')
    run('nft', 'add', 'chain', 'ip', 'foreign-nat', 'prerouting', '{ type nat hook prerouting priority dstnat; }')
    run('nft', 'add', 'rule', 'ip', 'foreign-nat', 'prerouting', 'tcp', 'dport', '8080', 'dnat', 'to', '192.0.2.90:80')
    foreign = run('nft', '-s', 'list', 'table', 'ip', 'foreign-nat').stdout
    for family, name in (('ip', 'DOCKER'), ('inet', 'synthetic-ufw')):
        run('nft', 'add', 'table', family, name)
        run('nft', 'add', 'chain', family, name, 'sentinel')
        run('nft', 'add', 'rule', family, name, 'sentinel', 'tcp', 'dport', '12345', 'accept')
    foreign_additional = {(family, name): run('nft', '-s', 'list', 'table', family, name).stdout
                          for family, name in (('ip', 'DOCKER'), ('inet', 'synthetic-ufw'))}
    for table, names in (('fail2ban-filter', ('f2b-recidive', 'f2b-recidive-v6')),
                         ('docker-block', ('docker-banned-ipv4', 'docker-banned-ipv6'))):
        run('nft', 'add', 'table', 'inet', table)
        for name in names:
            kind = 'ipv6_addr' if name.endswith(('ipv6', '-v6')) else 'ipv4_addr'
            run('nft', 'add', 'set', 'inet', table, name, '{ type ' + kind + '; flags interval,timeout; auto-merge; timeout 30d; }')
    for chain, hook in (('f2b-input', 'input'), ('f2b-forward', 'forward')):
        run('nft', 'add', 'chain', 'inet', 'fail2ban-filter', chain, '{ type filter hook ' + hook + ' priority -100; }')
        for family, name in (('ip', 'f2b-recidive'), ('ip6', 'f2b-recidive-v6')):
            run('nft', 'add', 'rule', 'inet', 'fail2ban-filter', chain, family, 'saddr', '@' + name, 'drop')
    run('nft', 'add', 'chain', 'inet', 'docker-block', 'prerouting', '{ type filter hook prerouting priority -110; }')
    for family, name in (('ip', 'docker-banned-ipv4'), ('ip6', 'docker-banned-ipv6')):
        run('nft', 'add', 'rule', 'inet', 'docker-block', 'prerouting', family, 'saddr', '@' + name, 'drop')
    try:
        if '--pristine' in sys.argv:
            # The historical release itself has a known unescaped-% PHP filter
            # and cannot start on 1.0.2. Do not pretend it is a working baseline.
            current = run('fail2ban-client', '-t', check=False)
            assert current.returncode != 0 and "'%' must be followed" in current.stderr
            spec = importlib.util.spec_from_file_location('pristine_upgrade', script)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            mapping = module.install_map(package)
            module.validate_package(package, mapping)
            module.audit_targets(package, mapping)
            module.validate_candidate(package, mapping)
            refused = run('/usr/bin/python3', str(script), check=False)
            assert refused.returncode != 0 and 'cannot be restarted safely for rollback' in refused.stderr
            assert Path('/etc/fail2ban/jail.local').read_bytes() == original_jail
            print('PASS: original v0.33 percent-format bug is fail-closed; complete merged upgrade configuration is valid; no successful pristine runtime upgrade claimed')
            sys.exit(0)
        run('fail2ban-client', '-x', 'start')
        wait(lambda: run('fail2ban-client', 'ping', check=False).returncode == 0)
        for ip in ('192.0.2.8', '2001:db8::8'):
            run('fail2ban-client', 'set', 'manualblock', 'banip', ip)
        wait(lambda: '2001:db8::8' in run('fail2ban-client', 'get', 'manualblock', 'banip').stdout)
        records = json.loads(run('/usr/bin/python3', str(package / 'scripts/f2b-ipv6-sync.py'), 'export').stdout)['manualblock']
        saved_expiry.update({line.split()[0]: dt.datetime.strptime(line.rsplit(' = ', 1)[1], '%Y-%m-%d %H:%M:%S').timestamp() for line in records})
        command = ['/usr/bin/python3', str(script)]
        if '--local-review-fixture' in sys.argv:
            refused = run(*command, check=False)
            assert refused.returncode != 0 and 'unknown local contents' in refused.stderr
            command += ['--local-review', str(private_review)]
        managed = Path('/usr/local/bin/f2b'); original_managed = managed.read_bytes()
        alias = temporary / 'synthetic-wrapper'; alias.write_bytes(original_managed)
        managed.unlink(); managed.symlink_to(alias)
        refused = run(*command, check=False)
        assert refused.returncode != 0 and 'symlink' in refused.stderr
        managed.unlink(); managed.write_bytes(original_managed); managed.chmod(0o755)
        managed.write_bytes(original_managed + b'\n# unknown synthetic edit\n')
        refused = run(*command, check=False)
        assert refused.returncode != 0 and 'unknown local contents' in refused.stderr
        managed.write_bytes(original_managed)
        conflict = Path('/etc/fail2ban/filter.d/f2b-exploit-critical.local')
        original_conflict = conflict.read_bytes() if conflict.exists() else None
        conflict.write_text('[Definition]\nignoreregex = .*\n')
        blocked = run(*command, check=False)
        assert blocked.returncode != 0 and 'suppress' in blocked.stderr
        assert conflict.read_text() == '[Definition]\nignoreregex = .*\n'
        if original_conflict is None: conflict.unlink()
        else: conflict.write_bytes(original_conflict)
        assert_site_protections()
        # Read-only preflight leaves existing site files/firewall unchanged.
        before = {p: p.read_bytes() for p in Path('/etc/fail2ban').rglob('*') if p.is_file()}
        result = run(*command)
        print(result.stdout)
        assert all(p.read_bytes() == data for p, data in before.items())
        assert foreign == run('nft', '-s', 'list', 'table', 'ip', 'foreign-nat').stdout
        result = run(*command, '--apply', '--backup-dir', str(temporary / 'backups'))
        print(result.stdout)
        backup = Path(next(line.split(': ', 1)[1] for line in result.stdout.splitlines() if line.startswith('Backup complete:')))
        assert_site_protections()
        assert json.loads((backup / 'fail2ban-ban-times.json').read_text())['manualblock']
        assert Path('/etc/fail2ban/jail.local').read_bytes() == original_jail
        assert site.read_bytes() == before[site]
        assert 'flush ruleset' not in Path('/etc/nftables.conf').read_text().split('# v0.34 upgrade:')[0]
        assert foreign == run('nft', '-s', 'list', 'table', 'ip', 'foreign-nat').stdout
        # Reapplication must pass preflight with the now-installed v0.34 files.
        print(run(*command).stdout)
        print(run(*command, '--apply', '--backup-dir', str(temporary / 'repeat-backups')).stdout)
        assert_site_protections()
        run('fail2ban-client', 'set', 'f2b-webshell-sweep', 'banip', '192.0.2.99')
        wait(lambda: '192.0.2.99' in run('fail2ban-client', 'get', 'f2b-webshell-sweep', 'banip').stdout)
        # Never silently move/re-add a post-backup ban with a new start/TTL.
        refused = run(*command, '--rollback', str(backup), check=False)
        assert refused.returncode != 0 and 'BEFORE stop' in refused.stderr, refused.stderr
        assert run('fail2ban-client', 'ping').returncode == 0
        assert '192.0.2.99' in run('fail2ban-client', 'get', 'f2b-webshell-sweep', 'banip').stdout
        assert site.read_bytes() == before[site]
        assert foreign == run('nft', '-s', 'list', 'table', 'ip', 'foreign-nat').stdout
        # Explicit fixture cleanup, NOT recovery behavior or a passing re-add.
        run('fail2ban-client', 'set', 'f2b-webshell-sweep', 'unbanip', '192.0.2.99')
        wait(lambda: '192.0.2.99' not in run('fail2ban-client', 'get', 'f2b-webshell-sweep', 'banip').stdout)
        print(run(*command, '--rollback', str(backup)).stdout)
        print(run(*command, '--audit-rollback', str(backup)).stdout)
        if reviewed_original is not None:
            assert Path('/etc/fail2ban/filter.d/nginx-recon-optimized.conf').read_bytes() == reviewed_original
        assert Path('/etc/fail2ban/jail.local').read_bytes() == original_jail
        assert Path('/etc/fail2ban/jail.d/99-webshell-sweep.local').exists() == is_dev
        assert Path('/etc/cron.d/f2b-v034-sync').exists() == is_dev
        assert_site_protections()
        restored = run('fail2ban-client', 'get', 'manualblock', 'banip').stdout
        assert all(ip in restored for ip in ('192.0.2.8', '2001:db8::8'))
        assert foreign == run('nft', '-s', 'list', 'table', 'ip', 'foreign-nat').stdout
        # Actual auto-rollback after a fault in the third file replacement.
        spec = importlib.util.spec_from_file_location('full_upgrade_fault', script)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        actual_install = module.atomic_install
        calls = []
        def fail_third(source, target):
            calls.append(target)
            if len(calls) == 3: raise OSError('namespace injected deployment failure')
            return actual_install(source, target)
        failure_log = io.StringIO()
        with contextlib.redirect_stderr(failure_log), \
             patch.object(module, 'atomic_install', side_effect=fail_third), \
             patch.object(sys, 'argv', [str(script), '--apply', '--backup-dir', str(temporary / 'fault-backups')] +
                          (['--local-review', str(private_review)] if '--local-review-fixture' in sys.argv else [])):
            assert module.main() == 1
        assert 'was rolled back' in failure_log.getvalue(), failure_log.getvalue()
        assert 'ROLLBACK ALSO FAILED' not in failure_log.getvalue()
        assert len(calls) == 3
        if reviewed_original is not None:
            assert Path('/etc/fail2ban/filter.d/nginx-recon-optimized.conf').read_bytes() == reviewed_original
        assert Path('/etc/fail2ban/jail.d/99-webshell-sweep.local').exists() == is_dev
        assert_site_protections()
        assert Path('/etc/fail2ban/jail.local').read_bytes() == original_jail
        restored = run('fail2ban-client', 'get', 'manualblock', 'banip').stdout
        assert all(ip in restored for ip in ('192.0.2.8', '2001:db8::8'))
        assert foreign == run('nft', '-s', 'list', 'table', 'ip', 'foreign-nat').stdout
        # Real daemon missing socket must time out; a later async start then
        # restores from native DB only, without any test-side ticket re-add.
        expected_jails, expected_tickets = module.rollback_expectations(backup, compare_live=False)
        run('fail2ban-client', 'stop')
        try: module.wait_rollback_ready(expected_jails, expected_tickets, timeout=.6)
        except module.UpgradeError as error: assert 'readiness timeout' in str(error)
        else: raise AssertionError('Stopped real daemon was reported ready')
        run('systemctl', 'start', 'fail2ban')
        module.wait_rollback_ready(expected_jails, expected_tickets, timeout=15)
        assert_site_protections()
        print('PASS: legacy full preflight/apply/repeat, async manual/automatic rollback and readonly audit; native timed bans/local overrides/foreign NAT preserved, unrepresentable new tickets refused BEFORE stop (systemd/cron simulated)')
        if preserved_overrides:
            print(f'PASS: representative scan-review .local coexistence and separate Apache guard preserved across apply/repeat/manual+automatic rollback; baseline v034dev={is_dev}')
    except Exception:
        print('\n'.join(Path('/var/log/fail2ban.log').read_text(errors='replace').splitlines()[-80:]))
        raise
    finally:
        run('fail2ban-client', 'stop', check=False)
        for target in reversed(bind_targets): run('umount', target)
        run('umount', '/etc')
