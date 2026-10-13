"""Real fresh file/firewall/daemon path; PRIVATE namespaces, simulated systemd.

Not an apt/network download, real boot, ARM64 VM or reboot validation.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

assert os.geteuid() == 0
assert os.readlink('/proc/self/ns/net') != os.readlink('/proc/1/ns/net'), 'Require unshare --net'
assert os.readlink('/proc/self/ns/mnt') != os.readlink('/proc/1/ns/mnt'), 'Require unshare --mount'


def run(*args, check=True):
    result = subprocess.run(args, capture_output=True, text=True)
    if check and result.returncode:
        raise AssertionError(str(args) + '\n' + result.stdout[-3000:] + result.stderr[-3000:])
    return result


run('mount', '--make-rprivate', '/')
run('mount', '-t', 'tmpfs', 'tmpfs', '/run')
Path('/run/lock').mkdir()
Path('/run/fail2ban').mkdir()
source = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('fresh', source / 'scripts/fresh-install.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
with tempfile.TemporaryDirectory(prefix='f2b-fresh-linux-') as temporary:
    temporary = Path(temporary)
    private_etc = temporary / 'etc'
    shutil.copytree('/etc', private_etc, symlinks=True)
    run('mount', '--bind', str(private_etc), '/etc')
    # Every written path is private; the source checkout stays read-only.
    for name in ('/usr/local', '/var/log', '/var/lib/fail2ban', '/var/backups', '/opt'):
        clone = temporary / 'root' / name.lstrip('/')
        clone.mkdir(parents=True)
        Path(name).mkdir(parents=True, exist_ok=True)
        run('mount', '--bind', str(clone), name)
    for name in ('/etc/nftables.d', '/etc/systemd/system/nftables.service.d', '/etc/f2b'):
        Path(name).mkdir(parents=True, exist_ok=True)
        assert not list(Path(name).iterdir()), 'Fixture must start without custom config'
    assert not Path('/etc/fail2ban/jail.local').exists()
    stock = '#!/usr/sbin/nft -f\nflush ruleset\ntable inet filter {\n' + ''.join(
        ' chain ' + chain + ' { type filter hook ' + chain + ' priority filter; }\n'
        for chain in ('input', 'forward', 'output')) + '}\n'
    Path('/etc/nftables.conf').write_text(stock)
    original_conffiles = m.conffiles
    m.conffiles = lambda package: ({'/etc/nftables.conf': hashlib.md5(stock.encode()).hexdigest()}
                                  if package == 'nftables' else original_conffiles(package))
    stubs = temporary / 'bin'
    stubs.mkdir()
    (stubs / 'systemctl').write_text('#!/bin/sh\ncase "$*" in\n'
        '"stop fail2ban") fail2ban-client stop >/dev/null 2>&1; exit 0;;\n'
        '"enable --now fail2ban") (sleep 1; fail2ban-client -x start) >/dev/null 2>&1 & exit 0;;\n'
        '"is-active --quiet fail2ban") exec fail2ban-client ping >/dev/null 2>&1;;\n'
        '"is-enabled --quiet nftables.service") exit 1;;\n'
        '"is-enabled --quiet nftables"|"is-enabled --quiet fail2ban"|"is-enabled --quiet cron"|"is-active --quiet cron") exit 0;;\n'
        '"list-unit-files") echo fail2ban.service;;\n'
        '"daemon-reload"|"enable nftables.service"|"enable --now cron"|"is-active --quiet cron") exit 0;;\n'
        '*) echo "Forbidden systemctl: $*" >&2; exit 99;;\nesac\n')
    (stubs / 'crontab').write_text('#!/bin/sh\n[ "$1" = -l ] || exit 99\nexit 0\n')
    (stubs / 'sudo').write_text('#!/bin/sh\nexec "$@"\n')
    nft = shutil.which('nft')
    nft_log = temporary / 'nft-commands.txt'
    (stubs / 'nft').write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> "' + str(nft_log) + '"\nexec "' + nft + '" "$@"\n')
    for file in stubs.iterdir(): file.chmod(0o755)
    os.environ['PATH'] = str(stubs) + ':' + os.environ['PATH']
    os.environ['TERM'] = 'xterm'
    run('nft', 'add', 'table', 'ip', 'synthetic_foreign')
    run('nft', 'add', 'chain', 'ip', 'synthetic_foreign', 'guard')
    run('nft', 'add', 'rule', 'ip', 'synthetic_foreign', 'guard', 'tcp', 'dport', '12345', 'drop')
    before = m.nft_preflight()
    from argparse import Namespace
    args = Namespace(ssh=False, ssh_port=22, docker=False, mail_to=None,
                     npm_log_dir=None, bootstrap_stock_nft=True)
    selected = m.policy(args)
    assert selected[1] == ['recidive', 'manualblock']
    m.file_guards()
    try:
        m.install(args, before, selected)
        assert Path('/etc/f2b/fresh-install.state').read_text() == 'complete\n'
        assert 'flush ruleset' not in Path('/etc/nftables.conf').read_text()
        assert not Path('/var/log/auth.log').exists()
        assert not Path('/opt/rustnpm/data/logs').exists()
        run('fail2ban-client', 'set', 'manualblock', 'banip', '192.0.2.7')
        run('fail2ban-client', 'set', 'manualblock', 'banip', '2001:db8::7')
        run('/usr/bin/python3', '/usr/local/sbin/f2b-ipv6-sync.py')
        for family, ip in ((4, '192.0.2.7'), (6, '2001:db8::7')):
            elements = run('nft', 'list', 'set', 'inet', 'docker-block', 'docker-banned-ipv' + str(family)).stdout
            assert ip in elements
        run('/usr/bin/python3', '/usr/local/libexec/f2b-runtime-verify.py', '--docker-check')
        run('bash', '/usr/local/bin/f2b', 'sync', 'check')
        audit = run('bash', '/usr/local/bin/f2b', 'audit').stdout
        assert 'Total Jails' in audit and 'nginx-php-errors' not in audit
        # Reconstruct the exact known partial legacy payload, retaining live bans.
        recovery_spec = importlib.util.spec_from_file_location('recovery', source / 'scripts/recover-fresh.py')
        recovery = importlib.util.module_from_spec(recovery_spec); recovery_spec.loader.exec_module(recovery)
        recovery.fresh.conffiles = m.conffiles
        for target, payload in recovery.mapping().items():
            target.write_bytes(recovery.legacy_bytes(payload))
        marker = Path('/etc/f2b/fresh-install.state')
        marker.write_text('incomplete; inspect backup before recovery\n')
        backup = next(Path('/var/backups').glob('f2b-fresh-*'))
        recovery.inspect(backup)
        backup.chmod(0o755)
        try: recovery.inspect(backup)
        except recovery.fresh.FreshError: pass
        else: raise AssertionError('Recovery accepted non-private backup')
        backup.chmod(0o700)
        foreign_file = backup / 'foreign-firewall.json'
        original_foreign = foreign_file.read_bytes()
        foreign_file.write_text('{"nftables": []}')
        try: recovery.inspect(backup)
        except recovery.fresh.FreshError: pass
        else: raise AssertionError('Recovery accepted foreign firewall mismatch')
        foreign_file.write_bytes(original_foreign)
        profile_file = Path('/etc/fail2ban/jail.d/zz-f2b-fresh-profile.local')
        original_profile = profile_file.read_bytes()
        profile_file.write_bytes(original_profile + b'# unknown local change\n')
        try: recovery.inspect(backup)
        except recovery.fresh.FreshError: pass
        else: raise AssertionError('Recovery accepted changed profile')
        profile_file.write_bytes(original_profile)
        # Execute the actual recovery main with the synthetic package MD5 hook.
        import sys
        original_argv = sys.argv
        sys.argv = ['recover-fresh.py', '--backup', str(backup), '--apply']
        try: assert recovery.main() == 0
        finally: sys.argv = original_argv
        assert marker.read_text() == 'complete\n'
        run('bash', '/usr/local/bin/f2b', 'sync', 'check')
        after = json.loads(run('nft', '-j', 'list', 'ruleset').stdout)
        assert m.load_upgrade().external_nft_digest(before) == m.load_upgrade().external_nft_digest(after)
        config_before = Path('/etc/nftables.conf').read_bytes()
        try: m.file_guards()
        except m.FreshError: pass
        else: raise AssertionError('Rerun did not refuse existing install')
        assert Path('/etc/nftables.conf').read_bytes() == config_before
        commands = nft_log.read_text()
        assert 'flush ruleset' not in commands
        assert all('-c -f /etc/nftables.conf' in line for line in commands.splitlines()
                   if '-f /etc/nftables.conf' in line), 'Only isolated syntax checks may read persistence'
        assert 'delete table' not in commands
        # Synthetic reconstruction of the complete old five-jail NPM profile.
        # This is fixture setup, NOT a supported core profile-add operation.
        import datetime
        import time
        import types
        legacy = types.ModuleType('legacy_npm_fresh')
        legacy.__file__ = str(source / 'scripts/fresh-install.py')
        old_code = run('git', '-C', str(source.parents[1]), 'show',
                       '393abab:releases/v0.34/scripts/fresh-install.py').stdout
        exec(compile(old_code, legacy.__file__, 'exec'), legacy.__dict__)
        logs = Path('/opt/f2b-npm-lab/data/logs'); logs.mkdir(parents=True)
        for name in ('fallback_http_access.log', 'fallback_http_error.log', 'fallback_error.log',
                     'backend.log', 'fallback_stream_access.log'):
            (logs / name).touch()
        args.npm_log_dir = logs
        old_profile = legacy.policy(args)
        assert len(old_profile[1]) == 5
        old_profile[0]['DEFAULT']['ignoreip'] = '127.0.0.1/8 ::1 192.0.2.99'
        with profile_file.open('w') as stream: old_profile[0].write(stream)
        verifier_path = Path('/usr/local/libexec/f2b-runtime-verify.py')
        verifier_path.write_text(run('git', '-C', str(source.parents[1]), 'show',
                                    '393abab:releases/v0.34/scripts/upgrade-v034dev-canary-227c393.py').stdout)
        run('fail2ban-client', 'reload')
        assert 'fallback_http_access.log' not in run('fail2ban-client', 'get', 'f2b-exploit-critical', 'logpath').stdout
        repair_spec = importlib.util.spec_from_file_location('repair_npm', source / 'scripts/repair-npm-http.py')
        repair = importlib.util.module_from_spec(repair_spec); repair_spec.loader.exec_module(repair)
        original_targets = {file: file.read_bytes() for file in (repair.PROFILE, repair.SWEEP, repair.VERIFIER)}
        plan = repair.preflight(logs)
        assert all(file.read_bytes() == value for file, value in original_targets.items()), 'Preflight modified targets'
        override = Path('/etc/fail2ban/jail.d/zzz-synthetic-coverage.local')
        override.write_text('[f2b-exploit-critical]\nlogpath = ' + str(logs / 'fallback_error.log') + '\n')
        try: repair.preflight(logs)
        except repair.fresh.FreshError as error: assert 'coverage' in str(error)
        else: raise AssertionError('Suppressing local log override must be refused')
        finally: override.unlink()
        original_sweep = repair.SWEEP.read_bytes()
        repair.SWEEP.write_bytes(original_sweep + b'# unrecognized managed edit\n')
        try: repair.preflight(logs)
        except repair.fresh.FreshError as error: assert 'Unknown managed target' in str(error)
        else: raise AssertionError('Unknown managed filter modification must be refused')
        finally: repair.SWEEP.write_bytes(original_sweep)
        original_command = repair.fresh.run
        injected = [False]
        def fail_once(*parts, **kwargs):
            if parts == ('fail2ban-client', '-t') and not injected[0]:
                injected[0] = True
                raise repair.fresh.FreshError('Synthetic post-write failure')
            return original_command(*parts, **kwargs)
        repair.fresh.run = fail_once
        try: repair.apply(plan, Path('/var/backups'))
        except repair.fresh.FreshError as error: assert 'rollback verification' in str(error)
        else: raise AssertionError('Expected repair rollback')
        finally: repair.fresh.run = original_command
        assert all(file.read_bytes() == value for file, value in original_targets.items())
        plan = repair.preflight(logs)
        repair.apply(plan, Path('/var/backups'))
        assert 'fallback_http_access.log' in run('fail2ban-client', 'get', 'f2b-exploit-critical', 'logpath').stdout
        assert '192.0.2.99' in run('fail2ban-client', 'get', 'manualblock', 'ignoreip').stdout
        run('/usr/bin/python3', str(verifier_path), '--npm-coverage')
        # Real polling pipeline, synthetic standard-format entries with current time.
        def entry(target, address):
            stamp = datetime.datetime.now().astimezone().strftime('%d/%b/%Y:%H:%M:%S %z')
            return f'[{stamp}] 404 - GET http test.example "{target}" [Client {address}] [Length 153] [Gzip -] "curl" "-"\n'
        def wait_bans(jail, expected):
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                if expected <= set(run('fail2ban-client', 'get', jail, 'banip').stdout.split()): return
                time.sleep(0.1)
            raise AssertionError('Synthetic NPM standard format did not reach expected jail ban')
        with (logs / 'fallback_http_access.log').open('a') as stream:
            for address in ('192.0.2.27', '2001:db8::27'):
                stream.write(entry('/this_is_a_new_hello_world.php?f2b-lab=1', address))
        wait_bans('f2b-exploit-critical', {'192.0.2.27', '2001:db8::27'})
        with (logs / 'fallback_http_access.log').open('a') as stream:
            for address in ('192.0.2.28', '2001:db8::28'):
                for suffix in ('one', 'two', 'three'):
                    stream.write(entry('/lab-missing-' + suffix + '.php', address))
        wait_bans('f2b-webshell-sweep', {'192.0.2.28', '2001:db8::28'})
        run('/usr/bin/python3', '/usr/local/sbin/f2b-ipv6-sync.py')
        run('/usr/bin/python3', str(verifier_path), '--docker-check')
        print('PASS: old error-only NPM profile repaired, rollback verified, whitelist/timed bans preserved and real polling auto-ban for both families (synthetic logs, not packets)')
        print('PASS: real fresh core install, active/log-backed jail count, dual-family bans, scoped persistence, foreign-rule preservation and rerun refusal (systemd simulated)')
    finally:
        run('fail2ban-client', 'stop', check=False)
