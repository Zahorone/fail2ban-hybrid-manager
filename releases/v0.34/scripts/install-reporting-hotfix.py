#!/usr/bin/python3
"""Scoped reporting-only code update; preflight unless --apply.

Preserve enforcement, port/diagnostic fixes, local filter/mail/reconciler/config.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys
import tempfile

SOURCE = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('report_code_transaction', SOURCE / 'scripts/install-diagnostic-hotfix.py')
transaction = importlib.util.module_from_spec(spec); spec.loader.exec_module(transaction)
transaction.CHECKER = Path('/usr/local/libexec/f2b-report-filter.py')
FUNCTIONS = ('f2b_version', 'f2b_audit', 'report_json', 'report_csv', 'report_daily',
             'audit_silent', 'stats_quick', 'report_attack_analysis', 'report_attack_timeline', 'monitor_trends')
LEGACY = 'dc78f8bf022c850368602e434cc0e0744861c7e1'
REPORTING_BASELINE = '7e41be127a5d159f12c656fbc0ab5ea7123df831'


def function(text, name):
    # JSON heredoc's closing brace is followed by EOF, not a function separator.
    found = list(re.finditer(r'^' + name + r'\(\) \{\n.*?^\}(?=\n(?:\n|#|$))', text, re.M | re.S))
    if len(found) != 1: raise transaction.HotfixError('Ambiguous reporting function: ' + name)
    return found[0][0]


def route_main(body):
    # Only reporting routes stop depending on the old global runtime cache.
    pattern = r'(?m)^([ \t]*)([a-z|_-]+)\)\n(?=[^\n]*runtime_snapshot)'
    def remove_report_routes(match):
        names = match[2].split('|')
        keep = [name for name in names if name not in {'report', 'audit', 'audit-silent', 'stats-quick'}]
        return match[1] + '|'.join(keep) + ')\n'
    body = re.sub(pattern, remove_report_routes, body)
    # Preserve the legacy runtime cache for other monitor commands, not trends.
    if '"monitor:trends"' not in body:
        body = body.replace('runtime_snapshot ||', '[ "$1:$2" = "monitor:trends" ] || runtime_snapshot ||', 1)
    # Old v0.33 release_lock masked a failed report's status.
    pattern = r'(?ms)(^[ \t]*report\)\n.*?^[ \t]*esac\n)([ \t]*)release_lock\n([ \t]*;;)'
    body = re.sub(pattern, lambda m: m[1] + m[2] + 'local report_result=$?\n' + m[2] +
                  'release_lock\n' + m[2] + 'return "$report_result"\n' + m[3], body, count=1)
    if 'local report_result=$?' not in body or 'return "$report_result"' not in body:
        raise transaction.HotfixError('Unrecognized report routing; refusing to mask report failures')
    old_analysis = '''                case "$3" in
                    --npm-only) report_attack_analysis "npm-only" ;;
                    --ssh-only) report_attack_analysis "ssh-only" ;;
                    *)          report_attack_analysis "all" ;;
                esac'''
    if old_analysis in body:
        body = body.replace(old_analysis, '                report_attack_analysis "${@:3}"', 1)
    if body.count('report_attack_analysis "${@:3}"') != 1:
        raise transaction.HotfixError('Unrecognized analysis argument routing')
    return body


def wrapper_source(original):
    canonical = (SOURCE / 'scripts/f2b-wrapper-v034.sh').read_text()
    updated = original
    for name in FUNCTIONS:
        old = function(updated, name)
        # Explicit report entrypoints only; no internal enforcement/monitoring
        # functions are copied from the newer wrapper.
        if ('f2b-report-filter.py --report' not in old and
                not any(marker in old for marker in ('get_f2b_count', 'ATTACK ANALYSIS',
                    'ATTACK WAVE TIMELINE', 'ATTACK TREND ANALYSIS', 'VERSION'))):
            raise transaction.HotfixError('Unrecognized reporting body: ' + name)
        updated = updated.replace(old, function(canonical, name), 1)
    old_main = function(updated, 'main')
    updated = updated.replace(old_main, route_main(old_main), 1)
    verify = function(original, 'f2b_docker_verify')
    dual = '--docker-check' in verify and ('f2b-diagnostic-membership.py' in verify or 'f2b-runtime-verify.py' in verify)
    label = ('Read-only exact IPv4/IPv6 membership and Docker union' if dual else
             'Legacy IPv4 count/union diagnostic; not exact dual-family membership')
    for name in ('show_help', 'f2b_docker_commands'):
        body = function(updated, name)
        patched = body
        for old in ('Deep verify of F2B ↔ docker-block sync (IPv4 union)',
                    'Read-only exact IPv4/IPv6 membership and Docker union'):
            patched = patched.replace(old, label)
        if name == 'show_help':
            old_help = '  report attack-analysis [--npm-only|--ssh-only]\n                                     Complete attack analysis'
            new_help = ('  report attack-analysis [--npm-only|--ssh-only]\n'
                        '                                     Full graphical terminal report (24h)\n'
                        '  report attack-analysis short [--npm-only|--ssh-only]\n'
                        '                                     Compact schema-2 summary (short/scope in either order)')
            patched = patched.replace(old_help, new_help, 1)
            if new_help not in patched:
                raise transaction.HotfixError('Unrecognized analysis help; refusing stale CLI guidance')
        updated = updated.replace(body, patched, 1)
    # Prove exact preservation of every other function/constant/port/diagnostic.
    before, after = original, updated
    for name in (*FUNCTIONS, 'main', 'show_help', 'f2b_docker_commands'):
        before = before.replace(function(before, name), name, 1)
        after = after.replace(function(after, name), name, 1)
    if before != after: raise transaction.HotfixError('Change outside approved reporting scope')
    return updated.encode()


def plan():
    transaction.secure(transaction.WRAPPER)
    transaction.secure(transaction.CHECKER, missing=True)
    helper = SOURCE / 'scripts/f2b-report-filter.py'
    expected = helper.read_bytes(); compile(expected, str(helper), 'exec')
    if transaction.CHECKER.exists():
        known = [transaction.run('git', '-C', str(SOURCE.parents[1]), 'show',
                                revision + ':releases/v0.34/scripts/f2b-report-filter.py').encode()
                 for revision in (LEGACY, REPORTING_BASELINE)]
        if transaction.CHECKER.read_bytes() not in (*known, expected):
            raise transaction.HotfixError('Unknown local reporting helper; preserve/review before overwrite')
    transaction.run('/usr/bin/python3', '-c', 'from zoneinfo import ZoneInfo; from fail2ban.client.csocket import CSocket')
    original = transaction.WRAPPER.read_bytes().decode('utf-8')
    config = '/etc/f2b/reporting.ini'
    declarations = re.findall(r'(?m)^NPM_REPORT_CONFIG=(.*)$', original)
    if declarations:
        if len(declarations) != 1: raise transaction.HotfixError('Ambiguous reporting config path')
        value = declarations[0].strip().strip('"\'')
        if not value.startswith('/') or any(c in value for c in ('$','`','\n')):
            raise transaction.HotfixError('Dynamic reporting config path requires explicit review')
        config = value
    transaction.run('/usr/bin/python3', str(helper), '--validate-config', '--config', config)
    patched = wrapper_source(original)
    with tempfile.TemporaryDirectory(prefix='f2b-report-stage-') as directory:
        candidate = Path(directory) / 'f2b'; candidate.write_bytes(patched)
        transaction.run('bash', '-n', str(candidate))
    return {transaction.CHECKER: expected, transaction.WRAPPER: patched}


def rollback(backup):
    transaction.secure(backup / 'manifest.json')
    manifest = json.loads((backup / 'manifest.json').read_text())
    targets = (transaction.CHECKER, transaction.WRAPPER)
    if manifest.get('schema') != 1 or set(manifest.get('targets', {})) != {str(p) for p in targets}:
        raise transaction.HotfixError('Not a reporting-only backup')
    restore = {}
    for index, path in enumerate(targets):
        transaction.secure(path)
        entry = manifest['targets'][str(path)]
        if hashlib.sha256(path.read_bytes()).hexdigest() != entry['after']:
            raise transaction.HotfixError('Installed reporting code changed since backup; refusing overwrite')
        content = None
        if entry['existed']:
            saved = backup / ('target-' + str(index)); transaction.secure(saved)
            content = saved.read_bytes()
            if hashlib.sha256(content).hexdigest() != entry['before']:
                raise transaction.HotfixError('Backup checksum mismatch')
        restore[path] = content
    with tempfile.TemporaryDirectory(prefix='f2b-report-rollback-') as directory:
        staged = Path(directory) / 'f2b'; staged.write_bytes(restore[transaction.WRAPPER])
        transaction.run('bash', '-n', str(staged))
    # Wrapper first: never leave restored legacy entrypoints pointing at a missing helper.
    current = {path: path.read_bytes() for path in targets}
    try:
        for path in reversed(targets):
            if restore[path] is None: path.unlink()
            else: transaction.atomic(path, restore[path])
    except Exception:
        for path in targets: transaction.atomic(path, current[path])
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--apply', action='store_true')
    mode.add_argument('--rollback', type=Path, help='restore a private reporting backup; refuse intervening code edits')
    args = parser.parse_args()
    try:
        import os
        if os.geteuid() != 0: raise transaction.HotfixError('Run with sudo')
        with transaction.lock():
            if args.rollback: rollback(args.rollback)
            else:
                replacement = plan()
                if args.apply: transaction.apply(replacement)
        print('PASS: reporting-only ' + ('code rollback' if args.rollback else 'code deployment' if args.apply else 'code/config preflight') +
              '; no enforcement/service/filter/mail/reconciler changes; live reporting config preserved')
        return 0
    except Exception as error:
        print('REFUSED/FAILED:', error, file=sys.stderr); return 1


if __name__ == '__main__': sys.exit(main())
