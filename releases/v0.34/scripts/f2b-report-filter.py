#!/usr/bin/env python3
"""Remove explicitly trusted service probes from reporting, never from bans."""

from __future__ import annotations

import argparse
import configparser
from collections import Counter
import csv
import datetime as dt
import gzip
import heapq
import ipaddress
import json
import os
import re
import sys
import textwrap
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import unquote, urlsplit
from zoneinfo import ZoneInfo


CLIENT_RE = re.compile(r"\[Client (?P<ip>[0-9A-Fa-f:.]+)\]")
REQUEST_RE = re.compile(
    r"\b(?P<method>GET|HEAD|POST|PUT|PATCH|DELETE|OPTIONS)\s+"
    r"(?P<scheme>https?|wss?)\s+(?P<host>[^\s\"]+)\s+\"(?P<path>[^\"]*)\"",
    re.IGNORECASE,
)
STATUS_RE = re.compile(
    r"\s(?P<status>[1-5][0-9]{2})(?:\s+[1-5][0-9]{2})?\s+-\s+"
    r"(?:GET|HEAD|POST|PUT|PATCH|DELETE|OPTIONS)\s+",
    re.IGNORECASE,
)
HTTP_RE = re.compile(
    r'^\[(?P<stamp>[^\]\r\n]+)\] '
    r'(?:(?:-|[A-Z_]+) (?:[1-5][0-9]{2}|-) )?'
    r'(?P<status>[1-5][0-9]{2}) - '
    r'(?P<method>GET|HEAD|POST|PUT|PATCH|DELETE|OPTIONS) '
    r'(?P<scheme>https?) (?P<host>[^\s\"]+) "(?P<path>[^\"\r\n]*)" '
    r'\[Client (?P<ip>[0-9A-Fa-f:.]+)\]')
DANGEROUS_RE = re.compile(
    r"(?:\.\./|%2e%2e|union(?:\s|%20)+select|/\.git(?:/|$)|"
    r"auto_prepend_file|allow_url_include|base64_decode|shell_exec|"
    r"(?:^|[?&])(?:cmd|exec|system)=)",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class ProbeRule:
    network: ipaddress.IPv4Network | ipaddress.IPv6Network
    method: str
    host: str
    status: int
    paths: frozenset[str]

    def matches(self, line: str) -> bool:
        if DANGEROUS_RE.search(line):
            return False
        record = HTTP_RE.match(line)
        if not record:
            return False
        decoded = record['path']
        for _ in range(2): decoded = unquote(decoded)
        if DANGEROUS_RE.search(decoded): return False
        if indicators(record.groupdict()): return False
        try:
            source = ipaddress.ip_address(record['ip'])
        except ValueError:
            return False
        return (
            source in self.network
            and record['method'] == self.method
            and record['host'].rstrip(".").lower() == self.host
            and int(record['status']) == self.status
            and record['path'] in self.paths
        )


def load_rules(path: Path) -> list[ProbeRule]:
    if not path.exists():
        return []
    parser = configparser.ConfigParser(interpolation=None)
    with path.open() as stream: parser.read_file(stream)
    if parser.defaults(): raise ValueError('DEFAULT reporting options are not supported')
    rules: list[ProbeRule] = []
    for section in parser.sections():
        if section == 'reporting':
            unknown = set(parser[section]) - {'fail2ban_timezone', 'sample_limit', 'npm_log_dir', 'fail2ban_log', 'ssh_jails'}
            if unknown: raise ValueError('Unknown reporting options: ' + ', '.join(sorted(unknown)))
            continue
        if not section.lower().startswith("trusted-probe"):
            raise ValueError('Unknown reporting section: ' + section)
        required = {"source", "method", "host", "status", "paths"}
        missing = required.difference(parser[section])
        unknown = set(parser[section]) - required
        if unknown: raise ValueError(section + ': unknown options: ' + ', '.join(sorted(unknown)))
        if missing:
            raise ValueError(f"{section}: missing {', '.join(sorted(missing))}")
        network = ipaddress.ip_network(parser[section]["source"], strict=False)
        method = parser[section]["method"].strip().upper()
        host = parser[section]["host"].strip().rstrip(".").lower()
        status = int(parser[section]["status"])
        paths = frozenset(
            item.strip() for item in parser[section]["paths"].split(",") if item.strip()
        )
        if not re.fullmatch(r'[A-Za-z0-9_.:-]+', host) or not paths or any(
            not p.startswith('/') or any(c in p for c in ('*', '\r', '\n', '"')) for p in paths
        ) or method not in {
            "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"
        } or not 100 <= status <= 599:
            raise ValueError(f"{section}: invalid method, host, status, or paths")
        rules.append(ProbeRule(network, method, host, status, paths))
    return rules


def report_settings(config: Path, npm_dir=None):
    parser = configparser.ConfigParser(interpolation=None)
    if config.exists():
        with config.open() as stream: parser.read_file(stream)
    values = parser['reporting'] if parser.has_section('reporting') else {}
    name = values.get('fail2ban_timezone', 'system')
    if name == 'system':
        with Path('/etc/localtime').open('rb') as stream: zone = ZoneInfo.from_file(stream)
    else: zone = ZoneInfo(name)
    limit = int(values.get('sample_limit', '5000'))
    if not 1 <= limit <= 100000: raise ValueError('sample_limit must be 1..100000')
    npm = Path(values.get('npm_log_dir', npm_dir or '/opt/rustnpm/data/logs'))
    fail2ban = Path(values.get('fail2ban_log', '/var/log/fail2ban.log'))
    if not npm.is_absolute() or not fail2ban.is_absolute(): raise ValueError('Reporting log paths must be absolute')
    return {'rules': load_rules(config), 'zone': zone, 'zone_name': name, 'limit': limit,
            'npm_dir': npm, 'fail2ban_log': fail2ban,
            'ssh_jails': set(x.strip() for x in values.get('ssh_jails', 'sshd,sshd-slowattack').split(',') if x.strip())}


class AmbiguousTimestamp(ValueError): pass


def timestamp(value, zone):
    if re.fullmatch(r'\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4}', value):
        return dt.datetime.strptime(value, '%d/%b/%Y:%H:%M:%S %z').astimezone(dt.timezone.utc)
    parsed = dt.datetime.fromisoformat(value.replace(',', '.').replace('Z', '+00:00'))
    if parsed.tzinfo is not None: return parsed.astimezone(dt.timezone.utc)
    # Naive logs cannot distinguish the repeated DST hour. Do not guess a fold
    # or silently include ambiguous/nonexistent timestamps in time-bound metrics.
    possibilities = set()
    for fold in (0, 1):
        candidate = parsed.replace(tzinfo=zone, fold=fold).astimezone(dt.timezone.utc)
        if candidate.astimezone(zone).replace(tzinfo=None) == parsed: possibilities.add(candidate)
    if len(possibilities) != 1: raise AmbiguousTimestamp('ambiguous/nonexistent local timestamp')
    return possibilities.pop()


F2B_RE = re.compile(
    r'^(?P<stamp>\d{4}-\d\d-\d\d[ T]\d\d:\d\d:\d\d(?:[.,]\d+)?(?:Z|[+-]\d\d:?\d\d)?) '
    r'(?P<component>fail2ban\.(?:filter|actions))\s+.*?\[(?P<jail>[A-Za-z0-9_.:-]+)\] (?P<kind>Restore Ban|Increase Ban|Unban|Ban|Found) '
    r'(?P<ip>[0-9A-Fa-f:.]+)(?=\s|$)')
EVENT_NAMES = {'Restore Ban': 'restored_ban', 'Increase Ban': 'extended_ban',
               'Ban': 'new_ban', 'Unban': 'unban', 'Found': 'found'}


def parse_http(line, zone):
    match = HTTP_RE.match(line)
    if not match: return None
    value = match.groupdict()
    value.update(time=timestamp(value.pop('stamp'), zone), status=int(value['status']),
                 ip=str(ipaddress.ip_address(value['ip'])), line=line)
    return value


def parse_f2b(line, zone):
    match = F2B_RE.match(line)
    if not match: return None
    if (match['kind'] == 'Found') != (match['component'] == 'fail2ban.filter'): return None
    return {'time': timestamp(match['stamp'], zone), 'jail': match['jail'],
            'kind': EVENT_NAMES[match['kind']], 'ip': str(ipaddress.ip_address(match['ip']))}


def log_files(directory, http=False, prefix=None):
    if not directory.exists(): return []
    if not directory.is_dir(): raise ValueError('Report log directory is not a directory')
    pattern = (r'(?:fallback(?:_http)?|dead-host|(?:proxy|redirection|dead)-host-[0-9]+)_access\.log(?:\.[0-9]+)?(?:\.gz)?'
               if http else re.escape(prefix) + r'(?:\.[0-9]+)?(?:\.gz)?')
    return sorted(f for f in directory.iterdir() if f.is_file() and re.fullmatch(pattern, f.name))


def collect(files, parse, settings, now, limit, observe, sample_if=lambda record: True):
    cutoff = now - dt.timedelta(hours=24)
    coverage = Counter(files=len(files), lines_read=0, records_24h=0, unparsed_lines=0,
                       invalid_records=0, ambiguous_local_time_records=0, before_window=0, future_records=0)
    latest = []
    for file in files:
        opener = gzip.open if file.suffix == '.gz' else open
        with opener(file, 'rt', encoding='utf-8', errors='replace') as stream:
            for number, line in enumerate(stream):
                coverage['lines_read'] += 1
                try: record = parse(line, settings['zone'])
                except AmbiguousTimestamp:
                    coverage['ambiguous_local_time_records'] += 1; continue
                except (ValueError, TypeError, OverflowError):
                    coverage['invalid_records'] += 1; continue
                if record is None: coverage['unparsed_lines'] += 1; continue
                if record['time'] < cutoff: coverage['before_window'] += 1; continue
                if record['time'] > now: coverage['future_records'] += 1; continue
                coverage['records_24h'] += 1
                observe(record)
                if not sample_if(record): continue
                key = (record['time'], str(file), number)
                item = (key, record)
                if len(latest) < limit: heapq.heappush(latest, item)
                elif key > latest[0][0]: heapq.heapreplace(latest, item)
    # File rotation order is irrelevant: timestamp comparison precedes selection.
    coverage = dict(coverage)
    coverage['availability'] = 'available' if files else 'unavailable: no matching log files'
    return [record for _, record in sorted(latest)], coverage


def indicators(record):
    target = record['path']
    for _ in range(2): target = unquote(target)
    path, query = urlsplit(target).path, urlsplit(target).query
    result = []
    if re.search(r'(?:^|[/\\?=&])\.\.(?:/|\\)', target): result.append('traversal_target')
    if re.search(r'/(?:\.env(?:[._~-][^/]*)?|\.git/(?:config|HEAD|index|packed-refs)|\.aws/(?:credentials|config)|\.ssh/authorized_keys)$', path):
        result.append('sensitive_metadata_target')
    if re.search(r'/(?:this_is_a_new_hello_world|shell|cmd|backdoor|wso|b374k|alfa)\.php$', path, re.I):
        result.append('executable_probe_target')
    if re.search(r'\bunion\s+(?:all\s+)?select\b|\bsleep\(\s*\d', query, re.I): result.append('sql_query_indicator')
    if re.search(r'(?:^|&)(?:cmd|exec|system)=|allow_url_include|auto_prepend_file', query, re.I):
        result.append('execution_query_indicator')
    # UA/referer text (including ordinary curl) is deliberately not searched.
    return result


def runtime_snapshot(call=None):
    if call is None:
        from fail2ban.client.csocket import CSocket
        def call(command):
            if command[0] not in {'status', 'get'}: raise ValueError('Reporting socket is read-only')
            socket = CSocket('/var/run/fail2ban/fail2ban.sock', timeout=15)
            try: value = socket.send(command)
            finally: socket.close()
            if value[0] != 0: raise ValueError('Fail2Ban reporting read failed')
            return value[1]
    names = dict(call(['status'])).get('Jail list')
    if isinstance(names, str): names = [v.strip() for v in names.split(',') if v.strip()]
    if not isinstance(names, (list, tuple)) or not names: raise ValueError('No usable active jail list')
    by_jail, union = {}, set()
    for jail in names:
        if not isinstance(jail, str) or not re.fullmatch(r'[A-Za-z0-9_.:-]+', jail): raise ValueError('Malformed jail list')
        values = call(['get', jail, 'banip'])
        if not isinstance(values, (list, tuple)) or not all(isinstance(v, str) for v in values):
            raise ValueError('Malformed ban list')
        addresses = {ipaddress.ip_address(v) for v in values}
        by_jail[jail] = len(addresses); union.update(addresses)
    return {'snapshot_utc': dt.datetime.now(dt.timezone.utc).isoformat(),
            'jails': by_jail, 'ban_records_across_jails': sum(by_jail.values()),
            'unique_ipv4': sum(v.version == 4 for v in union),
            'unique_ipv6': sum(v.version == 6 for v in union), 'unique_union': len(union),
            'audit_status': 'runtime_read_ok; active bans are informational, not audit failure'}


def build_report(settings, now=None, runtime=None, scope='all'):
    now = (now or dt.datetime.now(dt.timezone.utc)).astimezone(dt.timezone.utc)
    cutoff = now - dt.timedelta(hours=24)
    window_http = Counter(parsed_records=0, raw_http_errors=0, trusted_probe_records=0)
    events = Counter(); by_jail = {}; categories = Counter(); bins = [0] * 24
    trends = {str(hours): Counter() for hours in (1, 6, 24)}
    def observe_http(record):
        window_http['parsed_records'] += 1
        window_http['raw_http_errors'] += record['status'] >= 400
        window_http['trusted_probe_records'] += any(rule.matches(record['line']) for rule in settings['rules'])
    def observe_event(record):
        events[record['kind']] += 1
        by_jail.setdefault(record['jail'], Counter())[record['kind']] += 1
        for hours in (1, 6, 24):
            if record['time'] >= now - dt.timedelta(hours=hours): trends[str(hours)][record['kind']] += 1
        if record['kind'] == 'found':
            events['ssh_found'] += record['jail'] in settings['ssh_jails']
            bins[min(23, int((record['time'] - cutoff).total_seconds() // 3600))] += 1
    http_files = [] if scope == 'ssh-only' else log_files(settings['npm_dir'], http=True)
    http, http_coverage = collect(http_files, parse_http,
                                   settings, now, settings['limit'], observe_http)
    f2b, f2b_coverage = collect(log_files(settings['fail2ban_log'].parent, prefix=settings['fail2ban_log'].name),
                                 parse_f2b, settings, now, 20, observe_event,
                                 sample_if=lambda record: record['kind'] in {'new_ban', 'restored_ban', 'extended_ban'})
    excluded = [record for record in http if any(rule.matches(record['line']) for rule in settings['rules'])]
    included = [record for record in http if not any(rule.matches(record['line']) for rule in settings['rules'])]
    candidate_records = 0
    paths, candidate_paths = Counter(), Counter()
    for record in http: paths[urlsplit(record['path']).path] += 1
    for record in included:
        hints = indicators(record); candidate_records += bool(hints); categories.update(hints)
        if hints: candidate_paths[urlsplit(record['path']).path] += 1
    raw_errors = sum(v['status'] >= 400 for v in http)
    included_errors = sum(v['status'] >= 400 for v in included)
    ratio = lambda count, denominator: count / denominator if denominator else None
    event_kinds = ('found', 'ssh_found', 'new_ban', 'restored_ban', 'extended_ban', 'unban')
    counts = lambda counter: {k: counter[k] if f2b_coverage['files'] else None for k in event_kinds}
    if not http_coverage['files']:
        window_http = {k: None for k in window_http}
    return {'schema': 2, 'as_of_utc': now.isoformat(), 'cutoff_utc': cutoff.isoformat(),
            'window_hours': 24, 'fail2ban_log_timezone': settings['zone_name'],
            'coverage': {'http': http_coverage, 'fail2ban': f2b_coverage},
            'active': runtime if runtime is not None else runtime_snapshot(),
            'http_window': dict(window_http),
            'http_sample': {'limit': settings['limit'], 'selection': 'latest chronological records inside last 24h, before exclusions',
                            'raw_records': len(http), 'trusted_probe_records': len(excluded),
                            'included_records': len(included), 'raw_http_errors': raw_errors,
                            'included_http_errors': included_errors,
                            'raw_error_fraction': ratio(raw_errors, len(http)),
                            'included_error_fraction': ratio(included_errors, len(included)),
                            'candidate_records': candidate_records, 'candidate_fraction': ratio(candidate_records, len(included)),
                            'category_hits': dict(categories), 'categories_may_overlap': True},
            'fail2ban_events_24h': counts(events),
            'trends': {hours: {k: counter[k] if f2b_coverage['files'] else None for k in event_kinds if k != 'ssh_found'}
                       for hours, counter in trends.items()},
            'ssh_events_24h': {k: (sum(by_jail.get(jail, {}).get(k, 0) for jail in settings['ssh_jails']) if f2b_coverage['files'] else None)
                               for k in ('found', 'new_ban', 'restored_ban', 'extended_ban', 'unban')},
            'found_timeline': [{'start_utc': (cutoff + dt.timedelta(hours=i)).isoformat(), 'found_records': bins[i] if f2b_coverage['files'] else None} for i in range(24)],
            'found_summary': {'observed_records': events['found'] if f2b_coverage['files'] else None, 'window_hours': 24,
                              'average_per_hour': events['found'] / 24 if f2b_coverage['files'] else None,
                              'peak_rolling_hour_records': max(bins) if f2b_coverage['files'] else None},
            'recent_ban_event_sample': [{'timestamp_utc': r['time'].isoformat(), 'jail': r['jail'], 'kind': r['kind']} for r in f2b],
            'presentation_top': {
                'raw_sample_paths': paths.most_common(10),
                'included_candidate_paths': candidate_paths.most_common(10),
                'event_jails': sorted(({'jail': jail, 'events': dict(counter)} for jail, counter in by_jail.items()),
                                      key=lambda item: (-sum(item['events'].values()), item['jail']))[:10]},
            'interpretation': 'HTTP errors are not attacks; request indicators are candidates; Found/Ban records may overlap. No compromise, audit-failure or enforcement claim.'}


def diagnostic_label(wrapper=Path('/usr/local/bin/f2b')):
    if not wrapper.is_file(): return 'unknown diagnostic route'
    body = wrapper.read_text()
    match = re.search(r'^f2b_docker_verify\(\) \{\n.*?^\}$', body, re.M | re.S)
    if match and ('f2b-diagnostic-membership.py --docker-check' in match[0] or
                  'f2b-runtime-verify.py --docker-check' in match[0]):
        target = (wrapper.parent.parent / 'libexec/f2b-diagnostic-membership.py'
                  if 'f2b-diagnostic-membership.py' in match[0]
                  else wrapper.parent.parent / 'libexec/f2b-runtime-verify.py')
        if target.is_file() and 'def diagnostic_action_sets(' in target.read_text():
            return 'read-only exact IPv4/IPv6 loaded-action membership and Docker union'
        if target.is_file() and '--docker-check' in target.read_text():
            return 'read-only IPv4/IPv6 membership; older effective-configuration resolver'
        return 'diagnostic forwarding route present; checker capability unavailable'
    return 'legacy diagnostic; not verified as exact dual-family membership'


def human(report, scope='all'):
    active, sample, events = report['active'], report['http_sample'], report['fail2ban_events_24h']
    text = ('Reporting schema 2; scope=' + scope + '; last 24h ending ' + report['as_of_utc'] + '\n' +
            'Active ban records across jails: ' + str(active['ban_records_across_jails']) +
            '; unique IPv4=' + str(active['unique_ipv4']) + '; unique IPv6=' + str(active['unique_ipv6']) +
            '; unique union=' + str(active['unique_union']) + '\n')
    if scope != 'ssh-only':
        text += ('HTTP latest chronological parsed sample: raw=' + str(sample['raw_records']) +
            '; explicit trusted probes=' + str(sample['trusted_probe_records']) +
            '; included=' + str(sample['included_records']) + '\n' +
            'Raw HTTP error records: ' + str(sample['raw_http_errors']) + '/' + str(sample['raw_records']) +
            '; security-candidate records: ' + str(sample['candidate_records']) + '/' + str(sample['included_records']) + '\n')
    if scope != 'npm-only': text += 'SSH Fail2Ban events (not all auth attempts): ' + json.dumps(report['ssh_events_24h'], sort_keys=True) + '\n'
    return text + ('All-jail Fail2Ban observed 24h events: ' + json.dumps(events, sort_keys=True) + '\n' +
                   'Log coverage: ' + json.dumps(report['coverage'], sort_keys=True) + '\n' + report['interpretation'])


def terminal_text(value):
    # Log-derived paths/jails may contain control sequences. Render as text,
    # never allow a request target to inject terminal escapes or extra rows.
    return ''.join(c if c.isprintable() else '\\u%04x' % ord(c) for c in str(value))


def full_human(report, scope='all', color=False):
    width = 86
    lines = []
    def row(text=''):
        text = terminal_text(text)
        for part in textwrap.wrap(text, width - 4, break_on_hyphens=False, replace_whitespace=False) or ['']:
            lines.append('│ ' + part.ljust(width - 4) + ' │')
    def section(title):
        lines.append('├' + '─' * (width - 2) + '┤')
        row(title)
        if color: lines[-1] = '\x1b[1;36m' + lines[-1] + '\x1b[0m'
    def number(value): return 'unavailable' if value is None else str(value)
    def top(title, items, available):
        row(title)
        if not available: row('  unavailable: no matching log files')
        elif not items: row('  no observed records in selected sample')
        for key, count in items: row('  ' + str(count).rjust(6) + '  ' + terminal_text(key))
    def events(values):
        for key in ('found', 'new_ban', 'restored_ban', 'extended_ban', 'unban'):
            row('  ' + key.ljust(17) + number(values[key]))
    active, sample, coverage = report['active'], report['http_sample'], report['coverage']
    lines.append('┌' + '─' * (width - 2) + '┐')
    row('ATTACK ANALYSIS | schema 2 | scope=' + scope)
    row('Observed records and request indicators; not confirmed independent attacks')
    row('UTC window: ' + report['cutoff_utc'] + ' -> ' + report['as_of_utc'])
    section('ACTIVE BAN SNAPSHOT — all jails, not a health verdict')
    row('Ban records across jails: ' + str(active['ban_records_across_jails']))
    row('Unique IPv4: ' + str(active['unique_ipv4']) + ' | IPv6: ' + str(active['unique_ipv6']) +
        ' | union: ' + str(active['unique_union']))
    if scope != 'ssh-only':
        available = bool(coverage['http']['files'])
        section('HTTP — exact 24h observations and bounded chronological sample')
        row('Coverage: ' + coverage['http']['availability'])
        row('24h parsed records: ' + number(report['http_window']['parsed_records']) +
            ' | raw HTTP errors: ' + number(report['http_window']['raw_http_errors']))
        row('Sample: latest ' + str(sample['raw_records']) + ' / limit ' + str(sample['limit']) +
            ' records BEFORE explicit trusted-probe exclusions')
        row('Trusted probes: ' + str(sample['trusted_probe_records']) + ' | included: ' + str(sample['included_records']))
        if available:
            row('Raw HTTP error records: ' + str(sample['raw_http_errors']) + '/' + str(sample['raw_records']))
            row('Security-candidate records: ' + str(sample['candidate_records']) + '/' + str(sample['included_records']))
        else: row('HTTP error/candidate activity: unavailable (empty sample is not zero traffic)')
        section('TOP REQUEST PATHS — raw sample, query values omitted')
        top('Raw sample paths (includes trusted probes):', report['presentation_top']['raw_sample_paths'], available)
        top('Candidate paths (included sample only):', report['presentation_top']['included_candidate_paths'], available)
        top('Candidate category hits (overlap; DO NOT sum as attempts):',
            sorted(sample['category_hits'].items(), key=lambda item: (-item[1], item[0])), available)
    if scope != 'npm-only':
        section('SSH JAIL SIGNALS — not every raw authentication attempt')
        events(report['ssh_events_24h'])
    section('FAIL2BAN EVENTS — all jails, observed last 24h')
    events(report['fail2ban_events_24h'])
    row('Top event jails (Found/Ban may overlap; not unique attackers):')
    if not coverage['fail2ban']['files']: row('  unavailable: no matching log files')
    elif not report['presentation_top']['event_jails']: row('  no observed event records')
    for item in report['presentation_top']['event_jails']:
        row('  ' + item['jail'] + ': ' + ', '.join(k + '=' + str(v) for k, v in sorted(item['events'].items())))
    section('FOUND TIMELINE — all jails, 24 UTC bins anchored at window start')
    bins = report['found_timeline']
    peak = max((b['found_records'] or 0 for b in bins), default=0)
    for item in bins:
        count = item['found_records']
        bar = '' if count is None else '█' * (max(1, round(count / peak * 25)) if count else 0)
        row(item['start_utc'][5:16].replace('T', ' ') + ' UTC  ' + number(count).rjust(11) + '  ' + bar)
    section('COVERAGE AND INTERPRETATION')
    for source, values in coverage.items():
        if source == 'http' and scope == 'ssh-only': row('http: not selected (--ssh-only)'); continue
        row(source + ': ' + values['availability'] + '; files=' + str(values['files']) +
            '; unparsed=' + str(values['unparsed_lines']) + '; invalid=' + str(values['invalid_records']) +
            '; ambiguous DST=' + str(values['ambiguous_local_time_records']))
    row('Log presence does not prove complete 24h coverage. Repeated records are not deduplicated.')
    row(report['interpretation'])
    lines.append('└' + '─' * (width - 2) + '┘')
    return '\n'.join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default="/etc/f2b/reporting.ini")
    parser.add_argument('--report', choices=('json', 'csv', 'daily', 'analysis', 'timeline', 'trends', 'audit', 'stats', 'version'))
    parser.add_argument('--npm-dir')
    parser.add_argument('--scope', choices=('all', 'npm-only', 'ssh-only'), default='all')
    parser.add_argument('--format', choices=('human', 'json', 'short', 'full'), default='human')
    parser.add_argument('--version', default='unknown')
    parser.add_argument('--release', default='unknown')
    parser.add_argument('--builddate', default='unknown')
    parser.add_argument('--component', default='unknown')
    parser.add_argument('--docker-version', default='unknown')
    parser.add_argument('--validate-config', action='store_true')
    args = parser.parse_args()
    try:
        if args.validate_config:
            settings = report_settings(Path(args.config), args.npm_dir)
            print('PASS: reporting configuration; explicit probe rules=' + str(len(settings['rules'])))
            return 0
        if args.report == 'version':
            if args.format == 'short': print(args.version); return 0
            try: active = runtime_snapshot(); count = len(active['jails'])
            except Exception: count = None
            value = {'release': args.release, 'version': args.version, 'builddate': args.builddate,
                     'component': args.component, 'dockerblock_version': args.docker_version,
                     'reporting_schema': 2, 'fail2ban_jails': count, 'diagnostics': diagnostic_label()}
            print(json.dumps(value, sort_keys=True) if args.format == 'json' else
                  args.release + ' (' + args.version + ')\nBuild: ' + args.builddate + '\nReporting schema: 2\nDiagnostics: ' + value['diagnostics'])
            return 0
        if args.report:
            if os.geteuid() != 0: raise ValueError('Run reporting with sudo')
            active = runtime_snapshot()
            if args.report in {'audit', 'stats'}:
                print(json.dumps(active, sort_keys=True)); return 0
            if args.report == 'csv':
                writer = csv.writer(sys.stdout); writer.writerow(['snapshot_utc', 'jail', 'active_ban_records'])
                for jail, count in sorted(active['jails'].items()): writer.writerow([active['snapshot_utc'], jail, count])
                return 0
            settings = report_settings(Path(args.config), args.npm_dir)
            report = build_report(settings, runtime=active, scope=args.scope)
            report['scope'] = args.scope
            if args.report == 'json': print(json.dumps(report, sort_keys=True))
            elif args.report == 'trends': print(json.dumps({'as_of_utc': report['as_of_utc'], 'observed_event_records_by_window_hours': report['trends'],
                                                           'coverage': report['coverage']['fail2ban'], 'interpretation': report['interpretation']}, sort_keys=True))
            elif args.report == 'timeline': print(json.dumps({'as_of_utc': report['as_of_utc'], 'found_timeline': report['found_timeline'],
                                                             'events_24h': report['fail2ban_events_24h'], 'coverage': report['coverage']['fail2ban']}, sort_keys=True))
            elif args.report == 'analysis' and args.format != 'short':
                color = sys.stdout.isatty() and os.environ.get('TERM', '') != 'dumb' and 'NO_COLOR' not in os.environ
                print(full_human(report, args.scope, color=color))
            else: print(human(report, args.scope))
            return 0
        rules = load_rules(Path(args.config))
    except Exception as exc:
        print(f"f2b-report-filter: {exc}", file=sys.stderr)
        return 2
    for line in sys.stdin:
        if not any(rule.matches(line) for rule in rules):
            sys.stdout.write(line)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
