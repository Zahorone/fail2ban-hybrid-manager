#!/usr/bin/python3
"""Endpoint semantic preservation, not proof of absence of transient writers.

nft JSON expiry is seconds. Integer output bounds the absolute expiry to a
one-second interval; fractional output gets a millisecond allowance. Refuse
uncertain changes rather than relaxing membership or refreshing any ban.
"""
import json
import math
import time


def normalized(document, start, end):
    if not 0 <= end - start <= 2:
        raise ValueError('Runtime snapshot sampling window too wide to verify expiry')
    counters, sets = {}, {}

    def clean(value, path, counts, parent=None):
        if isinstance(value, dict):
            result = {}
            for key, item in value.items():
                if key == 'handle': continue  # kernel identity, not rule semantics
                if parent == 'counter' and key in {'packets', 'bytes'}:
                    if type(item) is not int or item < 0: raise ValueError('Unsupported runtime counter')
                    counts[json.dumps(path + [key])] = item
                    result[key] = 0
                else: result[key] = clean(item, path + [key], counts, key)
            return result
        if isinstance(value, list): return [clean(item, path + [index], counts) for index, item in enumerate(value)]
        return value

    rows = []
    for row in document['nftables']:
        if 'metainfo' in row: continue
        row = dict(row)
        for kind in ('set', 'map', 'element'):
            if kind not in row: continue
            payload = dict(row[kind]); identity = json.dumps([payload.get('family'), payload.get('table'), payload.get('name')])
            # nft may omit elem entirely for an empty set. Normalize only the
            # unordered membership, NEVER rule/expression ordering.
            members = sets.setdefault(identity, {})
            for element in payload.pop('elem', []):
                wrapped = isinstance(element, dict) and set(element) == {'elem'}
                meta = dict(element['elem']) if wrapped else {'val': element}
                if 'val' not in meta: raise ValueError('Unsupported runtime element representation')
                key = json.dumps(meta['val'], sort_keys=True, separators=(',', ':'))
                if key in members: raise ValueError('Duplicate runtime member; cannot verify')
                remaining = meta.pop('expires', None)
                expiry = None
                if remaining is not None:
                    if type(remaining) not in {int, float} or not math.isfinite(remaining) or remaining < 0:
                        raise ValueError('Unsupported runtime expiry')
                    resolution = 1 if type(remaining) is int else .001
                    expiry = [start + remaining - .02, end + remaining + resolution + .02]
                counts = {}
                members[key] = {'body': clean(meta, [], counts), 'counters': counts, 'expiry': expiry}
            row[kind] = payload
        rows.append(clean(row, [len(rows)], counters))
    return {'start': start, 'end': end, 'body': rows, 'counters': counters, 'sets': sets}


def capture(run):
    start = time.monotonic()
    document = json.loads(run('nft', '-j', 'list', 'ruleset'))
    return normalized(document, start, time.monotonic())


def compare(before, after):
    def counts(old, new):
        if old.keys() != new.keys() or any(new[key] < value for key, value in old.items()):
            raise ValueError('Runtime counter structure changed or counter reset')

    if before['body'] != after['body'] or before['sets'].keys() != after['sets'].keys():
        raise ValueError('Runtime structure/rule order/schema changed during preparation (possibly concurrent writer)')
    counts(before['counters'], after['counters'])
    expired = 0
    for name, old_members in before['sets'].items():
        new_members = after['sets'][name]
        if new_members.keys() - old_members.keys(): raise ValueError('Runtime membership added during preparation (possibly concurrent ban)')
        for key, old in old_members.items():
            new = new_members.get(key)
            if new is None:
                if old['expiry'] is not None and old['expiry'][1] <= after['start']:
                    expired += 1; continue
                raise ValueError('Runtime membership removed before proven natural expiry (possibly concurrent unban)')
            if old['body'] != new['body']: raise ValueError('Runtime element value/timeout metadata changed')
            counts(old['counters'], new['counters'])
            left, right = old['expiry'], new['expiry']
            if (left is None) != (right is None): raise ValueError('Runtime timed/permanent membership changed')
            if left is not None and max(left[0], right[0]) > min(left[1], right[1]):
                raise ValueError('Runtime absolute expiry changed beyond sampling/JSON precision')
    return expired
