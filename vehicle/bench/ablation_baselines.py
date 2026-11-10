"""Weak baseline and claim counting for the AAOS ablation. 仅用于授权测试。

Split out of ``ablation.py`` to stay under the repository's 300-line cap.
``weak_findings`` is the "property-name hit + fixed window" baseline: it must
check that the property name/id actually appears in the request (review P2-5),
otherwise it is just the rule binding with a wider net.
"""
from __future__ import annotations

import json


def unique_source_sets(findings):
    """Count flow+rule groups where the detector claims exactly one source.

    Same unit as ``source_candidates`` (one set per flow+rule), so the two
    numbers are comparable. Counting raw pairs (an earlier version) mixed units
    and made the delta meaningless (review P1-3).
    """
    groups = {}
    for finding in findings:
        for pair in finding.get('pairs') or []:
            key = (pair.get('flow_src', 'proxy'), pair.get('flow_event_id'),
                   pair.get('uid'), finding.get('rule_id'))
            groups.setdefault(key, []).append(pair)
    return sum(1 for rows in groups.values()
               if len({row.get('read_event_id') for row in rows}) == 1
               and all(row.get('source_read_unique') is True for row in rows))


def rule_prop_map(rules):
    mapping = {}
    for rule in rules:
        if not rule['enabled'] or rule['rule_type'] != 'data_egress':
            continue
        prop = json.loads(rule['condition_json']).get('property_id')
        mapping.setdefault(prop, []).append(rule['rule_id'])
    return mapping


def property_marker_hit(read, flow):
    """Property name/id present in the request -- NOT a value-level match.

    Review P2-5: the earlier weak baseline paired every flow in the window and
    only used ``prop_id`` to look up a rule, so it never checked the property
    name at all. Mirrors the token branch of ``value_match.match_content``.
    """
    tokens = {str(token) for token in (flow.get('request_tokens') or [])}
    markers = {str(read.get('prop_name')), str(read.get('prop_id'))}
    if tokens & markers:
        return True
    text = (flow.get('request_payload') or {}).get('text')
    return isinstance(text, str) and any(marker in text for marker in markers
                                         if marker != 'None')


def weak_findings(reads, flows, rules, window_ms, clock_offset_ms=None):
    """Baseline: package/session + property-name hit + time window only."""
    mapping = rule_prop_map(rules)
    usable = [f for f in flows if not f.get('terminal') and not f.get('failure_kind')]
    grouped = {}
    for read in reads:
        if (read.get('ev') != 'VHAL_READ' or read.get('outcome') != 'ok'
                or not read.get('pkg')):
            continue
        ts = read.get('host_received_ts')
        if ts is None:
            ts = read['ts'] - clock_offset_ms if clock_offset_ms is not None else None
        if ts is None:
            continue
        for flow in usable:
            if (flow.get('package') != read['pkg']
                    or flow.get('session_id') != read.get('session_id')):
                continue
            delta = flow['ts'] - ts
            if not 0 <= delta <= window_ms:
                continue
            if not property_marker_hit(read, flow):
                continue
            for rule_id in mapping.get(read.get('prop_id'), ()):
                pair = {'read_src': read.get('src') or 'vhal',
                        'read_event_id': read['evt_id'],
                        'flow_src': flow.get('src') or 'proxy',
                        'flow_event_id': flow['evt_id'], 'delta_ms': delta,
                        'content_match': False, 'value_match': False,
                        'pair_basis': 'property_name_in_window'}
                grouped.setdefault(rule_id, []).append(pair)
    return [{'rule_id': rule_id, 'evidence_kind': 'read_then_egress',
             'conclusion_level': 'correlated', 'pairs': pairs}
            for rule_id, pairs in grouped.items()]
