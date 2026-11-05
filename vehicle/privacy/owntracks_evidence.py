"""Evidence rules for the pinned OwnTracks sample. 仅用于授权测试。"""
import hashlib
import json
import re
from collections import defaultdict
from decimal import Decimal, ROUND_HALF_UP

from core.collector.attribution import ATTRIB_LOOSE_MS
from core.collector.identity import uid_of, user_of
from vehicle.analyze.pair_ambiguity import annotate_candidates
from vehicle.privacy.owntracks_contract import PACKAGE

WINDOW_MS = 30_000
READ_RULE = 'VSC-LAB-OWNTRACKS-LOCATION-001'
BODY_RULE = 'VSC-LAB-OWNTRACKS-HTTP-001'
SOURCES = ['vehicle/privacy/owntracks_contract.py', 'vehicle/privacy/owntracks_evidence.py',
           'vehicle/lab/SAMPLE_RUNTIME_REVIEW.md']


def coordinate_digest(values):
    clean = []
    for value, limit in zip(values, (90, 180), strict=True):
        if type(value) not in (float, int) or not -limit <= value <= limit:
            return None
        # Match the Hook's Number(toFixed(6)) followed by JSON.stringify.
        rounded = Decimal(value).quantize(Decimal('0.000001'), rounding=ROUND_HALF_UP)
        clean.append(format(rounded, 'f').rstrip('0').rstrip('.') if rounded else '0')
    return hashlib.sha256(('[' + ','.join(clean) + ']').encode()).hexdigest()[:16]


def _unique_fields(pairs):
    fields = dict(pairs)
    if len(fields) != len(pairs):
        raise ValueError('duplicate JSON fields')
    return fields


def summarize_body(raw):
    if not isinstance(raw, (str, bytes)) or len(raw) > 16384:
        return {}
    try:
        data = json.loads(raw, object_pairs_hook=_unique_fields)
    except (ValueError, RecursionError):
        return {}
    if not isinstance(data, dict) or data.get('_type') != 'location':
        return {}
    key = coordinate_digest((data.get('lat'), data.get('lon')))
    if key is None or type(data.get('tst')) is not int:
        return {}
    return {'coordinate_sha256_16': key, 'location_timestamp_seconds': data['tst']}


def _identity(row, session, user):
    return (row.get('session_id') == session and uid_of(row) is not None
            and user_of(row) == row.get('user_id') == user)


def location_read(row, session, user):
    return (row.get('src') == 'owntracks_location' and row.get('ev') == 'OWNTRACKS_LOCATION'
            and row.get('pkg') == PACKAGE and _identity(row, session, user)
            and all(type(row.get(k)) is int and row[k] > 0 for k in
                    ('evt_id', 'pid', 'host_received_ts', 'location_time_ms'))
            and isinstance(key := row.get('coordinate_sha256_16'), str)
            and re.fullmatch('[a-f0-9]{16}', key) is not None)


def location_post(flow, session, user):
    payload = flow.get('request_payload')
    delta = flow.get('attribution_delta_ms')
    if (flow.get('package') != PACKAGE or not _identity(flow, session, user)
            or flow.get('src', 'proxy') != 'proxy'
            or not all(type(flow.get(k)) is int and flow[k] > 0 for k in ('evt_id', 'ts'))
            or flow.get('attribution') != 'app_process_hook' or flow.get('attribution_ambiguous')
            or type(delta) is not int or abs(delta) >= ATTRIB_LOOSE_MS
            or flow.get('method') != 'POST' or flow.get('status_code') != 200
            or flow.get('terminal') or flow.get('failure_kind')
            or not isinstance(payload, dict) or any(payload.get(k) for k in
                ('raw_truncated', 'text_truncated', 'decode_error'))
            or not isinstance(sha := payload.get('raw_sha256'), str)
            or re.fullmatch('[a-f0-9]{64}', sha) is None):
        return {}
    return summarize_body(payload.get('text'))


def matches(read, flow, body):
    return (read['uid'] == flow['uid'] and read['coordinate_sha256_16'] == body['coordinate_sha256_16']
            and read['location_time_ms'] // 1000 == body['location_timestamp_seconds']
            and 0 <= flow['ts'] - read['host_received_ts'] <= WINDOW_MS)


def _finding(reads, rule_id):
    direct = rule_id == READ_RULE
    first = reads[0]
    return {'rule_id': rule_id, 'rule_revision': 1, 'rule_enabled': True, 'rule_android_version': '15',
            'rule_registry': 'owntracks_lab_evidence', 'rule_type': 'sensitive_read' if direct else 'data_egress',
            'severity': 'info', 'conclusion_level': 'observed' if direct else 'candidate',
            'evidence_kind': 'read_event' if direct else 'read_then_egress',
            'predicate': 'obtained_owntracks_location_callback' if direct else 'same_location_in_owntracks_http',
            'package': PACKAGE, 'session_id': first['session_id'], 'uid': first['uid'], 'user_id': first['user_id'],
            'property': 'location', 'data_type': 'location', 'data_type_name': '位置（OwnTracks 侧载对照）',
            'read_count': len(reads), 'event_ids': [r['evt_id'] for r in reads],
            'event_refs': [{'src': r['src'], 'evt_id': r['evt_id']} for r in reads],
            'basis_refs': SOURCES, 'source_refs': SOURCES}


def evaluate(reads, flows, session, user, endpoint_host='198.18.0.1'):
    from vehicle.privacy.owntracks_endpoint import allowed_host
    if not allowed_host(endpoint_host):
        raise ValueError('invalid owned OwnTracks receiver host')
    grouped = defaultdict(list)
    for read in reads:
        if location_read(read, session, user):
            grouped[read['uid']].append(read)
    pairs_by_uid, matched_requests = defaultdict(list), set()
    for flow in flows:
        path = flow.get('path')
        if (flow.get('scheme') != 'http' or flow.get('intercepted_tls')
                or flow.get('host') != endpoint_host or flow.get('target_port') != 18145
                or not isinstance(path, str) or not re.fullmatch('/owntracks/[a-f0-9]{16}', path)):
            continue
        body = location_post(flow, session, user)
        if not body:
            continue
        for read in grouped.get(flow['uid'], ()):
            if matches(read, flow, body):
                matched_requests.add(flow['evt_id'])
                pairs_by_uid[flow['uid']].append({
                    'read_src': read['src'], 'read_event_id': read['evt_id'],
                    'flow_src': 'proxy', 'flow_event_id': flow['evt_id'], 'uid': flow['uid'],
                    'delta_ms': flow['ts'] - read['host_received_ts'], 'clock_basis': 'host_received_ts',
                    'content_match': True, 'value_match': True, 'identity_scope': 'uid_verified', 'client_tls': False,
                    'content_match_basis': 'owntracks_coordinate_digest_and_location_timestamp',
                })
    findings = []
    for uid, hits in grouped.items():
        findings.append(_finding(hits, READ_RULE))
        if pairs := pairs_by_uid[uid]:
            matched_ids = {p['read_event_id'] for p in pairs}
            findings.append(dict(_finding([r for r in hits if r['evt_id'] in matched_ids], BODY_RULE),
                pairs=pairs, pair_count=len(pairs), window_ms=WINDOW_MS, window_declared_ms=WINDOW_MS,
                window_overridden=False, content_match=True, value_match=True,
                source_ambiguous_flows=annotate_candidates(pairs),
                correlation_scope='matching_content_candidates_origin_unproven',
                note='侧载对照的回调与 HTTP 正文同值；独立服务端回执由业务验收另行核验。'))
    return findings, {'scope': 'aaos_sideload_comparison', 'scoring': 'workflow_only',
                      'callback_events': sum(map(len, grouped.values())), 'matched_requests': len(matched_requests)}
