"""General-source facts and conservative JSON value correlation. 授权测试专用。"""
import hashlib
import json
import re
import sqlite3
from collections import Counter, defaultdict
from pathlib import Path
from core.collector.identity import compatible, identity_scope, uid_of, user_of
from core.collector.attribution import is_loose
from core.privacy.semantics import read_state
from vehicle.privacy.catalog import AAID, TYPES, catalog_hash
from vehicle.analyze.pair_ambiguity import annotate_candidates

RULE_DB = Path(__file__).resolve().parents[1] / 'rules/rules_library/rules.db'

# '13'/'14' are AOSP source rows and '15' is the device-observed row set; each
# resolves to its own rows so a finding never borrows a neighbour's provenance.
# android-16 rows are not built yet, so '16' still borrows '15' and the finding
# reports rule_version_basis=nearest_registered_row_api_surface; switch it to
# '16' together with the baseline_android16 rows.
ROW_VERSION = {'13': '13', '14': '14', '15': '15', '16': '15'}


def load_general_rules(version='15', db=RULE_DB):
    """Findings must resolve to a registered rule row; fail closed when they do not.

    2026-11-02: the rule IDs were emitted by this module while rules.db had zero
    matching rows, so no finding could be looked up. severity / revision / enabled
    now come from the library instead of being restated here.
    """
    requested = str(version)
    row_version = ROW_VERSION.get(requested)
    if row_version is None:
        raise ValueError(f'通用隐私规则未登记平台：{requested}')
    conn = sqlite3.connect(f'file:{db.resolve().as_posix()}?mode=ro', uri=True)
    conn.row_factory = sqlite3.Row
    try:
        rows = {r['rule_id']: dict(r) for r in conn.execute(
            "SELECT * FROM risk_rules WHERE android_version = ? AND rule_id LIKE 'VSC-G%'",
            (row_version,))}
    finally:
        conn.close()
    if not rows:
        raise ValueError(f'通用隐私规则未登记：{db} android_version={row_version}')
    return rows


def request_hashes(flow):
    """Only complete outgoing JSON string leaves, never previews or responses."""
    payload = flow.get('request_payload')
    if not isinstance(payload, dict) or any(payload.get(k) for k in
            ('raw_truncated', 'text_truncated', 'decode_error')):
        return set()
    text = payload.get('text')
    if not isinstance(text, str) or len(text) > 2 * 1024 * 1024:
        return set()
    try:
        stack = [json.loads(text)]
    except (ValueError, RecursionError):
        return set()
    hashes, count = set(), 0
    while stack and count < 10000:
        node = stack.pop(); count += 1
        if isinstance(node, dict):
            stack.extend(node.values())
        elif isinstance(node, list):
            stack.extend(node)
        elif isinstance(node, str) and len(node) >= 8:
            hashes.add(hashlib.sha256(node.encode('utf-8')).hexdigest()[:16])
    return hashes


def evidence(dtype, hits, egress, rule, platform=None, catalog_revision=2):
    rule_id = ('VSC-GE-' if egress else 'VSC-GR-') + dtype
    expected = 'data_egress' if egress else 'sensitive_read'
    if rule['rule_id'] != rule_id or rule['rule_type'] != expected:
        raise ValueError(f'规则登记与求值器不一致：{rule["rule_id"]}/{rule["rule_type"]}')
    requested = str(platform if platform is not None else rule['android_version'])
    return {'rule_id': rule_id,
        'rule_android_version': rule['android_version'],
        'rule_version_basis': ('registered_for_platform'
            if requested == rule['android_version'] else 'nearest_registered_row_api_surface'),
        'platform': requested,
        'rule_revision': rule['rule_revision'], 'rule_enabled': bool(rule['enabled']),
        'rule_type': rule['rule_type'], 'severity': rule['severity'],
        'conclusion_level': rule['conclusion_level'],
        'evidence_kind': 'read_then_egress' if egress else 'read_event',
        'predicate': 'same_value_in_outgoing_json' if egress else 'obtained_general_privacy_data',
        'property': dtype, 'data_type': dtype, 'data_type_name': TYPES[dtype]['name'],
        'package': hits[0]['pkg'], 'uid': uid_of(hits[0]), 'user_id': user_of(hits[0]),
        'session_id': hits[0]['session_id'], 'read_count': len(hits),
        'event_ids': [r['evt_id'] for r in hits],
        'event_refs': [{'src': r['src'], 'evt_id': r['evt_id']} for r in hits],
        'basis_refs': json.loads(rule['basis_refs_json']),
        'source_refs': json.loads(rule['source_refs_json']),
        'privacy_catalog_sha256': catalog_hash(catalog_revision),
        'note': '返回值证据；调用成功不等于取得数据。政策与必要性仍需人工复核。'}


def evaluate(reads, flows, package, session, version='15', rules=None, *, catalog_revision=2):
    rules = rules if rules is not None else load_general_rules(version)
    events = [r for r in reads if r.get('ev') == 'PRIVACY_READ'
              and r.get('pkg') == package and r.get('session_id') == session]
    types = {k: v for k, v in TYPES.items() if catalog_revision != 1 or k != AAID}
    grouped = defaultdict(list)
    for read in events:
        if read_state(read) != 'obtained' or uid_of(read) is None:
            continue
        if read.get('user_id', user_of(read)) != user_of(read):
            continue
        for dtype in read.get('data_types', []):
            if dtype in types:
                grouped[dtype, uid_of(read)].append(read)
    usable = [(f, request_hashes(f)) for f in flows if f.get('package') == package
        and f.get('session_id') == session and uid_of(f) is not None
        and f.get('user_id', user_of(f)) == user_of(f)
        and not f.get('terminal') and not f.get('failure_kind')
        and not f.get('attribution_ambiguous') and f.get('attribution') not in
            (None, 'unresolved', 'ambiguous', 'single_package_fallback')]
    findings = []
    for (dtype, uid), hits in grouped.items():
        read_rule = rules.get('VSC-GR-' + dtype)
        if read_rule is None:
            raise ValueError(f'VSC-GR-{dtype} 未在规则库登记')
        if read_rule['enabled']:
            findings.append(evidence(dtype, hits, False, read_rule, version, catalog_revision))
        pairs = []
        if dtype in ('android_id', 'contacts'):
            egress_rule = rules.get('VSC-GE-' + dtype)
            if egress_rule is None:
                raise ValueError(f'VSC-GE-{dtype} 未在规则库登记')
            if not egress_rule['enabled']:
                continue
            window = egress_rule['window_ms']
            if not window or window <= 0:
                raise ValueError(f'VSC-GE-{dtype} window_ms 必须为正数')
            for read in hits:
                value = read.get('value_hash', '')
                stamp = read.get('host_received_ts')
                if not re.fullmatch('[0-9a-f]{16}', value) or stamp is None or read.get('value_len', 0) < 8:
                    continue
                for flow, hashes in usable:
                    delta = flow.get('ts', -1) - stamp
                    if (not compatible(read, flow) or not 0 <= delta <= window or value not in hashes):
                        continue
                    pairs.append({'read_event_id': read['evt_id'], 'read_src': read['src'],
                        'flow_event_id': flow['evt_id'], 'flow_src': flow.get('src', 'proxy'),
                        'delta_ms': delta, 'clock_basis': 'host_received_ts',
                        'content_match': True, 'value_match': True,
                        'content_match_basis': 'complete_request_json_string_value_hash',
                        'value_transform': 'raw', 'identity_scope': identity_scope(read, flow),
                        'client_tls': flow.get('intercepted_tls'),
                        'attribution_loose': is_loose(flow)})
        if pairs:
            ambiguous_sources = annotate_candidates(pairs)
            paired_ids = {p['read_event_id'] for p in pairs}
            finding = evidence(dtype, [r for r in hits if r['evt_id'] in paired_ids], True, egress_rule,
                               version, catalog_revision)
            finding.update(pairs=pairs, pair_count=len(pairs), value_match=True, content_match=True,
                source_ambiguous_flows=ambiguous_sources,
                correlation_scope='matching_content_candidates_origin_unproven',
                window_ms=window, window_declared_ms=window, window_overridden=False,
                note='同包/会话/UID 的读取值在完整 JSON 请求中出现；相同值相关不证明唯一因果或违规。')
            if any(p['attribution_loose'] for p in pairs):
                finding.update(conclusion_level='candidate',
                               declared_conclusion_level=egress_rule['conclusion_level'],
                               conclusion_capped_by='attribution_loose')
            findings.append(finding)
    return findings, {'events': len(events), 'states': dict(Counter(read_state(r) for r in events)),
        'by_data_type': {dtype: dict(Counter(read_state(r) for r in events
            if dtype in r.get('data_types', []))) for dtype in types},
        'catalog_sha256': catalog_hash(catalog_revision),
        'hook_gaps': [r for r in reads if r.get('ev') == 'PRIVACY_GAP'],
        'caveats': [row['gap'] for row in types.values()]}
