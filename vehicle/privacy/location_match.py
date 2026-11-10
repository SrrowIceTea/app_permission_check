"""Limited offline location-content candidates. 仅用于授权测试；不生成规则结论。"""
import math
import re
from collections import Counter, defaultdict

from core.collector.attribution import is_loose
from core.collector.identity import compatible, identity_scope, uid_of, user_of
from core.privacy.semantics import read_state
from vehicle.analyze.pair_ambiguity import annotate_candidates
from vehicle.privacy.location_payload import request_values

PAIR_FORMS = ('pair_d6', 'pair_d6_lonlat', 'pair_raw', 'pair_raw_lonlat', 'geo_d6')
ATTRIBUTIONS = ('app_process_hook', 'system_sample', 'native_http_write')
LIMITS = [
    'experimental_only; no registered location egress rule; no findings emitted',
    'complete outgoing JSON string leaves containing a whole coordinate pair only',
    'numeric leaves, separate coordinates, other precision, form/protobuf not supported',
    'same content is not unique origin, causal propagation, endpoint receipt or a violation',
    'no match means not observed within this limited method, never absence of egress',
    'host_received_ts/ts in milliseconds; configurable window is not calibrated for location',
]


def _number(value):
    return (type(value) is int or type(value) is float and math.isfinite(value)) and value >= 0


def _ref(row, process_scoped=False):
    return (isinstance(row.get('src'), str) and bool(row['src'])
            and type(row.get('evt_id')) is int and row['evt_id'] >= 0
            and (not process_scoped and row.get('pid') is None
                 or type(row.get('pid')) is int and row['pid'] > 0))


def _identity(row):
    return (uid_of(row) is not None and uid_of(row) % 100000 >= 10000
            and type(row.get('user_id')) is int and row['user_id'] == user_of(row))


def _digest(value, length):
    return (isinstance(value, str) and re.fullmatch('[0-9a-f]{16}', value) is not None
            and type(length) is int and 8 <= length <= 256)


def _forms(row):
    if row.get('value_kind') != 'location_pair' or row.get('location_fix'):
        return {}, 'no_usable_location_pair'
    if row.get('location_form') not in PAIR_FORMS or not _digest(
            row.get('value_hash'), row.get('value_len')):
        return {}, 'invalid_primary_location_form'
    forms = row.get('location_forms')
    if forms is None:
        forms = [{'form': row['location_form'], 'hash': row['value_hash'], 'len': row['value_len']}]
    if not isinstance(forms, list) or len(forms) > 7:
        return {}, 'invalid_location_forms'
    result = {}
    for item in forms:
        if not isinstance(item, dict):
            return {}, 'invalid_location_forms'
        form = item.get('form')
        if form not in PAIR_FORMS:
            continue  # Never use single_lat_d6 or single_lon_d6, even together.
        if not _digest(item.get('hash'), item.get('len')) or form in result:
            return {}, 'invalid_location_forms'
        result[form] = (item['hash'], item['len'])
    if result.get(row['location_form']) != (row['value_hash'], row['value_len']):
        return {}, 'primary_location_form_conflict'
    return result, None


def _deduplicate(rows, diagnostics, process_scoped=False):
    groups = defaultdict(list)
    for row in rows:
        if not _ref(row, process_scoped):
            diagnostics['invalid_event_reference'] += 1
            continue
        groups[row['src'], row.get('pid'), row['evt_id']].append(row)
    result = []
    for group in groups.values():
        if any(row != group[0] for row in group[1:]):
            diagnostics['conflicting_event_reference'] += len(group)
        else:
            result.append(group[0])
            diagnostics['duplicate_event_reference'] += len(group) - 1
    return result


def evaluate(reads, flows, package, session, *, window_ms=30000):
    """Explicit experiment API; inputs untouched; results never enter findings/summary.

    Package/session arguments are the scope; they must come from the authorised
    capture manifest at the CLI boundary. This function does not certify capture health.
    """
    if not isinstance(package, str) or not package or not isinstance(session, str) or not session:
        raise ValueError('Explicit non-empty package/session required')
    if type(window_ms) is not int or window_ms <= 0:
        raise ValueError('window_ms must be a positive integer')
    diagnostics, candidates, usable = Counter(), [], []
    scoped_reads = [r for r in reads if isinstance(r, dict) and r.get('pkg') == package
                    and r.get('session_id') == session and r.get('ev') == 'PRIVACY_READ'
                    and 'location' in (r.get('data_types') or [])]
    scoped_flows = [f for f in flows if isinstance(f, dict) and f.get('package') == package
                    and f.get('session_id') == session]
    if not scoped_reads:
        diagnostics['no_scoped_general_location_reads'] += 1
    if not scoped_flows:
        diagnostics['no_scoped_flows'] += 1
    for row in _deduplicate(scoped_reads, diagnostics, process_scoped=True):
        if read_state(row) != 'obtained':
            diagnostics['location_not_obtained'] += 1
            continue
        if (not _identity(row) or not _number(row.get('host_received_ts'))
                or row.get('clock_basis', 'host_received_ts') != 'host_received_ts'):
            diagnostics['read_identity_or_clock_unavailable'] += 1
            continue
        forms, reason = _forms(row)
        if reason:
            diagnostics[reason] += 1
        else:
            candidates.append((row, forms))
    for row in _deduplicate(scoped_flows, diagnostics):
        if (not _identity(row) or row.get('attribution') not in ATTRIBUTIONS
                or row.get('attribution_ambiguous') or row.get('terminal') or row.get('failure_kind')):
            diagnostics['flow_identity_unresolved_or_failed'] += 1
            continue
        if (not _number(row.get('ts')) or not _number(row.get('attribution_delta_ms'))
                or row.get('clock_basis', 'host_received_ts') != 'host_received_ts'):
            diagnostics['flow_clock_or_attribution_distance_unavailable'] += 1
            continue
        values, reason, provenance = request_values(row)
        if reason:
            diagnostics[reason] += 1
        else:
            usable.append((row, values, provenance))
    pairs = []
    for read, forms in candidates:
        for flow, values, provenance in usable:
            delta = flow['ts'] - read['host_received_ts']
            if not compatible(read, flow) or not 0 <= delta <= window_ms:
                continue
            matched = [name for name, value in forms.items() if value in values]
            if not matched:
                continue
            pairs.append({'read_src': read['src'], 'read_event_id': read['evt_id'],
                'read_pid': read['pid'], 'flow_pid': flow.get('pid'),
                'flow_src': flow['src'], 'flow_event_id': flow['evt_id'],
                'uid': read['uid'], 'user_id': read['user_id'], 'delta_ms': delta,
                'clock_basis': 'host_received_ts', 'identity_scope': identity_scope(read, flow),
                'evidence_level': 'content_match_candidate', 'content_match': True,
                'content_match_basis': 'complete_outgoing_json_whole_coordinate_pair_string',
                'value_transform': 'hook_recorded_canonical_coordinate_pair',
                'payload_provenance': provenance,
                'matched_forms': [{'form': name, 'hash': forms[name][0], 'len': forms[name][1]}
                                  for name in matched],
                'attribution_loose': is_loose(flow), 'origin_proven': False})
    ambiguous = annotate_candidates(pairs)
    return {'schema_version': 1, 'experimental_only': True, 'emits_rule_findings': False,
        'package': package, 'session_id': session, 'window_ms': window_ms,
        'window_calibrated_for_location': False,
        'status': 'content_candidates' if pairs else 'not_observed_within_supported_scope',
        'inputs': {'scoped_location_reads': len(scoped_reads), 'scoped_flows': len(scoped_flows),
                   'comparable_reads': len(candidates), 'comparable_flows': len(usable)},
        'pairs': pairs, 'pair_count': len(pairs), 'ambiguous_flows': ambiguous,
        'matched_form_counts': dict(Counter(f['form'] for p in pairs for f in p['matched_forms'])),
        'diagnostics': {k: v for k, v in sorted(diagnostics.items()) if v}, 'limits': LIMITS.copy()}
