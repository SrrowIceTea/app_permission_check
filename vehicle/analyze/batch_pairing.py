"""Corroborate source reads for the sealed owned VHAL fixture. 仅用于授权测试。"""
import hashlib
import json
import re
from collections import Counter

from core.collector.attribution import is_loose
from core.collector.identity import uid_of
from vehicle.analyze.value_match import MAX_TEXT, equal_value, raw_value

FIXTURE_PACKAGE = 'com.vscanner.targetapp'
CLAIM_TOLERANCE_MS = 50
PAIRING_MODES = ('window', 'token', 'both')
TOKEN = re.compile(r'[A-Za-z0-9_-]{8,128}')
PRIMARY_FRAME = re.compile(r'\bcom\.vscanner\.targetapp\.VhalReader\.readOne\(')
CROSS_CHECK_FRAME = re.compile(r'\bcom\.vscanner\.targetapp\.VhalReader\.readFloatCrossCheck\(')


def _parse_batch(flow):
    payload = flow.get('request_payload') or {}
    summary = flow.get('request_parse') or {}
    status = flow.get('status_code')
    text = payload.get('text')
    if (flow.get('package') != FIXTURE_PACKAGE or not flow.get('session_id')
            or flow.get('src') != 'proxy' or uid_of(flow) is None
            or flow.get('attribution_source') != 'egress_hook' or is_loose(flow)
            or flow.get('method') != 'POST' or type(status) is not int or not 200 <= status < 300
            or not isinstance(text, str) or len(text) > MAX_TEXT
            or payload.get('raw_truncated') or payload.get('text_truncated') or payload.get('decode_error')
            or summary.get('heuristic') or summary.get('parse_status') not in (None, 'parsed_json')):
        return None
    try:
        doc = json.loads(text)
    except (ValueError, RecursionError):
        return None
    if not isinstance(doc, dict) or doc.get('package', FIXTURE_PACKAGE) != FIXTURE_PACKAGE:
        return None
    claims = doc.get('reads')
    if not isinstance(claims, list) or not 0 < len(claims) <= 256:
        return None
    # An upload action token identifies its own request. A cache flush needs
    # one original source token to bind its claims to a single cached batch.
    if 'cachedBatches' in doc or 'sourceBatchTokens' in doc:
        tokens = doc.get('sourceBatchTokens')
        if type(doc.get('cachedBatches')) is not int or doc['cachedBatches'] != 1:
            return None
        if not isinstance(tokens, list) or len(tokens) != 1:
            return None
        token, token_role = tokens[0], 'cached_source'
    else:
        if doc.get('package') != FIXTURE_PACKAGE:
            return None
        token, token_role = doc.get('scenarioToken'), 'direct_request'
    if not isinstance(token, str) or not TOKEN.fullmatch(token):
        return None
    return hashlib.sha256(token.encode()).hexdigest(), token_role, claims


def batch_index(flows):
    """One accepted use of each batch token within the same UID and session."""
    flows = list(flows)
    batches = {id(flow): batch for flow in flows if (batch := _parse_batch(flow)) is not None}
    keys = {id(flow): (flow['session_id'], uid_of(flow), batches[id(flow)][0])
            for flow in flows if id(flow) in batches}
    counts = Counter(keys.values())
    return {key: batch for key, batch in batches.items() if counts[keys[key]] == 1}


def claim_match(read, flow, batch):
    if batch is None or uid_of(read) is None or uid_of(read) != uid_of(flow):
        return None
    stack = read.get('stack')
    # The fixture's diagnostic cross-check APIs are deliberately excluded
    # from EgressSender. One wrapper may have the same property and value.
    if (read.get('src') != 'vhal' or read.get('api') != 'cpm.getProperty(II)'
            or not isinstance(stack, str) or not PRIMARY_FRAME.search(stack)
            or CROSS_CHECK_FRAME.search(stack)):
        return None
    ts, value = read.get('ts'), raw_value(read)
    if type(ts) is not int or value is None:
        return None
    token_hash, role, claims = batch
    prop_claims = [claim for claim in claims if isinstance(claim, dict)
                   and type(claim.get('propertyId')) is int and claim['propertyId'] == read['prop_id']]
    if len(prop_claims) != 1:
        return None
    claim = prop_claims[0]
    stamp = claim.get('readAtUtcMs')
    if (type(stamp) is not int or not 0 < stamp <= ts <= stamp + CLAIM_TOLERANCE_MS
            or claim.get('property') != read.get('prop_name') or claim.get('result') != 'ok'
            or read.get('outcome') != 'ok' or not equal_value(value, claim.get('value'))):
        return None
    return {'pair_basis': 'token_read_claim', 'origin_proven': True,
            'token_sha256': token_hash, 'token_role': role,
            'claim_match_ms': ts - stamp, 'claim_clock_basis': 'device_utc_ms',
            'content_match_basis': 'request_property_value', 'value_match': True,
            'value_transform': 'raw', 'value_fingerprint': hashlib.sha256(value.encode()).hexdigest(),
            'value_match_caveat': 'Fixture body claim corroborated by the observed read. Causal propagation is unproven.'}


def select_pairs(options, mode):
    """Prefer corroborated source reads per flow and property in hybrid mode."""
    read_refs = Counter((pair['read_src'], pair['read_event_id'])
                        for pair, claim, _ in options if claim)
    flow_refs = Counter((pair['flow_src'], pair['flow_event_id'])
                        for pair, claim, _ in options if claim)
    supported_flows = {(pair['flow_src'], pair['flow_event_id']) for pair, claim, _ in options
                       if claim and read_refs[(pair['read_src'], pair['read_event_id'])] == 1
                       and flow_refs[(pair['flow_src'], pair['flow_event_id'])] == 1}
    result = []
    for pair, claim, window in options:
        if claim and (pair['flow_src'], pair['flow_event_id']) in supported_flows:
            result.append({**pair, **claim})
        elif window and (mode == 'window' or (mode == 'both'
                and (pair['flow_src'], pair['flow_event_id']) not in supported_flows)):
            result.append({**pair, **window, 'origin_proven': False,
                           'pair_basis': 'value_in_window' if window.get('value_match')
                           else 'content_tag_in_window'})
    return result
