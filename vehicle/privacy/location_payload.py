"""Representation-aware JSON evidence. 仅用于授权测试；不恢复已脱敏的内容。"""
import hashlib
import json


def _unique_fields(items):
    result = dict(items)
    if len(result) != len(items):
        raise ValueError('duplicate JSON fields')
    return result


def _invalid_constant(_value):
    raise ValueError('non-JSON number')


def request_values(flow):
    """Return (leaf digests, rejection reason, representation provenance).

    Legacy transformed payloads have no separate text digest. Their persisted
    bytes require the capture input binding at the replay boundary; this API
    records that limitation instead of comparing two different representations.
    """
    payload = flow.get('request_payload')
    if not isinstance(payload, dict):
        return set(), 'request_body_unavailable', {}
    if any(payload.get(k) for k in ('raw_truncated', 'text_truncated', 'decode_error')):
        return set(), 'request_body_incomplete', {}
    retention = payload.get('retention')
    if retention not in (None, 'unchanged', 'decoded_text_only', 'redacted'):
        return set(), 'request_body_not_retained', {}
    text = payload.get('text')
    if not isinstance(text, str) or len(text) > 2 * 1024 * 1024:
        return set(), 'request_body_unavailable_or_oversized', {}
    try:
        encoded = text.encode('utf-8')
        text_sha = hashlib.sha256(encoded).hexdigest()
        if 'text_sha256' in payload or 'text_bytes' in payload:
            if (payload.get('text_sha256') != text_sha or type(payload.get('text_bytes')) is not int
                    or payload['text_bytes'] != len(encoded)):
                return set(), 'request_text_digest_or_length_mismatch', {}
            integrity = 'persisted_text_digest_verified'
        else:
            integrity = 'legacy_text_requires_capture_input_binding'
        if retention in (None, 'unchanged'):
            if ('raw_sha256' in payload and payload['raw_sha256'] != text_sha
                    or 'raw_bytes' in payload and (type(payload['raw_bytes']) is not int
                                                  or payload['raw_bytes'] != len(encoded))):
                return set(), 'request_body_digest_or_length_mismatch', {}
            if 'raw_sha256' in payload and 'raw_bytes' in payload:
                integrity = 'wire_and_persisted_text_digest_verified'
        stack = [json.loads(text, object_pairs_hook=_unique_fields, parse_constant=_invalid_constant)]
    except (ValueError, RecursionError, UnicodeError):
        return set(), 'request_body_invalid_json', {}
    values, visited = set(), 0
    while stack:
        visited += 1
        if visited > 10000:
            return set(), 'request_json_node_limit', {}
        node = stack.pop()
        if isinstance(node, dict):
            stack.extend(node.values())
        elif isinstance(node, list):
            stack.extend(node)
        elif isinstance(node, str) and 8 <= len(node) <= 256:
            try:
                values.add((hashlib.sha256(node.encode('utf-8')).hexdigest()[:16], len(node)))
            except UnicodeError:
                return set(), 'request_body_invalid_unicode', {}
    return values, None, {'representation': 'persisted_request_text', 'retention': retention,
                          'text_sha256': text_sha, 'text_bytes': len(encoded),
                          'integrity_basis': integrity}
