"""Conservative property-bound value evidence; authorized tests only.

This compares observations, not taint propagation or a legal violation. Numeric
values are accepted only inside the matching property's JSON record/key.
"""
import base64
import hashlib
import json
import math
from decimal import Decimal, InvalidOperation
from urllib.parse import quote

MAX_TEXT = 1024 * 1024
MAX_NODES = 20000
MAX_DEPTH = 32


def scalar(value):
    if value is None or isinstance(value, (dict, list)):
        return None
    if isinstance(value, bool):
        return 'true' if value else 'false'
    if isinstance(value, float) and not math.isfinite(value):
        return None
    return str(value)


def raw_value(read):
    if 'value_raw' in read:
        return scalar(read['value_raw'])
    value = scalar(read.get('value'))
    # Historical getProperty log display is not itself the returned value.
    if value and value.startswith('CarPropertyValue{status=0,value=') and value.endswith('}'):
        return value[len('CarPropertyValue{status=0,value='):-1]
    return value


def equal_value(left, right):
    right = scalar(right)
    if right is None:
        return False
    if left == right:
        return True
    if len(left) > 128 or len(right) > 128:
        return False
    try:
        a, b = Decimal(left), Decimal(right)
        return a.is_finite() and b.is_finite() and a == b
    except InvalidOperation:
        return False


def transformations(value):
    raw = value.encode('utf-8')
    return {
        'base64': base64.b64encode(raw).decode('ascii'),
        'hex': raw.hex(), 'urlencode': quote(value, safe=''),
        **{name: hashlib.new(name, raw).hexdigest() for name in ('md5', 'sha1', 'sha256')},
    }


def property_values(document, read):
    """Return values bound to this property, never an unrelated numeric leaf."""
    wanted = {str(read.get('prop_id')), read.get('prop_name')}
    wanted.discard(None)
    stack, count = [(document, 0)], 0
    while stack and count < MAX_NODES:
        node, depth = stack.pop()
        count += 1
        if depth > MAX_DEPTH:
            continue
        if isinstance(node, dict):
            for key, value in node.items():
                if key in wanted and scalar(value) is not None:
                    yield value
            ids = [node.get(k) for k in ('property', 'propertyId', 'prop_id', 'prop_name')]
            present = [str(p) for p in ids if p is not None]
            if present and all(p in wanted for p in present):
                if node.get('result', 'ok') == 'ok' and 'value' in node:
                    yield node['value']
            stack.extend((v, depth + 1) for v in node.values() if isinstance(v, (dict, list)))
        elif isinstance(node, list):
            stack.extend((v, depth + 1) for v in node if isinstance(v, (dict, list)))


def match_content(read, flow):
    """Return evidence metadata or None. No preview or response-side matching."""
    payload = flow.get('request_payload') or {}
    value = raw_value(read)
    if value is None and 'value_raw' in read:
        return None
    text = payload.get('text')
    if value is not None and text:
        if len(text) > MAX_TEXT or payload.get('decode_error'):
            return None
        try:
            document = json.loads(text)
        except (ValueError, RecursionError):
            return None
        forms = transformations(value)
        for found in property_values(document, read):
            form = 'raw' if equal_value(value, found) else next(
                (name for name, encoded in forms.items()
                 if encoded != value and scalar(found) == encoded), None)
            if form:
                return {'content_match_basis': 'request_property_value',
                        'value_match': True, 'value_transform': form,
                        'value_fingerprint': hashlib.sha256(value.encode()).hexdigest(),
                        'value_match_caveat': 'Content equality is not causal taint tracking.'}
        return None  # An explicit different value must never fall back to a name hit.
    tokens = set(flow.get('request_tokens') or [])
    if read.get('prop_name') in tokens or str(read.get('prop_id')) in tokens:
        return {'content_match_basis': 'request_property_token', 'value_match': False,
                'value_match_gap': 'read_value_or_request_payload_unavailable'}
    return None
