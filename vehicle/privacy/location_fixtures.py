"""Synthetic, owned location cases. 仅用于授权测试；不是设备采集或参考金标准。"""
import copy
import hashlib
import json

PACKAGE, SESSION = 'test.vscanner.location', 'synthetic-location-week1'
FORM_VALUES = {
    'pair_d6': '30.274100,120.155100',
    'pair_d6_lonlat': '120.155100,30.274100',
    'pair_raw': '30.2741,120.1551',
    'pair_raw_lonlat': '120.1551,30.2741',
    'geo_d6': 'geo:30.274100,120.155100',
    'single_lat_d6': '30.274100',
    'single_lon_d6': '120.155100',
}


def form(name, value):
    return {'form': name, 'len': len(value), 'hash': hashlib.sha256(value.encode()).hexdigest()[:16]}


def read(**extra):
    forms = [form(k, v) for k, v in FORM_VALUES.items()]
    return {'ev': 'PRIVACY_READ', 'src': 'privacy', 'pkg': PACKAGE, 'session_id': SESSION,
        'uid': 1012345, 'user_id': 10, 'pid': 100, 'evt_id': 1, 'host_received_ts': 1000,
        'data_types': ['location'], 'outcome': 'ok', 'collection_state': 'obtained',
        'non_empty': True, 'value_kind': 'location_pair', 'location_form': 'pair_d6',
        'location_precision': 6, 'location_forms': forms,
        'value_hash': forms[0]['hash'], 'value_len': forms[0]['len'], **extra}


def flow(value=FORM_VALUES['pair_d6'], **extra):
    text = json.dumps({'location': value})
    return {'src': 'proxy', 'evt_id': 2, 'ts': 1200, 'package': PACKAGE, 'session_id': SESSION,
        'uid': 1012345, 'user_id': 10, 'attribution': 'app_process_hook',
        'attribution_delta_ms': 20, 'method': 'POST',
        'request_payload': {'text': text, 'raw_truncated': False, 'text_truncated': False,
                            'decode_error': None}, **extra}


def cases():
    """Expected counts are authored test expectations, not measured accuracy."""
    broken = flow()
    broken['request_payload']['text_truncated'] = True
    return copy.deepcopy([
        {'name': 'same_pair', 'reads': [read()], 'flows': [flow()], 'expected_pairs': 1},
        {'name': 'different_pair', 'reads': [read()], 'flows': [flow('31.000000,121.000000')],
         'expected_pairs': 0},
        {'name': 'single_coordinates', 'reads': [read()],
         'flows': [flow({'lat': FORM_VALUES['single_lat_d6'], 'lon': FORM_VALUES['single_lon_d6']})],
         'expected_pairs': 0},
        {'name': 'repeated_origin', 'reads': [read(), read(evt_id=3, host_received_ts=1100)],
         'flows': [flow()], 'expected_pairs': 2, 'expected_ambiguous_flows': 1},
        {'name': 'other_session_identity', 'reads': [read()],
         'flows': [flow(session_id='other'), flow(uid=1112345, user_id=11, evt_id=3)],
         'expected_pairs': 0},
        {'name': 'empty_or_incomplete', 'reads': [read(collection_state='empty', non_empty=False),
                                                read(evt_id=3)],
         'flows': [broken, flow(evt_id=4, request_payload=None)], 'expected_pairs': 0},
    ])
