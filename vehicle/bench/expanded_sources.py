"""Neutral projections for new workflow review; never export old predictions/answers.

仅用于授权测试。 Synthetic coordinates and receiver paths are projected to hashes.
"""
import json
from pathlib import Path

from core.io_utils import load_jsonl
from vehicle.pipeline.contracts import ROOT, digest, read_json

BASE = 'output/vehicle-thirdparty-20261105-173730'
PERMISSIONS = 'output/rules-recovery-20261105-231119/owntracks-permissions-007'
IDENTITY = ('src', 'ev', 'evt_id', 'session_id', 'pkg', 'package', 'uid', 'pid', 'user_id',
            'ts', 'host_received_ts', 'device_start_ms', 'device_end_ms')
DETAILS = ('api', 'method', 'scheme', 'port', 'target_port', 'body_sha256', 'body_bytes',
           'write_bytes', 'returned_bytes', 'local_port', 'peer_port', 'caller',
           'coordinate_sha256_16', 'location_timestamp_ms', 'location_timestamp_seconds',
           'location_elapsed_realtime_ns', 'attribution', 'attribution_source',
           'attribution_ambiguous', 'status_code', 'native_write_ref', 'native_write_status',
           'field', 'read_state', 'outcome', 'reason', 'data_type')


def pick(row, keys):
    return {key: row[key] for key in keys if key in row}


def event(row):
    result = pick(row, IDENTITY + DETAILS)
    payload = row.get('request_payload') or {}
    if payload:
        result['request_payload'] = pick(payload, ('raw_sha256', 'raw_bytes', 'raw_truncated',
                                                'text_truncated', 'decode_error', 'content_type'))
        try:
            body = json.loads(payload.get('text', ''))
            from vehicle.privacy.owntracks_evidence import coordinate_digest
            result['location_body'] = {'type': body.get('_type'), 'timestamp_seconds': body.get('tst'),
                                      'coordinate_sha256_16': coordinate_digest((body['lat'], body['lon']))}
        except (ValueError, KeyError, TypeError):
            pass
    return result


class Sources:
    def __init__(self, root=ROOT):
        self.root, self.refs = Path(root), {}

    def bind(self, relative):
        path = (self.root / relative).resolve()
        if Path(relative).is_absolute() or not path.is_relative_to(self.root.resolve()):
            raise ValueError('source path escapes project root')
        self.refs[str(relative).replace('\\', '/')] = digest(path)
        return path

    def document(self, relative):
        return read_json(self.bind(relative))

    def capture(self, folder):
        manifest = self.document(folder + '/session-manifest.json')
        if manifest.get('application_class') != 'ordinary_third_party':
            raise ValueError('capture application identity missing')
        verification = self.document(folder + '/verification.json')
        if not verification.get('passed') or not all(verification.get('checks', {}).values()):
            raise ValueError('capture is unhealthy')
        for name, expected in manifest['input_sha256'].items():
            if Path(name).name != name:
                raise ValueError('capture input must be a filename')
            if digest(self.bind(folder + '/' + name)) != expected:
                raise ValueError('sealed capture input changed: ' + name)
        for name in manifest['used_hook_bundles']:
            if digest(self.bind(folder + '/hook-bundles/' + name)) != manifest['hook_bundles'][name]:
                raise ValueError('executed hook archive changed')
        rows = {}
        for name in ('reads', 'flows'):
            raw = load_jsonl(self.bind(folder + '/' + name + '.jsonl'))
            if any(r.get('session_id') != manifest['session'] for r in raw):
                raise ValueError('mixed capture sessions')
            rows[name] = [event(r) for r in raw]
        return {'identity': pick(manifest, ('session', 'packages', 'device_sdk', 'device_fingerprint',
                 'application_class', 'installed_apk_sha256', 'user_id', 'rules_sha256',
                 'privacy_catalog_sha256', 'used_hook_bundles', 'hook_bundles', 'data_scope')),
                'collection_health': verification['checks'], **rows}

    def receipts(self, relative):
        return [pick(r, ('ts', 'ts_ms', 'method', 'status', 'body_sha256', 'coordinate_sha256_16',
                         'location_timestamp_seconds')) for r in self.document(relative)]


def material(root=ROOT):
    source = Sources(root)
    mg = BASE + '/mg4-native-004'
    ot = BASE + '/owntracks-scenarios-008'
    business = source.document(mg + '/business.json')
    mg4 = {'id': 'mg4-native', 'family': 'mg4', 'package': 'com.tommasov.mg4browser',
           'captures': [source.capture(mg + '/capture')],
           'server_receipts': [pick(r, ('ts_ms', 'method', 'status', 'body_sha256', 'marker'))
                               for r in business['server_receipts']],
           'separate_actor': pick(business['negative_control'], ('ts_ms', 'pid', 'uid', 'source',
                                     'exit_code', 'response_status', 'body_sha256', 'marker'))}
    network = source.document(ot + '/verification.json')
    tracks = {'id': 'owntracks-network', 'family': 'owntracks', 'package': 'org.owntracks.android',
              'captures': [source.capture(ot + '/capture')],
              'actions': [pick(r, ('name', 'ts', 'device_injected_ms', 'coordinate_sha256_16',
                    'end_ms', 'offline_end_ms', 'reconnected_ms')) for r in network['steps']],
              'receiver_receipts': source.receipts(ot + '/receiver-receipts.json')}
    permissions = source.document(PERMISSIONS + '/verification.json')
    consent = {'id': 'owntracks-permissions', 'family': 'owntracks', 'package': 'org.owntracks.android',
               'captures': [source.capture(PERMISSIONS + '/' + name + '/capture')
                            for name in ('granted', 'denied', 'restored')],
               'phases': [pick(r, ('name', 'permissions', 'ts', 'device_injected_ms',
                     'coordinate_sha256_16', 'end_ms', 'observation_ms', 'session_id'))
                          for r in permissions['steps']],
               'receiver_receipts': source.receipts(PERMISSIONS + '/receiver-receipts.json')}
    for relative in ('output/p1p2-runtime/browser.apk',
                     'output/sample-acquisition-20261103/org.owntracks.android/sample.apk'):
        source.bind(relative)
    # The scoring gate is a contract, not a prediction or a historical answer.
    for relative in ('vehicle/bench/suite.py', 'vehicle/bench/labels.py', 'vehicle/bench/metrics.py',
                     'vehicle/privacy/owntracks_evidence.py'):
        source.bind(relative)
    return [mg4, tracks, consent], source.refs
