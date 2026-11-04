"""Synthetic capture builder for contract tests, never device acceptance proof."""
import json
from pathlib import Path
from vehicle.pipeline.contracts import ROOT, digest, write_json

PACKAGE = 'test.app'


def make_capture(root, with_read=True):
    root = Path(root)
    capture, hooks = root / 'capture', root / 'hooks'
    capture.mkdir(); hooks.mkdir()
    bundle = hooks / 'hook_vehicle_all.bundle.js'
    bundle.write_bytes(b'synthetic bundle for offline contract tests')
    events = [{'session_id': 's1', 'src': src, 'ev': event, 'evt_id': i,
               'host_received_ts': 1000} for i, (src, event) in enumerate(
                   [('vhal', 'ARMED'), ('egress', 'ARMED'), ('tls', 'PINNING_ARMED')], 1)]
    if with_read:
        events.append({'session_id': 's1', 'src': 'vhal', 'ev': 'VHAL_READ', 'evt_id': 10,
            'pkg': PACKAGE, 'uid': 1010123, 'user_id': 10, 'prop_id': 289408000,
            'prop_name': 'GEAR_SELECTION', 'api': 'cpm.getIntProperty(II)',
            'value_raw': 4, 'outcome': 'ok', 'host_received_ts': 1100})
    (capture / 'reads.jsonl').write_text(''.join(json.dumps(e) + '\n' for e in events), encoding='utf-8')
    (capture / 'flows.jsonl').write_text('', encoding='utf-8')
    (capture / 'requested-permissions.txt').write_text('android.car.permission.CAR_POWERTRAIN\n', encoding='utf-8')
    write_json(capture / 'verification.json', {'session': 's1', 'passed': True,
        'checks': {'workers_stopped_cleanly': True, 'app_alive_after_detach': True}})
    manifest = {'session': 's1', 'packages': [PACKAGE], 'device_sdk': 35,
        'application_class': 'ordinary_third_party', 'user_id': 10,
        'device_fingerprint': 'test/aaos:15/test', 'installed_apk_sha256': 'a' * 64,
        'rules_sha256': digest(ROOT / 'vehicle/rules/rules_library/rules.db'),
        'used_hook_bundles': [bundle.name], 'hook_bundles': {bundle.name: digest(bundle)}}
    seal_capture(capture, manifest)
    return capture, hooks


def seal_capture(capture, manifest=None):
    manifest = manifest or json.loads((capture / 'session-manifest.json').read_text(encoding='utf-8'))
    manifest['input_sha256'] = {n: digest(capture / n) for n in
        ('reads.jsonl', 'flows.jsonl', 'requested-permissions.txt', 'verification.json')}
    write_json(capture / 'session-manifest.json', manifest)
