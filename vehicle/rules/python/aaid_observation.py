"""Freeze the redacted four-state device evidence for the AAID rule. 授权测试专用。"""
import argparse
import re
from pathlib import Path

from vehicle.privacy.catalog import AAID_STATES, HERE
from vehicle.rules.python.privacy_observation import digest, read_json, reference
from vehicle.pipeline.contracts import write_json

SNAPSHOT = HERE / 'aaid-device-observation.json'


def load_snapshot():
    data = read_json(SNAPSHOT)
    cases = data.get('cases', {})
    if (data.get('scope') != 'owned_fixture_only' or data.get('device_api_level') != 35
            or set(cases) != set(AAID_STATES)):
        raise ValueError('AAID observation must contain four verified API 35 fixture cases')
    for case in cases.values():
        ref = case.get('verification', {})
        if not ref.get('path') or not re.fullmatch('[a-f0-9]{64}', ref.get('sha256', '')):
            raise ValueError('AAID observation missing a verification digest')
    return data


def freeze(folders, output):
    cases, fingerprints, bundles = {}, set(), set()
    for folder in folders:
        result = read_json(folder / 'verification.json')
        state = result['expected']
        checks = result.get('checks', {})
        device = result['device']
        if (result.get('passed') is not True or not checks or not all(checks.values())
                or state in cases or result.get('receipt_state') != state or device.get('device_sdk') != 35):
            raise ValueError('unverified or duplicate AAID acceptance case: ' + state)
        for name, expected in result['input_sha256'].items():
            if Path(name).name != name or digest(folder / name) != expected:
                raise ValueError('AAID acceptance input digest mismatch: ' + name)
        fingerprints.add(device['device_fingerprint'])
        bundles.add(result['input_sha256']['hook_privacy.bundle.js'])
        cases[state] = {'session': result['session'], 'package': result['package'],
            'installed_apk_sha256': device['installed_apk_sha256'], 'user_id': device['user_id'],
            'ad_id_declared': result['ad_id_declared'], 'gms_enabled': result['gms_enabled'],
            'gms_installed': result.get('gms_installed', result['gms_enabled']),
            'events': result['event_refs'], 'verification': reference(folder / 'verification.json'),
            'receipt': reference(folder / 'receipt.json')}
    if set(cases) != set(AAID_STATES) or len(fingerprints) != 1 or len(bundles) != 1:
        raise ValueError('AAID acceptance requires all four states on one API 35 image and bundle')
    if any(not cases[state]['gms_enabled'] for state in ('obtained', 'denied', 'empty')):
        raise ValueError('AAID positive, permission and empty controls require enabled GMS')
    if cases['unavailable']['gms_installed']:
        raise ValueError('AAID unavailable control must verify GMS absence for that user')
    write_json(output, {'scope': 'owned_fixture_only', 'device_api_level': 35,
        'device_fingerprint': fingerprints.pop(), 'hook_bundle_sha256': bundles.pop(),
        'human_signoff': 'pending', 'cases': cases})


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--case', type=Path, action='append', required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    freeze(args.case, args.out)
