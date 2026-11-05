"""Attach VHAL observations from a sealed API 35 case. 仅用于授权测试。"""
import re
from collections import defaultdict
from pathlib import Path

from core.io_utils import load_jsonl
from vehicle.pipeline.contracts import AuditError, ROOT, digest
from vehicle.pipeline.preflight import validate_capture

FIXTURE = 'com.vscanner.targetapp'


def grant_snapshot(capture, user=10):
    """Same-round dumpsys grants: outcomes alone must not imply granted or denied."""
    capture = Path(capture)
    text = (capture / 'dumpsys-package.txt').read_text(encoding='utf-8')
    granted, denied, mode = {}, {}, None
    for number, line in enumerate(text.splitlines(), 1):
        if re.match(r'^    install permissions:', line):
            mode = 'install'
            continue
        match = re.match(r'^    User (\d+):', line)
        if match:
            mode = 'target_user' if int(match.group(1)) == user else None
            continue
        if line.startswith('    ') and not line.startswith('      ') and line.strip():
            mode = None
            continue
        match = re.match(r'^\s+([\w.]+): granted=(true|false)', line)
        if not match or not mode:
            continue
        entry = {'line': number, 'text': line.strip()}
        (granted if match.group(2) == 'true' else denied)[match.group(1)] = entry
    declared = re.findall(r'(?m)^([\w.]+)$',
                          (capture / 'requested-permissions.txt').read_text(encoding='utf-8'))
    return {'path': 'dumpsys-package.txt', 'sha256': digest(capture / 'dumpsys-package.txt'),
            'granted': granted, 'denied': denied, 'declared': declared}


def grant_state(snapshot, permission):
    if permission in snapshot['granted']:
        return 'granted'
    if permission in snapshot['denied']:
        return 'denied'
    return 'declared_but_not_granted' if permission in snapshot['declared'] else 'not_declared'


def attach_observations(data, capture, catalog_snapshot=None):
    capture = Path(capture)
    rules = ROOT / 'vehicle/rules/rules_library/rules.db'
    validated = validate_capture(capture, FIXTURE, '15', rules, catalog_snapshot=catalog_snapshot)
    manifest = validated['manifest']
    inputs = manifest.get('input_sha256', {})
    if (data['profile']['api_level'] != 35 or validated['data_scope'] != 'all'
            or manifest.get('packages') != [FIXTURE]
            or 'requested-permissions.txt' not in inputs or 'reads.jsonl' not in inputs):
        raise AuditError('vhal_matrix_capture_mismatch', '设备矩阵要求封存的 API 35 自有夹具采集。',
                         '选择同设备、同会话并已绑定权限声明与事件摘要的采集。')
    indexed = defaultdict(list)
    for row in load_jsonl(capture / 'reads.jsonl'):
        if row.get('ev') == 'VHAL_READ' and row.get('src') == 'vhal' and row.get('pkg') == FIXTURE:
            indexed[row.get('prop_id')].append(row)
    snapshot = (grant_snapshot(capture, manifest.get('user_id', 10)) if (capture / 'dumpsys-package.txt').is_file()
                else None)
    if snapshot:
        snapshot['binding'] = ('capture_manifest' if 'dumpsys-package.txt' in inputs
                               else 'local_snapshot_not_in_capture_manifest')
    for entry in data['rows']:
        if 'property_id' not in entry:
            continue
        observations = {}
        sync_prefixes = ('cpm.getProperty(', 'cpm.getIntProperty(', 'cpm.getFloatProperty(',
                         'cpm.getBooleanProperty(')
        for path, prefixes in (('synchronous', sync_prefixes),
                               ('subscription_callback', ('subscription.onChangeEvent',))):
            events = [r for r in indexed[entry['property_id']] if r.get('api', '').startswith(prefixes)]
            outcomes = sorted({r.get('outcome', 'unknown') for r in events})
            observations[path] = {'status': 'observed' if events else 'not_observed', 'outcomes': outcomes,
                'apis': sorted({r['api'] for r in events}),
                'event_refs': [{'src': r['src'], 'evt_id': r['evt_id'], 'api': r.get('api'),
                                'outcome': r.get('outcome'), 'value': r.get('value')}
                               for r in events]}
        expression = entry['required_permissions']
        candidates = (expression.get('policy_candidates', [])
                      if isinstance(expression, dict) else [])
        permission = (expression.get('name') if isinstance(expression, dict) else None)
        if not permission and len(candidates) == 1:
            permission = candidates[0]
        state = grant_state(snapshot, permission) if snapshot and permission else (
            'not_verified' if snapshot is None else 'not_declared')
        entry['device_observation'] = observations | {'grant_state': state,
            'permission_candidate': permission,
            'async_get_properties': 'not_observed', 'legacy_callback': 'not_observed'}
    data['device_observation'] = {'session_id': validated['session_id'], 'package': FIXTURE,
        'capture': str(capture), 'device_fingerprint': manifest['device_fingerprint'],
        'installed_apk_sha256': manifest['installed_apk_sha256'], 'reads_sha256': inputs['reads.jsonl'],
        'requested_permissions_sha256': inputs['requested-permissions.txt'],
        'requested_permissions': (capture / 'requested-permissions.txt').read_text(encoding='utf-8').splitlines(),
        'grant_snapshot': snapshot,
        'capture_manifest_sha256': digest(capture / 'session-manifest.json'),
        'capture_privacy_catalog_sha256': manifest.get('privacy_catalog_sha256'),
        'scope': 'owned_fixture_only'}
    return data
