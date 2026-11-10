"""Read-only handoff snapshots for B-side acceptance. 仅用于授权测试。"""
import json
import re
import shutil
from pathlib import Path

from core.io_utils import load_jsonl
from vehicle.pipeline.contracts import digest
from vehicle.pipeline.preflight import validate_capture
from vehicle.privacy import location_experiment
from vehicle.privacy.location_inputs import read_manifest, unique_fields

KINDS = ('controlled_positive', 'different_value', 'single_coordinate', 'repeated_origin', 'third_party')
CLEANUP_CHECKS = ('workers_stopped_cleanly', 'worker_cleanup_healthy', 'device_settings_restored',
                  'device_reverse_restored', 'apk_unchanged', 'original_process_alive',
                  'no_hook_errors', 'collector_callbacks_healthy', 'proxy_log_redaction_healthy')


class UnsafeOutputError(ValueError):
    """Output would mutate the source capture; stop before writing diagnostics."""


def resolve(base, value):
    if not isinstance(value, str) or not value:
        raise ValueError('handoff_path_missing')
    path = Path(value)
    return path.resolve() if path.is_absolute() else (base / path).resolve()


def load_plan(path):
    path = Path(path).resolve()
    data = json.loads(path.read_text(encoding='utf-8-sig'), object_pairs_hook=unique_fields)
    if (not isinstance(data, dict) or data.get('schema_version') != 1
            or data.get('input_kind') not in ('device', 'synthetic')
            or not isinstance(data.get('cases'), list)):
        raise ValueError('invalid_handoff_plan')
    seen = set()
    for case in data['cases']:
        if (not isinstance(case, dict) or not isinstance(case.get('id'), str)
                or not re.fullmatch('[A-Za-z][A-Za-z0-9_-]{0,63}', case['id'])
                or case['id'] in seen or case.get('kind') not in KINDS
                or not isinstance(case.get('package'), str)):
            raise ValueError('invalid_or_duplicate_handoff_case')
        seen.add(case['id'])
    return data, path.parent


def _copy(source, destination):
    expected = digest(source)
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)
    if digest(destination) != expected or digest(source) != expected:
        raise ValueError('handoff_changed_during_snapshot')
    return expected


def snapshot(entry, base, output):
    """Only named artifacts and archived hooks, never mutate A's source capture."""
    source = resolve(base, entry.get('capture'))
    if output.resolve().is_relative_to(source):
        raise UnsafeOutputError('acceptance_output_inside_source_capture')
    capture = output / 'capture'
    manifest_path = source / 'session-manifest.json'
    manifest_sha = digest(manifest_path)
    manifest = read_manifest(manifest_path, entry['package'])
    if not isinstance(manifest, dict) or not isinstance(manifest.get('input_sha256'), dict):
        raise ValueError('handoff_manifest_or_input_hashes_invalid')
    hashes = manifest['input_sha256']
    if not {'reads.jsonl', 'flows.jsonl', 'verification.json', 'collector-health.json'} <= hashes.keys():
        raise ValueError('handoff_health_or_input_binding_missing')
    _copy(manifest_path, capture / manifest_path.name)
    for name, expected in hashes.items():
        if not isinstance(name, str) or Path(name).name != name:
            raise ValueError('invalid_handoff_input_name')
        if _copy(source / name, capture / name) != expected:
            raise ValueError('handoff_input_hash_mismatch')
    hooks = manifest.get('used_hook_bundles')
    if not isinstance(hooks, list) or not hooks or not isinstance(manifest.get('hook_bundles'), dict):
        raise ValueError('handoff_archived_hooks_missing')
    for name in hooks:
        if not isinstance(name, str) or Path(name).name != name:
            raise ValueError('invalid_archived_hook_name')
        _copy(source / 'hook-bundles' / name, capture / 'hook-bundles' / name)
    refs = {'capture_manifest_sha256': manifest_sha}
    for key in ('apk', 'rules', 'catalog_snapshot'):
        if key not in entry and key == 'catalog_snapshot':
            continue
        path = resolve(base, entry.get(key))
        refs[key + '_sha256'] = _copy(path, output / key / path.name)
        refs[key] = output / key / path.name
    if digest(manifest_path) != manifest_sha or any(digest(source / k) != v for k, v in hashes.items()):
        raise ValueError('handoff_source_changed_during_snapshot')
    return capture, manifest, refs


def _sidecar(entry, name, base, output, manifest, manifest_sha):
    path = resolve(base, entry.get(name))
    actual = _copy(path, output / (name + '.json'))
    if entry.get(name + '_sha256') != actual:
        raise ValueError(name + '_digest_missing_or_mismatched')
    data = json.loads((output / (name + '.json')).read_text(encoding='utf-8'))
    if (not isinstance(data, dict) or data.get('session_id') != manifest['session']
            or data.get('capture_manifest_sha256') != manifest_sha):
        raise ValueError(name + '_session_or_manifest_mismatch')
    return data


def validate_actions(actions, verification, manifest, capture):
    """Validate declared baseline and PID context; not independent actor attestation."""
    if (not isinstance(actions.get('capture_commit'), str)
            or not re.fullmatch('[a-f0-9]{7,64}', actions['capture_commit'])
            or not isinstance(actions.get('device_serial'), str) or not actions['device_serial']
            or not isinstance(actions.get('steps'), list) or not actions['steps']
            or not all(isinstance(v, str) and v.strip() for v in actions['steps'])
            or type(actions.get('tls_bypass')) is not bool
            or actions['tls_bypass'] != verification.get('tls_bypass')):
        raise ValueError('action_baseline_commit_device_steps_or_tls_missing')
    if any(verification['checks'].get(k) is not True for k in CLEANUP_CHECKS):
        raise ValueError('required_capture_identity_or_cleanup_check_missing')
    processes = actions.get('processes')
    if (not isinstance(processes, list) or not processes
            or not all(isinstance(p, dict) and type(p.get('pid')) is int and p['pid'] > 0
                       and type(p.get('uid')) is int and p['uid'] % 100000 >= 10000
                       and p['uid'] // 100000 == manifest['user_id']
                       and p.get('user_id') == manifest['user_id'] for p in processes)):
        raise ValueError('action_process_inventory_missing_or_invalid')
    identities = {(p['pid'], p['uid']) for p in processes}
    if any(r.get('ev') == 'PRIVACY_READ' and r.get('pkg') in manifest['packages']
           and (r.get('pid'), r.get('uid')) not in identities
           for r in load_jsonl(capture / 'reads.jsonl')):
        raise ValueError('read_pid_uid_absent_from_action_inventory')


def inspect_case(entry, base, output):
    if output.resolve().is_relative_to(resolve(base, entry.get('capture'))):
        raise UnsafeOutputError('acceptance_output_inside_source_capture')
    row = {'id': entry['id'], 'kind': entry['kind'], 'package': entry['package'],
           'status': 'blocked', 'condition_met': False, 'workflow_verified': False}
    try:
        capture, manifest, refs = snapshot(entry, base, output)
        if manifest.get('device_sdk') != 35 or str(manifest.get('android_version')) != '15':
            raise ValueError('handoff_requires_aaos35')
        health = json.loads((capture / 'collector-health.json').read_text(encoding='utf-8'))
        verification = json.loads((capture / 'verification.json').read_text(encoding='utf-8'))
        if (not isinstance(health, dict) or health.get('status') != 'completed'
                or health.get('session_id') != manifest['session']):
            raise ValueError('collector_not_healthy_for_session')
        if (not isinstance(verification, dict) or verification.get('passed') is not True
                or not isinstance(verification.get('checks'), dict) or not verification['checks']
                or any(value is not True for value in verification['checks'].values())):
            raise ValueError('capture_verification_not_healthy')
        # Location experiment remains independent of production findings/labels.
        result = location_experiment.replay(capture, entry['package'], 30000)
        checked = validate_capture(capture, entry['package'], '15', refs['rules'], refs['apk'],
                                   catalog_snapshot=refs.get('catalog_snapshot'))
        row.update(session_id=checked['session_id'], inputs=result['inputs'], pair_count=result['pair_count'],
                   ambiguous_flows=result['ambiguous_flows'], diagnostics=result['diagnostics'],
                   capture_health='passed', reason_code='action_record_missing',
                   evidence_sha256={k: v for k, v in refs.items() if k.endswith('_sha256')})
        (output / 'location-result.json').write_text(json.dumps(result, ensure_ascii=False, indent=2),
                                                    encoding='utf-8')
        actions = _sidecar(entry, 'actions', base, output, manifest, refs['capture_manifest_sha256'])
        if actions.get('completed') is not True or actions.get('kind') != entry['kind']:
            raise ValueError('scenario_not_completed_or_kind_mismatch')
        validate_actions(actions, verification, manifest, capture)
        row['action_record_validated'] = True  # Not independent gold labels or causal proof.
        row['declared_capture_commit'] = actions['capture_commit']
        enough = result['inputs']['compatible_comparisons'] > 0
        kind = entry['kind']
        if kind == 'third_party':
            row.update(status='attempt_recorded', condition_met=True,
                       reason_code=('content_candidates' if result['pair_count'] else
                                    'missing_general_location_reads' if not result['inputs']['scoped_location_reads']
                                    else 'inputs_not_comparable' if not enough else 'no_supported_content_match'))
        elif not enough:
            row.update(status='incomplete', reason_code='no_comparable_read_and_request')
        elif kind in ('different_value', 'single_coordinate'):
            row.update(status='passed' if not result['pair_count'] else 'failed',
                       condition_met=not result['pair_count'], reason_code='negative_control_expected_zero')
        elif kind == 'repeated_origin':
            ok = result['ambiguous_flows'] > 0
            row.update(status='passed' if ok else 'failed', condition_met=ok,
                       reason_code='repeated_sources_must_stay_ambiguous')
        else:
            receipts = _sidecar(entry, 'receipts', base, output, manifest, refs['capture_manifest_sha256'])
            hashes = receipts.get('request_body_sha256')
            if (not isinstance(hashes, list) or not hashes
                    or not all(isinstance(v, str) and re.fullmatch('[a-f0-9]{64}', v) for v in hashes)):
                raise ValueError('receiver_receipt_body_hashes_missing')
            flow_ids = {(p['flow_src'], p.get('flow_pid'), p['flow_event_id']) for p in result['pairs']}
            received = any((f.get('src'), f.get('pid'), f.get('evt_id')) in flow_ids
                           and (f.get('request_payload') or {}).get('raw_sha256') in hashes
                           for f in load_jsonl(capture / 'flows.jsonl'))
            ok = bool(result['pair_count']) and received
            row.update(status='passed' if ok else 'failed', condition_met=ok,
                       receiver_body_matched=received, reason_code='positive_requires_pair_and_bound_receipt')
    except (OSError, ValueError, TypeError, KeyError) as exc:
        row.update(status='blocked', condition_met=False,
                   reason_code=getattr(exc, 'code', str(exc)), error_type=type(exc).__name__)
    output.mkdir(parents=True, exist_ok=True)
    (output / 'acceptance.json').write_text(json.dumps(row, ensure_ascii=False, indent=2), encoding='utf-8')
    return row
