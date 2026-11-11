"""Bind ONE capture session to the bundle actually loaded and its receipts.

仅用于授权测试（自有设备与自有 APK）。2026-11-11 P0-3: a new bundle / SDK /
display fix is not evidence until a NEW session has business actions, receipts
and health sealed together. Historical sign-offs are never inherited. This is a
host-side evidence index: it does not claim that a device capture happened.

Contract (all optional files stay optional, but their absence is a named gap):
  business-actions.jsonl : one row per action with session/package/ts/receipt
  <receipt file>         : relative path inside the capture directory, sha256 bound

Review hardening (2026-11-11): verify_binding never trusts the binding's own
claims. It re-reads the action file and every receipt, requires the manifest to
declare the binding digest, and refuses short-circuit checks on missing fields.
``binding_consistent`` means the host-side index is internally consistent --
it NEVER means device acceptance happened (``device_acceptance`` stays pending).
"""
import argparse
import json
import re
from pathlib import Path

from vehicle.pipeline.contracts import digest, read_json, write_json

BINDING_FILE = 'session-binding.json'
ACTIONS_FILE = 'business-actions.jsonl'
RECEIPT_STATES = ('observed', 'failed', 'blocked')
RECEIPT_KINDS = ('owned_fixture_receipt', 'adb_state', 'ui_observation', 'synthetic_control')
NO_BINDING_GAP = '本轮未生成会话绑定；不能把旧构建的签核或旧会话证据计入当前版本验收。'
NO_ACTIONS_GAP = '本轮未封存业务动作与回执；不能据此宣称业务触达或新版本已验收。'
DEVICE_GAP = '会话绑定只是宿主机侧证据索引；设备侧新会话/业务动作/回执需另行执行。'
DIGEST_GAP = '会话清单未声明 session_binding_sha256：不能核验绑定是否被篡改。'
PENDING_STEPS = (
    '1. 运行 vehicle.ps1 prepare（重建当前 bundle，确认 freshness=clean 且 dirty_at_build=false）',
    '2. 用新会话运行 vehicle/pipeline/capture.py，业务动作与回执写入 business-actions.jsonl',
    '3. 用本模块 --verify 校验 session-binding.json 与归档 bundle 摘要',
    '4. 再跑 preflight/audit 生成新报告；不复用旧签核，不继承历史健康结论',
)


def _actions(output, session, package):
    """Re-read the action file and EVERY receipt. Also used by verify_binding."""
    path = output / ACTIONS_FILE
    if not path.is_file():
        return {'declared': False, 'rows': 0, 'receipts_verified': 0, 'observed': 0,
                'synthetic_only': False, 'valid': True, 'status': 'not_declared',
                'gaps': [NO_ACTIONS_GAP, DEVICE_GAP]}
    rows, problems = [], []
    for number, line in enumerate(path.read_text(encoding='utf-8').splitlines(), 1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except ValueError:
            problems.append(f'line {number}: invalid JSON')
            continue
        if not isinstance(row, dict):
            problems.append(f'line {number}: not an object')
            continue
        receipt = row.get('receipt')
        sha = row.get('receipt_sha256')
        issues = []
        if row.get('session_id') != session or row.get('package') != package:
            issues.append('session/package mismatch')
        if not isinstance(row.get('action'), str) or not row['action']:
            issues.append('missing action')
        if type(row.get('ts_ms')) is not int or row['ts_ms'] <= 0:
            issues.append('invalid ts_ms')
        if row.get('receipt_status') not in RECEIPT_STATES:
            issues.append('invalid receipt_status')
        if row.get('source') not in RECEIPT_KINDS:
            issues.append('unknown receipt source')
        if not isinstance(receipt, str) or not receipt or Path(receipt).name != receipt:
            issues.append('receipt must be a file inside the capture directory')
        elif not isinstance(sha, str) or re.fullmatch('[0-9a-f]{64}', sha) is None:
            issues.append('invalid receipt_sha256')
        else:
            target = output / receipt
            if not target.is_file() or digest(target) != sha:
                issues.append('receipt file missing or digest mismatch')
        if issues:
            problems.append(f'line {number}: ' + ', '.join(issues))
        else:
            rows.append(row)
    observed = sum(1 for r in rows if r['receipt_status'] == 'observed')
    synthetic = any(r.get('source') == 'synthetic_control' for r in rows)
    status = 'invalid' if problems else 'observed' if observed else 'declared_no_receipt'
    gaps = list(problems)
    if not observed:
        gaps.append('业务动作已声明但没有 observed 回执；不得写成业务已触达。')
    if synthetic:
        gaps.append('含 synthetic_control 回执，不作为设备业务触达证据。')
    return {'declared': True, 'rows': len(rows), 'receipts_verified': len(rows),
            'observed': observed, 'synthetic_only': synthetic, 'valid': not problems,
            'status': status, 'gaps': gaps, 'file': ACTIONS_FILE}


def build_binding(output, *, session, package, bundle_name, bundle_sha256,
                  identity_block=None, switches=None):
    """Write the binding for THIS capture only; never reads a historical file."""
    output = Path(output)
    verification = read_json(output / 'verification.json')
    if verification.get('session', session) != session:
        raise ValueError('verification.json belongs to another session')
    actions = _actions(output, session, package)
    inputs = {name: digest(output / name) for name in
              ('reads.jsonl', 'flows.jsonl', 'egress.jsonl') if (output / name).is_file()}
    health = {'passed': verification.get('passed') is True,
              'checks': sorted(verification.get('checks') or {}),
              'session': verification.get('session')}
    recorded = (health['passed'] and actions['status'] == 'observed'
                and not actions.get('synthetic_only'))
    binding = {'schema_version': 1, 'session_id': session, 'package': package,
               'hook_bundle': {'name': bundle_name, 'sha256': bundle_sha256,
                               'identity': identity_block or {}},
               'capture_switches': dict(switches or {}),
               'health': health, 'inputs': inputs, 'business_actions': actions,
               'status': 'host_actions_recorded' if recorded else 'host_actions_incomplete',
               'gaps': list(actions['gaps']), 'limits': [DEVICE_GAP],
               'generated_by': 'host_side_evidence_index_v1',
               'note': '索引不证明设备采集已发生；业务触达与合规性仍需独立核验。'}
    write_json(output / BINDING_FILE, binding)
    return binding


def _result(status, checks, failures, gaps, **extra):
    return {'status': status, 'checks': checks, 'failures': failures,
            'gaps': list(dict.fromkeys(gaps)), 'limits': [DEVICE_GAP],
            'device_acceptance': 'pending', **extra}


def verify_binding(capture, manifest=None, verification=None, *, package=None):
    """Fail-closed cross-check; re-reads action rows and every receipt file."""
    capture = Path(capture)
    path = capture / BINDING_FILE
    if not path.is_file() and manifest is None and not (capture / 'session-manifest.json').is_file():
        return _result('not_declared', {}, [], [NO_BINDING_GAP, *PENDING_STEPS])
    try:
        manifest = manifest if manifest is not None else read_json(capture / 'session-manifest.json')
        if not path.is_file():
            if isinstance(manifest, dict) and 'session_binding_sha256' in manifest:
                return _result('failed', {'binding_exists': False},
                               [{'code': 'declared_binding_missing'}], [NO_BINDING_GAP])
            return _result('not_declared', {}, [], [NO_BINDING_GAP, *PENDING_STEPS])
        verification = verification if verification is not None else read_json(capture / 'verification.json')
        binding = read_json(path)
    except Exception as error:  # noqa: BLE001 - 证据不可读必须成为明确的失败
        return _result('failed', {}, [{'code': 'binding_unreadable',
                        'exception_type': type(error).__name__}], [NO_BINDING_GAP])
    if not isinstance(binding, dict) or not isinstance(manifest, dict) \
            or not isinstance(verification, dict):
        return _result('failed', {}, [{'code': 'invalid_binding_contract'}], [NO_BINDING_GAP])
    session = manifest.get('session')
    packages = manifest.get('packages') or []
    target = package or (packages[0] if packages else None)
    checks = {}
    expected = manifest.get('session_binding_sha256')
    checks['digest'] = (isinstance(expected, str)
        and re.fullmatch('[0-9a-f]{64}', expected) is not None
        and digest(path) == expected)
    checks['session'] = isinstance(session, str) and binding.get('session_id') == session
    checks['package'] = isinstance(target, str) and binding.get('package') == target
    bundle = binding.get('hook_bundle') or {}
    hooks = manifest.get('hook_bundles') or {}
    current = manifest.get('current_hook_sha256')
    checks['bundle_sha256'] = (isinstance(current, str) and bool(bundle.get('sha256'))
        and bundle.get('sha256') == current and hooks.get(bundle.get('name')) == current)
    recorded = manifest.get('hook_bundle')
    checks['bundle_identity'] = (isinstance(recorded, dict)
        and recorded.get('sha256') == bundle.get('sha256'))
    declared = manifest.get('capture_switches')
    checks['switches'] = (isinstance(declared, dict) and bool(declared)
        and declared == binding.get('capture_switches'))
    checks['health'] = (isinstance(binding.get('health'), dict)
        and binding['health'].get('passed') is True
        and verification.get('passed') is True
        and verification.get('session') == session)
    inputs = binding.get('inputs') or {}
    checks['inputs'] = bool(inputs) and all(
        isinstance(name, str) and Path(name).name == name
        and (capture / name).is_file() and digest(capture / name) == sha
        for name, sha in inputs.items())
    # 绝不采信 binding 自述：重读业务动作文件与每一个回执，逐字段比对。
    computed = _actions(capture, binding.get('session_id'), binding.get('package'))
    claimed = binding.get('business_actions') or {}
    fingerprint = ('status', 'rows', 'observed', 'synthetic_only', 'valid', 'declared')
    checks['actions_recomputed'] = (computed['valid'] and computed['status'] != 'invalid'
        and all(computed.get(k) == claimed.get(k) for k in fingerprint))
    failures = [{'code': name + '_mismatch'} for name, ok in checks.items() if not ok]
    actions_complete = (checks['actions_recomputed'] and computed['status'] == 'observed'
                        and not computed['synthetic_only'])
    pending = []
    if not actions_complete:
        pending.append('业务动作/回执未封存或仅合成对照：新 bundle 的设备验收仍待执行。')
        pending.extend(PENDING_STEPS)
    if expected is None:
        pending.append(DIGEST_GAP)
    status = ('failed' if failures else 'incomplete' if pending else 'binding_consistent')
    return _result(status, checks, failures,
                   [*(binding.get('gaps') or []), DEVICE_GAP, *pending],
                   session_id=binding.get('session_id'),
                   bundle_sha256=bundle.get('sha256'),
                   actions=computed['status'],
                   observed_receipts=computed['observed'],
                   business_actions=computed)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('capture', type=Path)
    parser.add_argument('--build', action='store_true', help='为本轮采集生成会话绑定')
    parser.add_argument('--session'), parser.add_argument('--package')
    parser.add_argument('--bundle-name', default='hook_vehicle_all.bundle.js')
    args = parser.parse_args(argv)
    if args.build:
        if not args.session or not args.package:
            parser.error('--build 需要 --session 与 --package')
        manifest = read_json(args.capture / 'session-manifest.json')
        if not manifest.get('current_hook_sha256'):
            parser.error('会话清单缺少 current_hook_sha256；请先完成本轮采集')
        binding = build_binding(args.capture, session=args.session, package=args.package,
            bundle_name=args.bundle_name,
            bundle_sha256=manifest['current_hook_sha256'],
            identity_block=manifest.get('hook_bundle'),
            switches=manifest.get('capture_switches'))
        manifest['session_binding_sha256'] = digest(args.capture / BINDING_FILE)
        write_json(args.capture / 'session-manifest.json', manifest)
        print(json.dumps({'status': binding['status'], 'file': BINDING_FILE,
                          'gaps': binding['gaps']}, ensure_ascii=False, indent=2))
        return 0
    result = verify_binding(args.capture)
    result['pending_steps'] = list(PENDING_STEPS)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result['status'] != 'failed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
