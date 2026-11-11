"""Fail closed on unhealthy/mismatched evidence, before producing findings.

仅用于授权测试（自有设备与自有 APK）。 Legacy capture hashes may be absent;
this is recorded explicitly. New captures bind every analysis input by SHA-256.
"""
import re
from pathlib import Path
from core.io_utils import load_jsonl
from vehicle.compatibility import profile
from vehicle.pipeline import readiness
from vehicle.pipeline.contracts import AuditError, ROOT, digest, read_json
from vehicle.pipeline.evidence_manifest import INPUT_NAMES, artifact_ref
from vehicle.privacy import ha_contract as ha
from vehicle.privacy import ha_socket_evidence as ha_socket
from vehicle.privacy import mg4_contract as mg4
from vehicle.privacy import abs_contract as abs_scope
from vehicle.privacy import owntracks_contract as owntracks

HOOK_DIRS = (ROOT / 'vehicle/hooks/dist', ROOT / 'core/frida_host/dist')
ERROR_EVENTS = {'ERROR', 'SCRIPT_ERROR', 'CAPTURE_ERROR', 'VLOG_FAIL'}


def reject(code, message, **details):
    raise AuditError(code, message, '修复原因后创建新采集会话；不要修改失败证据为通过。', **details)


def validate_capture(capture, package, version, rules, apk=None, *, catalog_snapshot=None):
    capture = Path(capture)
    selected = profile(version)
    manifest = read_json(capture / 'session-manifest.json')
    scope = manifest.get('data_scope', 'all') if isinstance(manifest, dict) else 'all'
    if scope not in ('all', 'general'):
        reject('invalid_data_scope', '未知的数据采集范围。')
    if not selected['dynamic_verified'] and scope != 'general':
        reject('version_not_validated', selected['reason'])
    verification_path = capture / 'verification.json'
    evidence = {'capture/verification.json': artifact_ref(verification_path)}
    verification = read_json(verification_path)
    if not isinstance(manifest, dict) or not isinstance(verification, dict):
        reject('invalid_capture_contract', '采集清单与验收结果必须是 JSON 对象。')
    checks = verification.get('checks', {})
    if (verification.get('passed') is not True or not checks
            or any(v is not True for v in checks.values())):
        reject('capture_unhealthy', '采集未通过健康验收，不能生成正常审计报告。')
    if package not in manifest.get('packages', []):
        reject('package_not_captured', '目标包不在该轮采集白名单。')
    if manifest.get('application_class') not in (None, 'ordinary_third_party'):
        reject('application_scope_mismatch', '本入口仅接受普通第三方安装的 App。')
    if manifest.get('rules_sha256') != digest(rules):
        reject('rules_mismatch', '当前规则库与采集时的规则库不同。')
    sdk = manifest.get('device_sdk')
    if sdk is not None:
        matches = str(sdk) == str(selected['api_level'])
    else:
        matches = bool(re.search(r':' + selected['android_version'] + r'/',
                                 manifest.get('device_fingerprint', '')))
    if not matches:
        reject('device_version_mismatch', '设备 API 与所选车载规则版本不一致。')
    bundles = manifest.get('hook_bundles', {})
    used = manifest.get('used_hook_bundles', ['hook_vehicle_all.bundle.js'])
    agent = 'hook_vehicle_general.bundle.js' if scope == 'general' else 'hook_vehicle_all.bundle.js'
    ha_modes = [(mode, key) for mode, key in (
        (ha, 'ha_webhook_contract_sha256'), (ha_socket, ha_socket.MANIFEST_KEY))
        if mode.BUNDLE in used or key in manifest]
    if len(ha_modes) > 1:
        reject('ha_contract_mismatch', '单一会话同时声明了多个 HA 采集契约。')
    ha_mode = None
    mg4_enabled = mg4.BUNDLE in used or mg4.MANIFEST_KEY in manifest
    abs_enabled = abs_scope.BUNDLE in used or abs_scope.MANIFEST_KEY in manifest
    owntracks_enabled = owntracks.BUNDLE in used or owntracks.MANIFEST_KEY in manifest
    if owntracks_enabled:
        from vehicle.privacy.owntracks_endpoint import allowed_host
        if not allowed_host(manifest.get('owntracks_endpoint_host', '198.18.0.1')):
            reject('owntracks_endpoint_invalid', 'OwnTracks 接收端必须为已声明的自有测试地址。')
        if (ha_modes or mg4_enabled or abs_enabled or not owntracks.supports(package, manifest)
                or manifest.get('capture_mode') != 'attach_system_proxy'
                or manifest.get(owntracks.MANIFEST_KEY) != owntracks.contract_hash()):
            reject('owntracks_contract_mismatch', 'OwnTracks 样本身份或定位回调契约与本轮采集不一致。')
        agent = owntracks.BUNDLE
    if abs_enabled:
        if (ha_modes or mg4_enabled or not abs_scope.supports(package, manifest)
                or manifest.get('capture_mode') != 'attach_preserve_proxy'
                or manifest.get(abs_scope.MANIFEST_KEY) != abs_scope.contract_hash()):
            reject('abs_send_contract_mismatch', 'YAABSA 样本身份或 ABS 采集契约不一致。')
        agent = abs_scope.BUNDLE
    if mg4_enabled:
        if (ha_modes or not mg4.supports(package, manifest)
                or manifest.get('capture_mode') != 'attach_system_proxy'
                or manifest.get(mg4.MANIFEST_KEY) != mg4.contract_hash()):
            reject('mg4_contract_mismatch', 'MG4 样本身份或 WebView 契约与本轮采集不一致。')
        agent = mg4.BUNDLE
    if ha_modes:
        ha_mode, key = ha_modes[0]
        if (not ha.supports(package, manifest) or manifest.get('capture_mode') != 'attach_preserve_proxy'
                or manifest.get(key) != ha_mode.contract_hash()):
            reject('ha_contract_mismatch', 'HA 正文扩展身份或契约与本轮采集不一致。')
        agent = ha_mode.BUNDLE
    if not used or agent not in used:
        reject('missing_capture_hook', '未记录本轮使用的车载采集 agent。')
    for name in used:
        if not isinstance(name, str) or Path(name).name != name:
            reject('invalid_bundle_name', '钩子清单包含无效文件名。')
        archived = capture / 'hook-bundles' / name
        candidates = (archived,) if manifest.get('hook_archive') == 'hook-bundles' or archived.exists() \
            else tuple(folder / name for folder in HOOK_DIRS)
        matched = next((p for p in candidates if p.is_file() and digest(p) == bundles.get(name)), None)
        if matched is None:
            raise AuditError('hook_mismatch', f'缺少与采集摘要一致的钩子：{name}',
                             '恢复原始 bundle 到采集目录的 hook-bundles，或重新采集。')
        evidence[f'hook/{name}'] = artifact_ref(matched, sha256=bundles[name])
    for name in ('reads.jsonl', 'flows.jsonl'):
        if not (capture / name).is_file():
            reject('missing_capture_input', f'缺少采集输入：{name}')
    rows = {name: load_jsonl(capture / name) for name in ('reads.jsonl', 'flows.jsonl', 'egress.jsonl')}
    session = manifest.get('session')
    events = [r for values in rows.values() for r in values]
    if not session or not events or any(r.get('session_id') != session for r in events):
        reject('session_mismatch', '输入为空、混入其他会话或缺失会话身份。')
    if verification.get('session', session) != session:
        reject('verification_session_mismatch', '验收记录属于另一会话。')
    if manifest.get('capture_mode') in ('attach_system_proxy', 'attach_preserve_proxy'):
        health_path = capture / 'collector-health.json'
        evidence['capture/collector-health.json'] = artifact_ref(health_path)
        health = read_json(health_path)
        if health.get('status') != 'completed' or health.get('session_id') != session:
            reject('collector_unhealthy', '代理回调有错误或未正常收尾，不能当作正常零流量。')
    errors = [r for r in rows['reads.jsonl'] if r.get('ev') in ERROR_EVENTS]
    if errors:
        reject('hook_errors', '采集日志存在钩子错误；不能把缺失事件当成无行为。', count=len(errors))
    armed = {(r.get('src'), r.get('ev')) for r in rows['reads.jsonl']}
    sample_mode = abs_scope if abs_enabled else mg4 if mg4_enabled else ha_mode
    if owntracks_enabled:
        sample_mode = owntracks
    # 单一就绪契约（2026-11-11 P0）：capture 与 preflight 共用同一集合，
    # --no-tls-bypass 的合法对照不再被要求 PINNING_ARMED，但也不免除其他钩子。
    tls_bypass, switch_source = readiness.resolve_switch(verification, manifest)
    if tls_bypass is None:
        reject('tls_switch_mismatch', 'TLS 开关在验收记录与会话清单之间不一致。')
    privacy_required = (manifest.get('privacy_catalog_sha256') is not None
                        or scope == 'general' or catalog_snapshot is not None)
    required = readiness.required_events(tls_bypass=tls_bypass, scope=scope,
        sample_mode=sample_mode, privacy_required=privacy_required)
    catalog = manifest.get('privacy_catalog_sha256')
    if privacy_required:
        from vehicle.privacy.catalog import catalog_hash, matches_catalog_snapshot
        catalog_valid = (matches_catalog_snapshot(read_json(catalog_snapshot), catalog) if catalog_snapshot
                         else catalog in (catalog_hash(1), catalog_hash()))
        if not catalog_valid or not any(r.get('src') == 'privacy' and r.get('ev') == 'ARMED'
                and r.get('pkg') == package and r.get('privacy_catalog_sha256') == catalog
                and r.get('sdk') == selected['api_level'] for r in rows['reads.jsonl']):
            reject('privacy_catalog_mismatch', '通用隐私规则/Hook 契约与采集时不同或缺少对应就绪记录。')
    if not required <= armed:
        reject('hook_not_armed', '本轮指定的采集钩子未全部就绪。',
               missing=sorted([list(r) for r in required - armed]))
    switch_error, tls_diagnostics = readiness.check_switch(rows['reads.jsonl'],
        tls_bypass=tls_bypass, session=session, sample_mode=sample_mode,
        require_switch=(switch_source == 'declared'))
    if switch_error:
        reject(switch_error, 'TLS 开关声明与就绪事件不一致；不能按旧口径判定就绪。',
               **tls_diagnostics)
    tls_diagnostics['switch_source'] = switch_source
    if switch_source == 'legacy_default':
        tls_diagnostics['gaps'].append('旧会话未显式记录 tls_bypass，按默认开启处理；不视为已验证。')
    hashes = manifest.get('input_sha256')
    if sample_mode and not hashes:
        reject('incomplete_input_hashes', '样本扩展必须绑定本轮输入摘要。')
    if abs_enabled and abs_scope.INPUT not in hashes:
        reject('incomplete_input_hashes', '缺少封存的 ABS 请求文件摘要。')
    if hashes is not None:
        if not all(name in hashes for name in ('reads.jsonl', 'flows.jsonl', 'verification.json')):
            reject('incomplete_input_hashes', '新采集清单缺少必要输入摘要。')
        for name, expected in hashes.items():
            path = capture / name
            if Path(name).name != name or not path.is_file() or digest(path) != expected:
                reject('input_mismatch', f'采集输入摘要不一致：{name}')
            if name not in INPUT_NAMES.values():
                key = f'capture/{name}'
                ref = evidence.setdefault(key, artifact_ref(path, sha256=expected))
                if ref['sha256'] != expected:
                    reject('input_mismatch', f'采集输入摘要不一致：{name}')
    # 当前构建身份（2026-11-11 P0-3）：验收记录里的 bundle 必须与本轮清单一致，
    # 旧 sign-off / 旧 dist 产物不能借新会话通过。
    recorded_hook = verification.get('hook_bundle') or {}
    if recorded_hook.get('sha256') not in (None, manifest.get('current_hook_sha256')):
        reject('hook_bundle_mismatch', '验收记录与会话清单登记的当前 bundle 不一致；不能继承旧产物签核。')
    from vehicle.pipeline import session_binding
    binding = session_binding.verify_binding(capture, manifest, verification, package=package)
    if binding['status'] == 'failed':
        reject('session_binding_invalid',
               '会话绑定与当前证据不一致；不能复用其他会话或旧构建的签核。',
               failures=binding['failures'])
    from vehicle.pipeline.process_lifecycle import SUMMARY_FILE as LIFECYCLE_SUMMARY
    if manifest.get('process_lifecycle') is not None and not (capture / LIFECYCLE_SUMMARY).is_file():
        reject('lifecycle_summary_missing', '清单声明了进程生命周期覆盖但摘要文件缺失；不能宣称已记录覆盖缺口。')
    installed = manifest.get('installed_apk_sha256')
    if not isinstance(installed, str) or not re.fullmatch('[0-9a-f]{64}', installed):
        reject('missing_apk_identity', '缺少采集时装机 APK 的完整摘要。')
    if apk and digest(apk) != installed:
        reject('apk_mismatch', '提供的 APK 与采集时装机 APK 不同。')
    target = [r for r in rows['reads.jsonl'] if r.get('ev') == 'VHAL_READ' and r.get('pkg') == package]
    gaps = ['仅覆盖 attach 后行为；短时无观测不证明未采集。']
    gaps.extend(tls_diagnostics['gaps'])
    gaps.extend(binding['gaps'])
    gaps.extend(manifest.get('gaps', []))
    if scope == 'general':
        if any(r.get('ev') == 'VHAL_READ' for r in rows['reads.jsonl']):
            reject('vhal_outside_scope', '通用范围不得混入其他版本的 VHAL 事件。')
        gaps.append('仅审计通用 Android 来源；未启用本版本 VHAL 规则。')
        if not selected['dynamic_verified']:
            gaps.append('该 API 版本通用来源尚无设备验收；本轮运行结果不自动升级全局兼容状态。')
    if catalog is None:
        gaps.append('旧会话未记录通用隐私 agent 契约，不能据此宣称通用来源已覆盖。')
    gaps.extend('通用钩子缺口：' + str(r.get('where')) for r in rows['reads.jsonl']
                if r.get('ev') == 'PRIVACY_GAP')
    if manifest.get('application_class') is None:
        gaps.append('旧会话未记录普通第三方安装身份，不能用于独立普通 App 基准统计。')
    if hashes is None:
        gaps.append('旧会话没有输入文件摘要，输入完整性未绑定；建议重新采集。')
    if not target:
        gaps.append('健康采集期间未观测到覆盖范围内的车辆属性读取；不代表 App 无其他隐私行为。')
    # preflight 的 passed 只表示「本轮证据满足审计前门禁」，不等于设备已验收。
    if binding['status'] != 'binding_consistent':
        gaps.append('本轮未取得完整且一致的当前 bundle 会话绑定；不得计入新版本设备验收。')
    return {'status': 'passed', 'session_id': session, 'manifest': manifest,
            'profile': selected, 'data_scope': scope, 'target_read_events': len(target),
            'tls_readiness': tls_diagnostics, 'gaps': gaps,
            'device_acceptance': binding['device_acceptance'],
            'session_binding': {k: binding.get(k) for k in
                ('status', 'session_id', 'bundle_sha256', 'actions', 'observed_receipts',
                 'device_acceptance')},
            'evidence_artifacts': evidence}
