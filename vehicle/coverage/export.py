"""Generate the coverage chain from the actual versioned DB and Hook inventory.

仅用于授权测试。 A rule row is not proof that a property is granted or available.
"""
import json
import re
import sqlite3
from pathlib import Path
from vehicle.pipeline.contracts import ROOT, digest, write_json
from vehicle.compatibility import profile, os_version

GENERAL_GAPS = [
    ('厂商私有车辆属性', 'TODO：基于受测设备/OEM 资料确认', 'TODO：不猜测厂商接口或签名',
     '普通第三方可能不可访问；没有授权厂商资料，不生成常量。'),
]


def build_coverage(version='15', rules_path=None):
    version = os_version(version)
    selected = profile(version)
    rules_path = Path(rules_path or ROOT / 'vehicle/rules/rules_library/rules.db')
    source = (ROOT / 'vehicle/hooks/hook_vhal.js').read_text(encoding='utf-8')
    watch_block = source.split('watch: {', 1)[1].split('}', 1)[0]
    watched = {int(value) for value in re.findall(r'(\d+)\s*:', watch_block)}
    with sqlite3.connect(rules_path.resolve().as_uri() + '?mode=ro', uri=True) as db:
        db.row_factory = sqlite3.Row
        properties = db.execute('SELECT * FROM vhal_properties WHERE android_version=?', (version,)).fetchall()
        permissions = {r['permission_name']: dict(r) for r in db.execute(
            'SELECT * FROM permissions WHERE android_version=?', (version,))}
        rules = [dict(r) for r in db.execute('SELECT * FROM risk_rules WHERE android_version=?', (version,))]
    rows = []
    for prop in properties:
        matched = [r for r in rules if r['property_key'] == prop['property_key'] and r['enabled']]
        expression = json.loads(prop['read_permission_expr_json'] or '{"op":"unknown"}')
        mapping_status = 'definition_recorded'
        if expression.get('op') == 'unknown':
            expression['policy_candidates'] = sorted({r['permission_name'] for r in matched if r['permission_name']})
            mapping_status = 'policy_candidate_not_device_permission_mapping'
        permission = expression.get('name')
        candidate = expression.get('policy_candidates', [])
        raw = permissions.get(permission or (candidate[0] if len(candidate) == 1 else None), {}).get(
            'protection_level_raw', 'unknown')
        restricted = 'signature' in raw or 'privileged' in raw
        hooked = prop['property_id'] in watched
        rows.append({'data_type': prop['property_name'], 'property_id': prop['property_id'],
            'required_permissions': expression, 'protection_level': raw,
            'permission_mapping_status': mapping_status,
            'ordinary_app_access': 'restricted_expect_denial' if restricted else 'permission_and_availability_dependent',
            'read_apis': ['CarPropertyManager.getProperty', 'getFloatProperty', 'getIntProperty',
                          'getBooleanProperty', 'subscribePropertyEvents/onChangeEvent'],
            'hook_coverage': {'status': 'implemented' if hooked else 'missing',
                'artifact': 'vehicle/hooks/hook_vhal.js', 'legacy_registerCallback': 'not_hooked',
                'async_getProperties': 'not_hooked'},
            'rule_ids': [r['rule_id'] for r in matched],
            'acceptance_examples': ['tools/vehicle_scenario_acceptance.py',
                'vehicle/analyze/test_vehicle_evidence.py'],
            'acceptance_scope': 'historical_fixture_suite_not_per_property_proof',
            'uncovered_reasons': (['Android 15 属性到权限的定义字段为空；规则策略候选不能冒充设备映射。']
                if mapping_status != 'definition_recorded' else []) +
                (['普通第三方签名/特权权限预期被拒绝；拒绝不算采集。'] if restricted else []) +
                ['厂商 ROM/独立样本未完成逐属性验收。', '异步读取/旧 registerCallback 路径未覆盖。',
                 '值级匹配要求属性绑定 JSON；二进制协议无值级保证。'],
            'definition_status': prop['definition_status'],
            'source_refs': json.loads(prop['source_refs_json']),
            'device_refs': json.loads(prop['device_calibration_json'])})
    for name, permission, api, reason in GENERAL_GAPS:
        rows.append({'data_type': name, 'required_permissions': permission, 'read_apis': [api],
            'hook_coverage': {'status': 'not_connected_to_vehicle'}, 'rule_ids': [],
            'ordinary_app_access': 'requires_capability_validation', 'acceptance_examples': [],
            'uncovered_reasons': [reason]})
    if not properties:
        rows.append({'data_type': 'VHAL 车辆属性（本版本未校准）', 'required_permissions': 'TODO',
            'read_apis': [], 'rule_ids': [], 'hook_coverage': {'status': 'not_validated_for_version'},
            'acceptance_examples': [], 'uncovered_reasons': ['没有该版本定义与设备校准；禁止套用 API35。']})
    from vehicle.privacy.coverage import coverage_rows
    rows.extend(coverage_rows(selected['api_level']))
    if selected['api_level'] == 35:
        from vehicle.privacy import ha_contract as ha
        rows.append({'data_type': 'Android 设备电量（HA Automotive 样本）',
            'required_permissions': 'HA 该读取路径无需运行时权限',
            'read_apis': ['ACTION_BATTERY_CHANGED → Intent.getIntExtra(level/scale)'],
            'hook_coverage': {'status': 'sample_opt_in', 'artifact': 'vehicle/hooks/hook_vehicle_ha.js'},
            'rule_ids': [ha.READ_RULE, ha.BODY_RULE],
            'acceptance_examples': ['vehicle/lab/HA_WEBHOOK_VALIDATION.md'],
            'source_refs': ha.SOURCES,
            'uncovered_reasons': ['仅校准 AAOS 35 指定 APK 与隔离 webhook；充电状态、动力电池及其他网络栈单列。']})
    return {'schema_version': 1, 'target': 'ordinary_third_party_app', 'profile': selected,
            'rules_sha256': digest(rules_path), 'rows': rows,
            'caveat': '仅列能力与缺口；规则/静态引用/读取/外发/政策违规不能互相替代。'}


def coverage_bytes(data):
    header = {k: v for k, v in data.items() if k != 'rows'}
    head = json.dumps(header, ensure_ascii=False)[:-1]
    rows = ',\n'.join(json.dumps(row, ensure_ascii=False) for row in data['rows'])
    return (head + ', "rows": [\n' + rows + '\n]}\n').encode('utf-8')


def export_coverage(output, version='15', vhal_capture=None):
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    data = build_coverage(version)
    if vhal_capture:
        from vehicle.coverage.device_observation import attach_observations
        data = attach_observations(data, vhal_capture)
    # Keep each evidence row on one physical line; provenance can be large, and
    # generated source artifacts must also remain below the repository line cap.
    (output / 'coverage.json').write_bytes(coverage_bytes(data))
    lines = ['# 普通第三方车载 App 覆盖链', '',
        '仅用于授权测试。VHAL 行由规则库与 hook_vhal 生成，通用来源行由 vehicle/privacy 目录与 hook_privacy 生成；JSON 保留来源及详细缺口。', '',
        '| 数据类型 | 所需权限 | 读取 API | Hook 覆盖 | 判断规则 | 验收样例 | 未覆盖原因 |',
        '|---|---|---|---|---|---|---|']
    for row in data['rows']:
        values = [row['data_type'], json.dumps(row['required_permissions'], ensure_ascii=False),
                  ', '.join(row['read_apis']), row['hook_coverage']['status'], ', '.join(row['rule_ids']) or '无',
                  ', '.join(row['acceptance_examples']) or '待补', '；'.join(row['uncovered_reasons'])]
        lines.append('| ' + ' | '.join(v.replace('|', '\\|') for v in values) + ' |')
    if data.get('device_observation'):
        lines.extend(['', '## 自有 API 35 夹具设备结果', '',
            '设备和事件摘要见 coverage.json。权限授予来自同一会话的 dumpsys 快照；'
            '订阅回调只认实际收到的 onChangeEvent，注册成功本身不算读取。', '',
            '| 属性 | 同步结果 | 同步 API | 订阅回调 | 权限授予 |',
            '|---|---|---|---|---|'])
        for row in data['rows']:
            observed = row.get('device_observation')
            if not observed:
                continue
            sync, callback = observed['synchronous'], observed['subscription_callback']
            lines.append('| ' + ' | '.join([row['data_type'], ', '.join(sync['outcomes']) or sync['status'],
                ', '.join(sync['apis']), ', '.join(callback['outcomes']) or callback['status'],
                observed['grant_state']]) + ' |')
    (output / 'COVERAGE.md').write_text('\n'.join(lines) + '\n', encoding='utf-8')
    return data
