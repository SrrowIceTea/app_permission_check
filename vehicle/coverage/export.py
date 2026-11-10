"""Generate the coverage chain from the actual versioned DB and Hook inventory.

仅用于授权测试。 A rule row is not proof that a property is granted or available.
"""
import json
import re
import sqlite3
from contextlib import closing
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
    with closing(sqlite3.connect(rules_path.resolve().as_uri() + '?mode=ro', uri=True)) as db:
        db.row_factory = sqlite3.Row
        properties = db.execute('SELECT * FROM vhal_properties WHERE android_version=?', (version,)).fetchall()
        permissions = {r['permission_name']: dict(r) for r in db.execute(
            'SELECT * FROM permissions WHERE android_version=?', (version,))}
        rules = [dict(r) for r in db.execute('SELECT * FROM risk_rules WHERE android_version=?', (version,))]
        has_aaid = db.execute("SELECT 1 FROM risk_rules WHERE rule_id='VSC-GR-advertising_id' LIMIT 1").fetchone()
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
                          'getBooleanProperty', 'subscribePropertyEvents/onChangeEvent',
                          'getPropertiesAsync(List)', 'getIntArrayProperty'],
            'hook_coverage': {'status': 'implemented' if hooked else 'missing',
                'artifact': 'vehicle/hooks/hook_vhal.js',
                'legacy_registerCallback': 'implemented',
                # 2026-11-10 设备实测（cpm-signatures-device35.json）：AAOS 35 没有
                # getProperties(int[])，也没有 getPropertyAsync；真实签名是
                # getPropertiesAsync(java.util.List, ...) 与 getIntArrayProperty(int,int)。
                # 两者已由 vehicle/hooks/vhal_batch.js 覆盖，7/7 场景实测 ARMED 且零 ERROR。
                'async_getProperties': 'implemented',
                'int_array_property': 'implemented',
                'batch_int_array_getProperties': 'absent_on_aaos35'},
            'rule_ids': [r['rule_id'] for r in matched],
            'acceptance_examples': ['tools/vehicle_scenario_acceptance.py',
                'vehicle/analyze/test_vehicle_evidence.py'],
            'acceptance_scope': 'historical_fixture_suite_not_per_property_proof',
            'uncovered_reasons': (['该规则版本缺少属性权限定义。策略候选与设备实际授予分开记录。']
                if mapping_status != 'definition_recorded' else []) +
                (['普通第三方签名/特权权限预期被拒绝；拒绝不算采集。'] if restricted else []) +
                ['厂商 ROM/独立样本未完成逐属性验收。',
                 'getPropertyList 返回配置列表而非属性值，不需要 Hook；'
                 '批量异步与 int 数组读取已覆盖（vhal_batch.js）。',
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
    rows.extend(coverage_rows(selected['api_level'], 2 if has_aaid else 1))
    if selected['api_level'] == 35:
        from vehicle.privacy import ha_contract as ha, owntracks_contract as owntracks
        from vehicle.privacy import owntracks_evidence as ot_rules
        rows.append({'data_type': 'Android 设备电量（HA Automotive 样本）',
            'required_permissions': 'HA 该读取路径无需运行时权限',
            'read_apis': ['ACTION_BATTERY_CHANGED → Intent.getIntExtra(level/scale)'],
            'hook_coverage': {'status': 'sample_opt_in', 'artifact': 'vehicle/hooks/hook_vehicle_ha.js'},
            'rule_ids': [ha.READ_RULE, ha.BODY_RULE],
            'acceptance_examples': ['vehicle/lab/HA_WEBHOOK_VALIDATION.md'],
            'source_refs': ha.SOURCES,
            'uncovered_reasons': ['仅校准 AAOS 35 指定 APK 与隔离 webhook；充电状态、动力电池及其他网络栈单列。']})
        rows.append({'data_type': '位置/轨迹（OwnTracks 样本）',
            'required_permissions': {'op': 'any_of', 'names': ['android.permission.ACCESS_COARSE_LOCATION',
                                                             'android.permission.ACCESS_FINE_LOCATION']},
            'permission_mapping_status': 'android_location_permissions_not_same_round_grant_proof',
            'read_apis': ['org.owntracks.android.services.LocationProcessor.onLocationChanged'],
            'hook_coverage': {'status': 'sample_opt_in', 'artifact': 'vehicle/hooks/hook_vehicle_owntracks.js'},
            'rule_ids': [ot_rules.READ_RULE, ot_rules.BODY_RULE],
            'acceptance_examples': ['vehicle/lab/SAMPLE_RUNTIME_REVIEW.md'],
            'acceptance_scope': 'pinned_apk_isolated_http_workflow_only',
            'source_refs': [{'path': 'vehicle/privacy/owntracks_contract.py', 'apk_sha256': owntracks.APK_SHA256}],
            'uncovered_reasons': ['审计展示直接回调与同值正文候选；独立回执由业务验收核验。',
                '专用规则限定侧载对照，单列业务验收。',
                'TLS、其他 APK 版本和独立评分待覆盖。']})
    return {'schema_version': 1, 'target': 'ordinary_third_party_app', 'profile': selected,
            'rules_sha256': digest(rules_path), 'rows': rows,
            'caveat': '仅列能力与缺口；规则/静态引用/读取/外发/政策违规不能互相替代。'}


def coverage_bytes(data):
    header = {k: v for k, v in data.items() if k != 'rows'}
    head = json.dumps(header, ensure_ascii=False)[:-1]
    rows = ',\n'.join(json.dumps(row, ensure_ascii=False) for row in data['rows'])
    return (head + ', "rows": [\n' + rows + '\n]}\n').encode('utf-8')


def export_coverage(output, version='15', vhal_capture=None, catalog_snapshot=None, *, rules_path=None):
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    data = build_coverage(version, rules_path)
    if vhal_capture:
        from vehicle.coverage.device_observation import attach_observations
        data = attach_observations(data, vhal_capture, catalog_snapshot)
    # Keep each evidence row on one physical line; provenance can be large, and
    # generated source artifacts must also remain below the repository line cap.
    (output / 'coverage.json').write_bytes(coverage_bytes(data))
    lines = ['# 普通第三方车载 App 覆盖链', '',
        '仅用于授权测试。VHAL 行由规则库与 hook_vhal 生成，通用来源行由 vehicle/privacy 目录与 hook_privacy 生成；JSON 保留来源及详细缺口。', '',
        '范围声明：本表只说明"能观测哪些 API"（覆盖链），**不含本轮实际观测结果**。'
        '位置/麦克风/联系人/Android ID/广告标识的四态（已观测、仅注册未取值、有读取但未取到值、未观测）'
        '只在同轮 PDF 报告《七、车载场景与证据覆盖》与工作台「动态审计」页给出；'
        '本表没有出现某个数据类型，不等于该类型未被采集，也不等于安全。', '',
        '| 数据类型 | 所需权限 | 读取 API | Hook 覆盖 | 判断规则 | 验收样例 | 未覆盖原因 |',
        '|---|---|---|---|---|---|---|']
    for row in data['rows']:
        values = [row['data_type'], json.dumps(row['required_permissions'], ensure_ascii=False),
                  ', '.join(row['read_apis']), row['hook_coverage']['status'], ', '.join(row['rule_ids']) or '无',
                  ', '.join(row['acceptance_examples']) or '待补', '；'.join(row['uncovered_reasons'])]
        lines.append('| ' + ' | '.join(v.replace('|', '\\|') for v in values) + ' |')
    if data.get('device_observation'):
        snapshot = data['device_observation'].get('grant_snapshot') or {}
        lines.extend(['', '## 自有 API 35 夹具设备结果', '',
            '设备和事件摘要见 coverage.json。订阅回调只认实际收到的 onChangeEvent。',
            '权限授予依据为 ' + {'capture_manifest': '采集清单绑定的 dumpsys 快照。',
                'local_snapshot_not_in_capture_manifest': '与采集同目录的 dumpsys 快照，旧采集清单未绑定其摘要。'
                }.get(snapshot.get('binding'), '未取得设备快照。'), '',
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
