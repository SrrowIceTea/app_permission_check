"""V-Scanner draft project policy; not an Android fact or legal interpretation."""
import hashlib
import json
from pathlib import Path
from parse_sources import packed


def draft_rules(facts, policy_path):
    rows = {item['table']: {} for item in facts}
    keys = {'permissions': 'permission_name', 'vhal_properties': 'property_name', 'dangerous_apis': 'api_key'}
    for item in facts:
        row = item['row']
        rows[item['table']][row[keys[item['table']]]] = row
    api = next(r for r in rows['dangerous_apis'].values()
               if r['method_name'] == 'getProperty' and r['jvm_descriptor'].startswith('(II)'))
    policy_hash = hashlib.sha256(Path(policy_path).read_bytes()).hexdigest()
    # 覆盖 vhal_properties 的全部 8 个属性，与 POLICY.md 的 severity 表一一对应。
    # 原先只覆盖 3 个：CURRENT_GEAR 实测可读却无规则，是已知漏报。
    # severity 沿用既有三行的同一判据（标识能力），不是新发明的分级。
    # 顺序即序号，追加在末尾，因此既有的 P001-P003 / R001-R003 / E001-E003 编号不变。
    selected = [('INFO_VIN', 'VIN', 'high'),
                ('PERF_VEHICLE_SPEED', 'vehicle speed', 'medium'),
                ('GEAR_SELECTION', 'gear selection', 'medium'),
                ('CURRENT_GEAR', 'current gear', 'medium'),
                ('PERF_ODOMETER', 'odometer', 'medium'),
                ('ENGINE_RPM', 'engine rpm', 'low'),
                ('FUEL_LEVEL', 'fuel level', 'low'),
                ('EV_BATTERY_LEVEL', 'ev battery level', 'low')]
    rules = []

    def emit(kind, prefix, clause, conclusion, ordinal, label, severity, prop, permission):
        """生成一条规则。source_refs 一律来自已抽取的事实行，不在这里编造。"""
        source_refs = json.loads(prop['source_refs_json']) + json.loads(api['source_refs_json'])
        row = {'rule_id': f'VSC-{prefix}{ordinal:03}', 'android_version': prop['android_version'],
               'rule_revision': 1, 'title': f'{label}: {kind}', 'rule_type': kind,
               'severity': severity, 'permission_name': permission,
               'property_key': prop['property_key'] if kind != 'over_permission' else None,
               'api_key': api['api_key'] if kind != 'over_permission' else None,
               'window_ms': 3000 if kind == 'data_egress' else None,
               'conclusion_level': conclusion, 'enabled': 0,
               'source_refs_json': packed(source_refs),
               'basis_refs_json': packed([{'kind': 'project_policy', 'path': 'POLICY.md',
                   'version': 'draft-1', 'clause': clause, 'sha256': policy_hash}]),
               'notes': 'DISABLED draft. No evaluator implemented. Runtime/source applicability '
                        'and package attribution unverified. Not a legal violation conclusion.'}
        common = {'draft_dsl': 1, 'session_whitelist_required': True,
                  'device_source_compatibility_required': True}
        if kind == 'over_permission':
            common.update(predicate='manifest_permission_requires_necessity_review', permission=permission)
            evidence = ['manifest_requested_permission', 'app_function_description',
                        'reviewed_necessity_policy', 'apk_sha256']
        elif kind == 'sensitive_read':
            common.update(predicate='successful_property_value_read', property_id=prop['property_id'])
            evidence = ['non_null_available_value', 'event_id', 'uid_package_attribution',
                        'hook_health_ok', 'rule_and_source_version']
        else:
            common.update(predicate='read_before_egress_within_window', property_id=prop['property_id'],
                          same_session=True, same_attributed_package=True, clock_normalized=True)
            evidence = ['read_event_id', 'egress_event_id', 'reliable_uid_package_attribution',
                        'clock_offset_and_uncertainty', 'collector_health_ok']
            common['content_match'] = 'required_to_upgrade_beyond_temporal_correlation'
        row['condition_json'] = packed(common)
        row['evidence_requirements_json'] = packed({'all': evidence})
        rules.append({'table': 'risk_rules', 'row': row})

    # R / E 按**属性**生成：谓词说的是"这条属性被读了 / 被读了又发出去"，与属性一一对应。
    for ordinal, (name, label, severity) in enumerate(selected, 1):
        prop = rows['vhal_properties'][name]
        permission = json.loads(prop['read_permission_expr_json'])['name']
        emit('sensitive_read', 'R', 'R1', 'observed', ordinal, label, severity, prop, permission)
        emit('data_egress', 'E', 'E1', 'correlated', ordinal, label, severity, prop, permission)

    # P 按**去重后的权限**生成。谓词是"清单请求了该权限"，与属性无关；
    # 按属性生成会让共享同一权限的属性（GEAR_SELECTION 与 CURRENT_GEAR 同受
    # CAR_POWERTRAIN 管辖、FUEL_LEVEL 与 EV_BATTERY_LEVEL 同受 CAR_ENERGY 管辖）
    # 产生两条一模一样的结论——那是噪声，不是信息。severity 取首次出现的属性。
    seen_permissions = []
    for name, label, severity in selected:
        permission = json.loads(rows['vhal_properties'][name]['read_permission_expr_json'])['name']
        if any(p == permission for p, _, _ in seen_permissions):
            continue
        seen_permissions.append((permission, label, severity))
    for ordinal, (permission, label, severity) in enumerate(seen_permissions, 1):
        emit('over_permission', 'P', 'P1', 'candidate', ordinal, label, severity,
             rows['vhal_properties'][selected[ordinal - 1][0]], permission)
    return rules
