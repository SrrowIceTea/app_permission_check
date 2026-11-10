"""Layered, per-run evidence gaps for AAOS properties. 仅用于授权测试。

``vehicle/coverage/export.py`` reports a *capability* chain (what the rule DB
and Hook inventory define). This module reports the *current run* gaps: for one
capture, which properties made it through each layer of the evidence chain.

Layers stay separate on purpose. Collapsing them into one "coverage rate" would
hide the fact that a static reference, an implemented Hook, a successful read,
a matched upload and a located source are five different strengths of evidence.
Each layer is counted and reported independently; a missing input is reported
as ``not_supplied`` rather than guessed as zero.
"""
from __future__ import annotations

from vehicle.analyze.value_match import raw_value

LAYERS = (
    ('static_reference', '静态/能力层：规则库或 APK 静态产物声明了该属性'),
    ('hook_implemented', 'Hook 层：该属性的读取 API 已被 Hook 覆盖'),
    ('value_obtained', '本轮取得层：至少有 outcome=ok 且返回值可解析的读取'),
    ('content_matched_upload', '上传层：有属性绑定的值级内容匹配'),
    ('source_located', '来源层：当前观测下能收敛到唯一读取候选'),
    ('scenario_executed', '场景层：有执行场景记录（仅场景级，不按属性归因）'),
)

# Transparent, non-optimised heuristics: each action records the gap it targets,
# its precondition, the evidence it should add and a coarse cost band.
ACTIONS = {
    'hook_implemented': ('补齐该属性读取 API 的 Hook 实现并做离线回归',
                         '已有授权签名/属性定义', '新增可观测的读取事件',
                         'high', 'Hook 未实现时，后续任何层都不可判'),
    'value_obtained': ('选择与该属性相关的业务场景并执行（如车速→行驶、电量→充电）',
                       'Hook 已实现且采集健康', '新增成功读取的属性类别',
                       'medium', '静态引用不保证本轮执行路径可达'),
    'content_matched_upload': ('延长后台停留、恢复网络或等待延迟批量上传',
                               '本轮已成功取得值', '新增可复核的值级关联',
                               'medium', '缓存/批传会让上传晚于读取窗口'),
    'source_located': ('补取批次标识、独立时钟或重复值判别依据',
                       '已有值级内容匹配', '缩小来源候选集合或明确歧义',
                       'medium', '重复同值与跨批次候选不可靠加窗口解决'),
    'static_reference': ('补取装机版本 APK 并做静态引用核对',
                         'APK 与本轮安装摘要一致', '新增静态引用层证据',
                         'high', '规则库定义不等于该 APK 的静态引用'),
}


def _canonical_map(coverage_chain):
    """Map both ``property_id`` and ``data_type`` to the canonical name.

    Review P0-5: without this, ``291504647`` and ``PERF_VEHICLE_SPEED`` counted as
    two different properties, inflating the denominator and splitting one
    property's per-layer states across two rows.
    """
    mapping = {}
    for row in (coverage_chain or {}).get('rows', []):
        name = row.get('data_type') or row.get('property_name')
        if not name:
            continue
        mapping[str(name)] = str(name)
        if row.get('property_id') is not None:
            mapping[str(row['property_id'])] = str(name)
    return mapping


def _canonical(value, mapping):
    return mapping.get(str(value), str(value))


def _property_keys(reads, coverage_chain, enabled_properties, mapping):
    keys = set()
    for row in (coverage_chain or {}).get('rows', []):
        name = row.get('data_type') or row.get('property_name')
        if name:
            keys.add(_canonical(name, mapping))
    keys.update(_canonical(value, mapping) for value in (enabled_properties or ())
                if value is not None)
    for read in reads:
        if read.get('prop_name'):
            keys.add(_canonical(read['prop_name'], mapping))
    return sorted(keys)


def _capability_properties(coverage_chain, mapping):
    """Properties the rule DB / hook inventory declares. NOT this APK's scan."""
    if coverage_chain is None:
        return None
    return {_canonical(row.get('data_type'), mapping)
            for row in coverage_chain.get('rows', []) if row.get('data_type')}


def _implemented_properties(coverage_chain):
    if coverage_chain is None:
        return None
    return {str(row.get('data_type')) for row in coverage_chain.get('rows', [])
            if (row.get('hook_coverage') or {}).get('status') == 'implemented'
            and row.get('data_type')}


def _static_properties(static, coverage_chain=None, mapping=None):
    """Properties actually referenced by this APK's static scan.

    ``core.static.static_rules`` findings carry a rule_id but no property name,
    so map rule_id -> property via the coverage chain's ``rule_ids`` column.
    A ``weak``/``none`` hit only means "the dex contains a whole constant table"
    and cannot identify one property, so it must not count as a reference.
    Review P2-4.
    """
    if static is None:
        return None
    mapping = mapping or {}
    by_rule = {}
    for row in (coverage_chain or {}).get('rows', []):
        name = row.get('data_type') or row.get('property_name')
        if name:
            for rule_id in row.get('rule_ids') or []:
                by_rule[rule_id] = _canonical(name, mapping)
    keys = set()
    for finding in static.get('findings', []):
        if finding.get('static_strength') in ('weak', 'none'):
            continue
        for field in ('property', 'property_name', 'data_type', 'data_type_key'):
            value = finding.get(field)
            if value:
                keys.add(_canonical(value, mapping))
        name = by_rule.get(finding.get('rule_id'))
        if name:
            keys.add(name)
    return keys


def compute(reads, flows, findings, *, coverage_chain=None, static=None,
            candidate_summary=None, scenarios=None, enabled_properties=None,
            observation_conditions=None):
    """Return per-layer counts, per-property chain and gap-driven next actions."""
    reads, flows, findings = list(reads), list(flows), list(findings)
    mapping = _canonical_map(coverage_chain)
    keys = _property_keys(reads, coverage_chain, enabled_properties, mapping)
    implemented = _implemented_properties(coverage_chain)
    if implemented is not None:
        implemented = {_canonical(name, mapping) for name in implemented}
    static_scanned = _static_properties(static, coverage_chain, mapping)
    declared = _capability_properties(coverage_chain, mapping)
    # ONE source per layer (review P0-5). Per-property states used to read
    # "static_scanned OR declared" while the layer count read only
    # static_scanned, so a property could show a static reference in its own
    # chain while the static layer counted zero.
    static_source = static_scanned if static_scanned is not None else declared
    obtained = {_canonical(r['prop_name'], mapping) for r in reads
                if r.get('outcome') == 'ok' and r.get('prop_name')
                and raw_value(r) is not None}
    matched = {_canonical(f['property'], mapping) for f in findings
               if f.get('value_match') is True and f.get('property')}
    located = {_canonical(s['property'], mapping)
               for s in (candidate_summary or {}).get('sets', [])
               if s.get('state') == 'unique_candidate' and s.get('property')}
    body_unavailable = not any((f.get('request_payload') or {}).get('text') for f in flows)

    per_property = {}
    for key in keys:
        states = {
            'static_reference': None if static_source is None else key in static_source,
            'hook_implemented': None if implemented is None else key in implemented,
            'value_obtained': key in obtained,
            'content_matched_upload': key in matched,
            'source_located': key in located,
        }
        first_missing = next((name for name, _ in LAYERS[:5] if states[name] is not True), None)
        per_property[key] = {'layers': states, 'first_missing_layer': first_missing}

    layers = []
    for index, (name, label) in enumerate(LAYERS):
        if name == 'scenario_executed':
            executed = [s for s in (scenarios or [])
                        if (s.get('successful_read_events') or 0) > 0]
            layers.append({'layer': name, 'label': label,
                           'status': 'not_supplied' if scenarios is None else 'measured',
                           'count': len(executed), 'unit': 'scenario',
                           'attribution': 'scenario_level_only_not_per_property',
                           'reason': '场景记录不携带属性维度，不能按属性推算覆盖。'})
            continue
        source = {'static_reference': static_source,
                  'hook_implemented': implemented, 'value_obtained': obtained,
                  'content_matched_upload': matched, 'source_located': located}[name]
        present = None if source is None else {k for k in keys if k in source}
        layers.append({
            'layer': name, 'label': label,
            'status': 'not_supplied' if present is None else 'measured',
            'count': None if present is None else len(present),
            'gap_count': None if present is None else len(keys) - len(present),
            'keys': None if present is None else sorted(present),
            'gaps': None if present is None else sorted(set(keys) - present),
            'basis': ('apk_static_scan' if name == 'static_reference'
                      and static_scanned is not None
                      else 'capability_definition_not_apk_static_scan'
                      if name == 'static_reference' else 'current_run_observations'),
            'reason': '未提供该层输入，按 not_supplied 记录，不猜测为零。'
            if present is None else None,
        })

    actions = []
    if body_unavailable:
        actions.append({'targets_gap': 'request_body_available',
                        'action': '先恢复代理/协议解析，取得完整可用的请求正文',
                        'precondition': '代理与 TLS 夹具在本轮生效',
                        'expected_new_evidence': '可解析的请求正文',
                        'cost': 'low', 'rationale': '正文不可用时，后续上传/来源层都不可判。'})
    for key, row in per_property.items():
        gap = row['first_missing_layer']
        if not gap or gap not in ACTIONS:
            continue
        action, precondition, expected, cost, rationale = ACTIONS[gap]
        actions.append({'property': key, 'targets_gap': gap, 'action': action,
                        'precondition': precondition, 'expected_new_evidence': expected,
                        'cost': cost, 'rationale': rationale})
    return {
        'generated_by': 'vehicle/analyze/coverage_layers.py::compute',
        'schema_version': 1,
        'properties_considered': len(keys),
        'layers': layers, 'by_property': per_property,
        'next_actions': actions[:40],
        'observation_conditions_link': (observation_conditions or {}).get('rates'),
        'caveats': [
            '各层证据强度不同，分别报告；不得合并成一个「覆盖率」数字。',
            '规则库/覆盖链定义不等于该 APK 的静态引用，也不保证本轮可执行到。',
            '执行过场景不保证触发了对应属性行为；静态引用不保证 Hook 已实现。',
            'next_actions 是透明启发式，未估计动作收益，不能当作最优调度。',
            '唯一来源候选不是因果证明；来源层缺口不等于「没有外发」。',
        ],
    }
