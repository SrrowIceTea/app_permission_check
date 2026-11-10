"""隐私观测投影：把 general_privacy 与结论行变成可展示的三态矩阵。

授权测试专用。只投影产物、不改任何结论：`registration_only` 不会被写成 `observed`，
`not_observed` 也不会被写成"安全"。字段含义见 FIELD_CONTRACT.md 第 6 节。

缺省约定（与第 1–3 节一致）：**键不存在 = 产物没有该字段**；有字段但内容不成立时，
用显式字符串状态 + 原因码表达，不用 `null` 同时兼指"没有"和"不知道"。
"""
from __future__ import annotations

DATA_TYPES = (
    ('location', '位置/轨迹', '定位'),
    ('microphone', '麦克风', '麦克风'),
    ('contacts', '联系人', '联系人'),
    ('android_id', 'Android ID', 'Android ID'),
    ('advertising_id', '广告标识', '广告标识'),
)
STATE_LABELS = {
    'observed': '已观测',
    'registration_only': '仅注册 / 未取值',
    'read_not_obtained': '有读取但未取到值',
    'not_observed': '未观测',
}
# `read_not_obtained` 的原因码取"最强的那条读取证据"，不是出现次数最多的一条：
# denied/unavailable/error 是拿不到（外部原因），empty 是拿到了空值，call_only 只是调用没取值。
READ_REASON_ORDER = ('denied', 'unavailable', 'error', 'empty', 'unknown', 'call_only')
NOTE = ('本矩阵只描述本轮设备侧观测：已观测＝拿到值且有哈希，可逐条复核；'
        '仅注册 / 未取值＝注册了订阅但没取到值，按判据不升级；'
        '未观测＝本轮没有该数据类型的读取或注册事件。未观测不等于未采集，也不代表安全。')


def _counts(mapping, dtype):
    value = mapping.get(dtype) if isinstance(mapping, dict) else None
    return {str(key): int(count) for key, count in value.items()
            if isinstance(count, int) and not isinstance(count, bool)} \
        if isinstance(value, dict) else {}


def _findings_by_type(rows):
    """按 data_type 汇总结论行里的值哈希证据，用于给矩阵补可复核计数。"""
    index = {}
    for row in rows if isinstance(rows, list) else []:
        dtype = row.get('data_type')
        if not isinstance(dtype, str):
            continue
        item = index.setdefault(dtype, {'rule_ids': [], 'event_ids': [],
                                        'value_hash_present': 0, 'evidence': 0})
        if isinstance(row.get('rule_id'), str) and row['rule_id'] not in item['rule_ids']:
            item['rule_ids'].append(row['rule_id'])
        evidence = row.get('read_evidence')
        if isinstance(evidence, list):
            item['evidence'] += len(evidence)
            item['event_ids'].extend(e.get('evt_id') for e in evidence
                                     if isinstance(e, dict) and isinstance(e.get('evt_id'), int))
        basis = row.get('observed_basis')
        if isinstance(basis, dict) and isinstance(basis.get('value_hash_present'), int):
            item['value_hash_present'] += basis['value_hash_present']
    return index


def _row(dtype, name, subject, states, registrations, finding, gaps):
    observed = states.get('obtained', 0)
    reg_total = sum(registrations.values())
    if observed:
        state, code = 'observed', 'obtained_read'
        text = ('已取到值：本轮 %d 条读取事件 collection_state=obtained，值哈希 %d 条，'
                '可按事件逐条复核。' % (observed, finding.get('value_hash_present', 0)))
    elif reg_total:
        state, code = 'registration_only', 'call_only_no_value'
        text = '该 App 注册了%s订阅，但未取到值，按判据不升级。' % subject
    elif states:
        state = 'read_not_obtained'
        code = next((key for key in READ_REASON_ORDER if key in states), 'unknown')
        text = ('本轮有%s读取事件但没有取到值（%s）；仅记录调用，不能证明取得数据。'
                % (subject, '、'.join('%s=%d' % (k, v) for k, v in sorted(states.items()))))
    else:
        state = 'not_observed'
        code = 'no_events_with_hook_gaps' if gaps else 'no_events_in_session'
        text = '本轮没有「%s」数据的读取或注册事件。' % subject
        if gaps:
            text += ('但本轮有 %d 条 Hook 缺口涉及该数据类型的 API（evt_id %s），'
                     '无事件不等于未采集。' % (len(gaps), '、'.join(str(i) for i in gaps)))
        text += '未观测不等于未采集，也不代表安全。'
    item = {'data_type': dtype, 'data_type_name': name,
            'state': state, 'state_label': STATE_LABELS[state],
            'reason_code': code, 'reason_text': text,
            'read_events': sum(states.values()), 'read_states': states,
            'call_only_events': reg_total, 'registrations_by_kind': registrations,
            'value_hash_present': finding.get('value_hash_present', 0),
            'finding_rule_ids': finding.get('rule_ids', []),
            'evidence_event_ids': finding.get('event_ids', [])}
    if gaps:
        item['observation_gap_event_ids'] = gaps
    return item


def _gap_types(gaps):
    """把 Hook 缺口按 API 签名归到数据类型：只认 catalog 里登记的 class.method 前缀。"""
    try:
        from vehicle.privacy import catalog
    except Exception:      # 投影层不因隐私模块不可用而失败
        return {}
    index = {}
    for target in catalog.TARGETS:
        prefix = '%s.%s' % (target['cls'], target['method'])
        index.setdefault(prefix, target['data_type'])
    mapped = {}
    for gap in gaps:
        message = gap.get('message') or ''
        for prefix, dtype in index.items():
            if message.startswith(prefix):
                mapped.setdefault(dtype, []).append(gap.get('evt_id'))
                break
    return {dtype: [i for i in ids if isinstance(i, int)] for dtype, ids in mapped.items()}


def observation(summary, rows=None):
    """返回 privacy_observation。status=not_available 时 data_types 为空列表，不假装有观测。"""
    source = 'audit/summary.json:general_privacy'
    general = summary.get('general_privacy') if isinstance(summary, dict) else None
    if not isinstance(general, dict):
        return {
            'status': 'not_available',
            'source': source,
            'reason_code': 'no_general_privacy_artifact',
            'reason_text': ('本轮没有 general_privacy 产物（旧产物 / 纯静态任务 / 未执行一般隐私采集）；'
                            '这不等于未采集，也不能当作安全。'),
            'data_types': [], 'not_observed': [], 'registration_only': [],
            'call_only_events': 0, 'observation_gaps': [], 'note': NOTE,
        }
    states = general.get('by_data_type') if isinstance(general.get('by_data_type'), dict) else {}
    registrations = general.get('registrations') if isinstance(general.get('registrations'), dict) else {}
    reg_types = registrations.get('by_data_type') if isinstance(registrations.get('by_data_type'), dict) else {}
    gap_rows = general.get('hook_gaps') if isinstance(general.get('hook_gaps'), list) else []
    gaps = [{'where': row.get('where'), 'message': row.get('message'), 'evt_id': row.get('evt_id')}
            for row in gap_rows if isinstance(row, dict)]
    index = _findings_by_type(rows)
    gap_types = _gap_types(gaps)
    items = [_row(dtype, name, subject, _counts(states, dtype), _counts(reg_types, dtype),
                  index.get(dtype, {}), gap_types.get(dtype, []))
             for dtype, name, subject in DATA_TYPES]
    return {
        'status': 'available',
        'source': source,
        'data_types': items,
        'not_observed': [i['data_type'] for i in items if i['state'] == 'not_observed'],
        'registration_only': [i['data_type'] for i in items if i['state'] == 'registration_only'],
        'call_only_events': (registrations.get('events')
                             if isinstance(registrations.get('events'), int) else 0),
        'observation_gaps': gaps,
        'note': NOTE,
    }


def annotate(rows):
    """给 /findings 的每一行补 observation_state；只投影，不动 conclusion_level。"""
    for row in rows:
        evidence = row.get('read_evidence')
        basis = row.get('observed_basis')
        level = row.get('conclusion_level')
        if level == 'correlated' and isinstance(basis, dict):
            state, code = 'correlated', 'egress_correlated'
            text = '有跨源关联证据，判据与关联窗口见 observation_basis。'
        elif level == 'observed' and isinstance(evidence, list):
            state, code = 'observed', 'read_evidence_obtained'
            text = '按 read_evidence 逐条复核：每条都带 evt_id、collection_state 与值哈希。'
        elif level == 'observed':
            state, code = 'unverified', 'observed_without_read_evidence'
            text = '结论等级为 observed，但结论行没有 read_evidence，无法在界面上逐条复核。'
        else:
            state, code = 'unverified', 'no_read_evidence'
            text = '该结论没有运行时读取证据（静态候选或其他），不构成"已观测"。'
        row['observation_state'] = state
        row['observation_reason_code'] = code
        row['observation_reason_text'] = text
        if isinstance(evidence, list):
            row['read_evidence_count'] = len(evidence)
    return rows
