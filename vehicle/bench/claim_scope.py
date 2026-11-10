"""命题 ↔ 求值器契约与三态观测门控。仅用于授权测试（自有设备与自有 APK）。

字段/文件归属（周一 11-16 固定，本次不碰另两人主线的共享文件）：

* 本模块是「命题 case → 所需求值器」「观测三态」的**唯一权威来源**。
* ``vehicle/bench/claim_verdicts.py`` 只消费本模块，不再自带任何映射或判定。
* ``tools/real_sample_result.py`` 只读本模块产出的 ``observation_state`` / ``report_cell``，
  不自行推算。
* 求值器名的唯一来源：``vehicle/analyze/detection_summary.py::EXTRACTORS``。
* 命题 id 的唯一来源：``vehicle/bench/aaos35-suite.json`` 的 case id / kind。
* 三态语义的唯一来源：``core/evidence/decidability.py``（平台无关内核，不复制不改）。

本模块不写回任何产物、不改 ``finding_uid``、不迁移证据库、不改既有 7 个判定状态。
四种判定口径反例（C1–C4）见 ``counterexamples()``；其中 ``legacy_stance()`` 按
2026-11-10 版 ``claim_verdicts.py:38-48`` 逐行复刻，用于证明缺陷可复现，不参与生产判定。
"""
from __future__ import annotations

from core.evidence import decidability as dc

# 未登记契约的 case：沿用既有统计结构，但必须显式标注，绝不静默升级为「本题已观测」。
UNSCOPED = 'legacy_unscoped'

# case id -> 本命题必需的业务求值器（顺序稳定，便于对照）。
# 依据 aaos35-suite.json 的 kind 与 suite.py::_replay 逐 case 分支（:74-135）：
#   ha_battery -> result['ha_webhook']; ha_control / ha_control_failure -> result['ha_websocket'];
#   mg4_post -> mg4_native_http(verified_flows); mg4_webview_post -> result['mg4_webview'];
#   yaabsa_send -> result['abs_native_send']; yaabsa_playback 走 _playback，不产 audit 摘要。
CASE_EVALUATORS = {
    'ha-battery': ('ha_webhook',),
    'ha-control': ('ha_websocket',),
    'ha-control-failure': ('ha_websocket',),
    'mg4-post': ('mg4_native_http',),
    'mg4-webview-post': ('mg4_webview',),
    'yaabsa-send': ('abs_native_send',),
}
# 结构性不可计分（docs/RESULTS_20261110.md §4.6 W05）：没有 audit 产物，不是「没跑求值器」。
NO_AUDIT_CASES = ('yaabsa-playback',)

CALIBERS = {
    'C1': '观测充分：任意求值器运行 ⇒ 本题被观测',
    'C2': '命题与证据对应：整轮业务证据总数 ⇒ 本命题断言',
    'C3': '未运行/不可判：统计结构缺失 ≡ 求值器跑了且 0 命中',
    'C4': '计分与投影一致：表格「运行求值器数」被当作本命题观测证据',
}

STATE_LABELS = {
    dc.DECIDABLE: '已观测（本命题）',
    dc.DECIDABLE_NO_EVIDENCE: '已观测·本轮无命中',
    dc.NOT_APPLICABLE: '不可判（未运行/缺统计）',
    UNSCOPED: '未登记契约·旧口径',
}

# B 周 D2：unscored 是「结构性不可计分」，不是一种观测状态；两种原因补救动作不同。
UNSCORED_REASONS = {
    'no_audit_output': '未计分·无采集产物',
    'reviewers_disagreed': '未计分·评审未一致',
}
UNSCORED_LIMITATIONS = {
    'no_audit_output': '无采集产物，无法计分',
    'reviewers_disagreed': '评审意见未一致，不计分（不是没有行为、不是阴性结论）',
}


def required_evaluators(case):
    """返回本命题所需求值器；未登记返回 ``None``（显式标注，不猜）。"""
    return CASE_EVALUATORS.get(case)


def scoped_evidence(detection, required):
    """只统计本命题所需求值器的业务证据；没有 per-evaluator 明细时返回 ``None``。"""
    per = (detection or {}).get('business_evidence')
    # 有统计结构但字典为空 = 明确「本命题 0 条证据」(0)；
    # 结构缺失 / 未登记契约 = 无法裁剪 (None)。两者不可混，见 FIELD_CONTRACT.md §6。
    if not isinstance(per, dict) or required is None:
        return None
    total = 0
    for name, row in per.items():
        if name in required and isinstance(row, dict):
            try:
                total += int(row.get('count') or 0)
            except (TypeError, ValueError):
                continue
    return total


def observation(detection, case):
    """判定本命题的观测状态：复用共享内核三态，绝不把弃判写成阴性。

    ``detection`` 是 ``claim_verdicts.read_detection()`` 的返回值（只增字段，不改旧键）。
    返回的字段全部是**新增投影字段**，不覆盖任何既有计数字段。
    """
    required = required_evaluators(case)
    if required is None:
        return {
            'observation_state': UNSCOPED,
            'observation_scope': 'unregistered_case',
            'required_evaluators': [],
            'matched_evaluators': [],
            'business_evidence_scoped': None,
            'observation_reason': ('该 case 未登记命题↔求值器契约，沿用既有统计结构；'
                                   '本行不得据此声称「本题已被观测」。'),
            'missing_conditions': [],
            'missing_reasons': {},
        }
    det = detection or {}
    ran = [str(name) for name in (det.get('evaluators_that_ran') or [])]
    matched = [name for name in required if name in ran]
    present = det.get('detection_summary_present') is True
    scoped = scoped_evidence(det, required)
    business = scoped if scoped is not None else (det.get('business_evidence_total') or 0)
    conditions = [
        dc.condition('summary_present', '本轮有 detection_summary 统计结构', present,
                     '产物没有 detection_summary，无法确认任何求值器是否运行'),
        dc.condition('question_evaluator_ran', '本命题所需求值器至少有一个运行',
                     bool(matched),
                     '本命题所需 ' + '、'.join(required) + ' 均未运行'),
    ]
    decision = dc.evaluate('claim:' + str(case),
                           ('summary_present', 'question_evaluator_ran'),
                           conditions, bool(business > 0))
    dc.assert_no_negative_verdict(decision)
    reason = decision.statement
    if decision.status == dc.NOT_APPLICABLE:
        # 评审 F4：内核 statement 已自带「本轮不可判定（不是阴性结论）：」，
        # 不再叠加同义前缀。逐条 missing_reasons 才区分「统计结构缺失」
        # 与「所需求值器未运行」，两者补救动作不同。
        detail = '；'.join(f'{key}：{text}'
                           for key, text in decision.missing_reasons.items())
        reason = (reason
                  + ('具体原因：' + detail + '。' if detail else '')
                  + ' 已运行的其他求值器不能替代本命题所需求值器。')
    return {
        'observation_state': decision.status,
        'observation_scope': 'scoped',
        'required_evaluators': list(required),
        'matched_evaluators': matched,
        'business_evidence_scoped': scoped,
        'observation_reason': reason,
        'satisfied_conditions': list(decision.satisfied),
        'missing_conditions': list(decision.missing),
        'missing_reasons': dict(decision.missing_reasons),
    }


def classify(adjudicated, *, observed, evidence_present):
    """七态判定的唯一实现；``observed`` / ``evidence_present`` 必须是显式 bool。

    状态集合与 2026-11-10 版完全一致（不新增、不重编号），只是把「是否观测到」
    与「证据是否属于本命题」这两个入参改成由调用方按契约给出。
    """
    if not isinstance(observed, bool) or not isinstance(evidence_present, bool):
        raise ValueError('observed / evidence_present must be explicit bools')
    if adjudicated not in ('present', 'absent'):
        return 'unscored'
    if evidence_present:
        return 'correct_assert' if adjudicated == 'present' else 'false_positive'
    if adjudicated == 'present':
        return 'false_negative' if observed else 'missed_without_observation'
    return 'correct_rejection' if observed else 'correct_by_absence_of_observation'


def report_cell(row):
    """报告「本命题观测」列的唯一映射：观测三态 + unscored 的具体原因。

    旧产物无 observation_state 且非 unscored 时显示「无观测状态」，不按数量推算。
    """
    row = row or {}
    if row.get('status') == 'unscored':
        return UNSCORED_REASONS.get(row.get('unscored_reason'), '未计分·原因未记录')
    return STATE_LABELS.get(row.get('observation_state'), '—（无观测状态）')


def evidence_cell(row, dash='—'):
    """报告「业务证据」列的唯一映射：只投影按命题裁剪后的证据数。

    整轮 ``business_evidence_total`` 不得进入本列（C2 反例）；旧产物没有
    ``business_evidence_scoped`` 时返回 dash，绝不退化成整轮值或默认 0。
    """
    row = row or {}
    if row.get('status') == 'unscored':
        return dash
    value = row.get('business_evidence_scoped')
    return value if type(value) is int and value >= 0 else dash


def legacy_stance(adjudicated, business_total, evaluators_ran):
    """逐行复刻 2026-11-10 版 ``claim_verdicts.py::stance``（:38-48），仅供复现反例。"""
    if adjudicated not in ('present', 'absent'):
        return 'unscored'
    observed = bool(evaluators_ran)
    if (business_total or 0) > 0:
        return 'correct_assert' if adjudicated == 'present' else 'false_positive'
    if adjudicated == 'present':
        return 'false_negative' if observed else 'missed_without_observation'
    return 'correct_rejection' if observed else 'correct_by_absence_of_observation'


def _detection(counts, ran, present=True, total=None):
    per = {name: {'count': value, 'ran': True} for name, value in counts.items()}
    return {
        'business_evidence_total': sum(per[r]['count'] for r in per) if total is None else total,
        'rule_hits': 0,
        'evaluators_that_ran': list(ran),
        'detection_summary_present': present,
        'business_evidence': per if present else None,
        'evaluator_gaps': [],
    }


def _fixed(detection, case, adjudicated):
    obs = observation(detection, case)
    scoped = obs['business_evidence_scoped']
    return {
        'observation_state': obs['observation_state'],
        'required_evaluators': obs['required_evaluators'],
        'matched_evaluators': obs['matched_evaluators'],
        'business_evidence_scoped': scoped,
        'system_stance': 'present' if (scoped or 0) > 0 else 'absent',
        'status': classify(adjudicated,
                           observed=obs['observation_state'] in (dc.DECIDABLE,
                                                                 dc.DECIDABLE_NO_EVIDENCE),
                           evidence_present=(scoped or 0) > 0),
        'observation_reason': obs['observation_reason'],
    }


def counterexamples():
    """四种判定口径的可复现反例。全部合成输入，不需要设备、不需要冻结产物。

    每项给出 ``legacy``（旧口径下实际会发生什么，即周一复现结果）与
    ``fixed``（按本契约应有的结果，即周二修复目标）。
    """
    out = {}

    # C1：本题要 mg4_native_http，实际只跑了不相关的 ha_websocket。
    c1 = _detection({'ha_websocket': 0}, ['ha_websocket'])
    out['C1'] = {
        'caliber': CALIBERS['C1'], 'case': 'mg4-post', 'adjudicated': 'present',
        'input': {'evaluators_that_ran': c1['evaluators_that_ran'],
                  'business_evidence': c1['business_evidence']},
        'legacy': {'system_stance': 'absent',
                   'status': legacy_stance('present', c1['business_evidence_total'],
                                           c1['evaluators_that_ran']),
                   'observation_state': None,
                   'defect': '本题求值器根本没跑，却记成「观测了但漏检」(false_negative)，污染 recall。'},
        'fixed': _fixed(c1, 'mg4-post', 'present'),
        'expected': '本题未被观测 → missed_without_observation + not_applicable。',
    }

    # C2：别的 case 的 3 条 websocket 证据被算到 mg4-post 命题头上。
    c2 = _detection({'ha_websocket': 3}, ['ha_websocket'])
    out['C2'] = {
        'caliber': CALIBERS['C2'], 'case': 'mg4-post', 'adjudicated': 'present',
        'input': {'evaluators_that_ran': c2['evaluators_that_ran'],
                  'business_evidence': c2['business_evidence']},
        'legacy': {'system_stance': 'present',
                   'status': legacy_stance('present', c2['business_evidence_total'],
                                           c2['evaluators_that_ran']),
                   'observation_state': None,
                   'defect': '整轮 business_evidence_total=3 被当成本命题命中，给出 correct_assert。'},
        'fixed': _fixed(c2, 'mg4-post', 'present'),
        'expected': '按命题裁剪后证据=0 → absent + missed_without_observation，不借别题证据。',
    }

    # C3：产物里根本没有 detection_summary，旧口径把它当成「求值器没跑且结论碰巧正确」。
    c3 = _detection({}, [], present=False)
    out['C3'] = {
        'caliber': CALIBERS['C3'], 'case': 'ha-control-failure', 'adjudicated': 'absent',
        'input': {'detection_summary_present': False,
                  'note': 'read_detection() 旧实现用 or 0 / or [] 补齐，与「跑了且 0 命中」同形'},
        'legacy': {'system_stance': 'absent',
                   'status': legacy_stance('absent', 0, []),
                   'observation_state': None,
                   'defect': '统计结构缺失被写成 correct_by_absence_of_observation 并计入计分分母，'
                             '报告还会编造原因「没有运行任何求值器」；实际连是否运行都不可判。'},
        'fixed': _fixed(c3, 'ha-control-failure', 'absent'),
        'expected': '状态仍沿用七态（统计兼容），但 observation_state=not_applicable 且写明缺统计结构。',
    }

    # C4：报告把「运行求值器数」当观测证据；W03 冻结行的显示口径与计分口径不一致。
    row = {'item': 'W03', 'case': 'mg4-post', 'adjudicated': 'absent',
           'evaluators_that_ran': [], 'business_evidence_total': 0,
           'observation_state': dc.NOT_APPLICABLE}
    out['C4'] = {
        'caliber': CALIBERS['C4'], 'case': 'mg4-post', 'adjudicated': 'absent',
        'input': {'report_row': row},
        'legacy': {'report_column': '运行求值器数', 'report_cell': 0,
                   'defect': '表格只有数量 0，没有三态；读者会把 0 读成「没发生/没行为」，'
                             '与计分里的 not_applicable / unobserved_ratio 不同口径。'},
        'fixed': {'report_column': '本命题观测', 'report_cell': report_cell(row)},
        'expected': '显示列给出「不可判（未运行/缺统计）」，与 observation_state 同源。',
    }
    return out
