"""AAOS observation-condition-gated questions. 仅用于授权测试（自有设备与 APK）。

Turns scattered engineering checks into one rule model: for each question q,
define the necessary observation-condition set P_q, probe this run's artifacts,
and only allow an answer when every condition holds. A missing condition yields
``not_applicable`` plus the exact list of what is needed to recover -- never
"no violation", "did not happen" or "passed".

This module is vehicle-specific (VHAL reads, UID/user isolation, property-bound
payloads). The gating contract itself lives in ``core.evidence.decidability``
so the mobile line can reuse it without vehicle depending on mobile.
"""
from __future__ import annotations

from core.collector.identity import uid_of, user_of
from core.evidence import decidability as dc
from vehicle.analyze.value_match import raw_value
from vehicle.policy.availability import policy_text_usable

Q_VALUE_OBTAINED = 'q_actual_value_obtained'
Q_CONTENT_MATCH = 'q_content_match_in_egress'
Q_SOURCE_LOCATED = 'q_source_read_located'
Q_BEFORE_CONSENT = 'q_before_policy_consent'
Q_POLICY_CONSISTENCY = 'q_policy_disclosure_consistency'

# question -> ordered necessary conditions P_q. Different questions are judged
# separately; one global "run healthy" flag may never stand in for all of them.
QUESTIONS = {
    Q_VALUE_OBTAINED: ('collector_healthy', 'hook_observation_present',
                       'read_return_semantics_clear', 'read_identity_resolved', 'clock_comparable'),
    Q_CONTENT_MATCH: ('collector_healthy', 'read_return_semantics_clear',
                      'flow_identity_resolved', 'request_body_available',
                      'body_structured_parsed', 'value_match_observed'),
    Q_SOURCE_LOCATED: ('collector_healthy', 'read_return_semantics_clear',
                       'flow_identity_resolved', 'clock_comparable', 'request_body_available',
                       'body_structured_parsed', 'candidate_enumeration_complete',
                       'repeat_or_batch_disambiguated'),
    Q_BEFORE_CONSENT: ('collector_healthy', 'clock_comparable', 'consent_channel_available',
                       'read_return_semantics_clear'),
    Q_POLICY_CONSISTENCY: ('policy_snapshot_bound', 'policy_clause_located',
                           'value_match_observed', 'human_semantic_review'),
}

DESCRIPTIONS = {
    'collector_healthy': '采集回调健康且无未处理异常',
    'hook_observation_present': '目标包有带会话标识的 VHAL 读取 Hook 记录',
    'read_return_semantics_clear': '至少一次成功读取且返回值语义明确',
    'identity_resolved': '读取与流可解析到 UID/用户且归因无歧义',
    'read_identity_resolved': '读取侧可解析到 UID 与用户',
    'flow_identity_resolved': '外发流可归属到 UID 且无归因歧义',
    'clock_comparable': '读取时间可用主机接收时间或显式设备时钟偏移比较',
    'request_body_available': '至少一条请求正文完整可用、无截断/解码失败',
    'body_structured_parsed': '请求正文按属性绑定解析，未依赖启发式标记',
    'value_match_observed': '至少一条配对有属性绑定的值级内容匹配',
    'candidate_enumeration_complete': '上传的候选集合覆盖了所有时序可能的成功读取（不只是窗口内命中）',
    'repeat_or_batch_disambiguated': '重复值/批传的来源歧义已被显式识别且候选完整',
    'consent_channel_available': '存在可信的政策同意/查看信号（车载默认无此通道）',
    'policy_snapshot_bound': '可用政策原文与受测 APK 摘要绑定（用户协议/抽取失败不算）',
    'policy_clause_located': '政策具体条款/原文已定位',
    'human_semantic_review': '政策一致性已由人工语义复核（工具不产出违规结论）',
}


def _health_ok(value):
    """Strict probe: no record means NOT satisfied (fail closed, never guessed)."""
    if value is True:
        return True, None
    if isinstance(value, dict):
        if value.get('errors'):
            return False, f"采集健康记录含 {len(value['errors'])} 条回调异常"
        if value.get('passed') is True or value.get('status') in ('completed', 'passed'):
            return True, None
        return False, f"采集健康记录状态为 {value.get('status')!r}，不能确认健康"
    return False, '未提供 collector-health.json / 采集健康记录；本轮按不满足处理'


def candidate_coverage(reads, flows, candidate_summary):
    """Check whether source sets cover all time-plausible successful reads.

    ``findings.pairs`` only contains reads that matched INSIDE the configured
    window. Building a candidate set from those pairs therefore does NOT prove
    the source set is complete: a cached/delayed batch upload may originate
    from an earlier successful read that the window excluded. Review P1-1.

    For each set (one outbound flow + rule), enumerate every successful read of
    the same property whose host receive time is not later than that flow, then
    report the ids absent from the set. Reads without a comparable clock are
    skipped -- ``clock_comparable`` gates those separately.
    """
    sets = (candidate_summary or {}).get('sets') or []
    if not sets:
        return {'applicable': False, 'complete': False, 'possible_reads': 0,
                'missing_read_ids': [],
                'note': '未产生来源候选集合，完整性不可验证（按不满足处理）'}
    flow_ts = {f.get('evt_id'): f.get('ts') for f in flows
               if type(f.get('ts')) in (int, float)}
    possible, missing = set(), set()
    for row in sets:
        prop = str(row.get('property'))
        enumerated = {str(cid).rsplit(':', 1)[-1] for cid in row.get('candidate_ids', [])}
        ts = flow_ts.get(row.get('flow_event_id'))
        for read in reads:
            if (read.get('ev') != 'VHAL_READ' or read.get('outcome') != 'ok'
                    or str(read.get('prop_name')) != prop or raw_value(read) is None):
                continue
            received = read.get('host_received_ts')
            if type(received) not in (int, float):
                continue
            if ts is not None and received > ts:
                continue
            rid = str(read['evt_id'])
            possible.add(rid)
            if rid not in enumerated:
                missing.add(rid)
    return {'applicable': True, 'complete': not missing,
            'possible_reads': len(possible), 'missing_read_ids': sorted(missing),
            'note': ('候选集合只覆盖窗口内命中；更早的缓存/批传来源读取未进入候选。'
                     if missing else '候选集合覆盖了本轮时序可能的同属性成功读取。')}


def probe_conditions(reads, flows, findings, *, collector_health=None,
                     consent=None, policy=None, candidate_summary=None,
                     candidate_coverage_result=None):
    """Probe every condition purely from this run's artifacts."""
    reads, flows, findings = list(reads), list(flows), list(findings)
    vhal = [r for r in reads if r.get('ev') == 'VHAL_READ']
    successful = [r for r in vhal if r.get('outcome') == 'ok'
                  and raw_value(r) is not None and r.get('pkg')]
    clock_ok = any(r.get('host_received_ts') is not None for r in successful)
    # Read identity and transport identity are answered by DIFFERENT questions.
    # Review P0-4: one unattributable, unrelated flow used to make a perfectly
    # decidable "did the app obtain this value" question undecidable.
    read_identity_ok = bool(successful) and all(
        uid_of(r) is not None and user_of(r) is not None for r in successful)
    flow_identity_ok = not any(
        f.get('attribution_ambiguous') or f.get('attribution') in ('unresolved', 'ambiguous')
        for f in flows)
    payloads = [(f.get('request_payload') or {}).get('text') for f in flows]
    body_ok = any(isinstance(t, str) and t for t in payloads)
    body_clean = body_ok and not any(
        (f.get('request_payload') or {}).get('text_truncated') or
        (f.get('request_payload') or {}).get('decode_error') or
        (f.get('request_parse') or {}).get('heuristic') for f in flows)
    pairs = [p for f in findings for p in (f.get('pairs') or [])]
    value_ok = any(p.get('value_match') is True and
                   p.get('content_match_basis') == 'request_property_value' for p in pairs)
    cand = candidate_summary or {}
    coverage = candidate_coverage_result or candidate_coverage(reads, flows, cand)
    cand_ok = cand.get('candidate_sets', 0) > 0 and cand.get('generated_by') is not None
    enumeration_complete = cand_ok and coverage['applicable'] and coverage['complete']
    disambiguated = enumeration_complete and 'ambiguity_rate' in cand
    consent_ok = bool(consent) and consent.get('trusted') is True
    policy = policy or {}
    policy_bound = policy_text_usable(policy)
    clause_ok = bool(policy.get('clause_refs') or policy.get('reviews'))
    reviewed = policy.get('human_signoff') == 'signed' or policy.get('independent_human_review') is True
    healthy, health_detail = _health_ok(collector_health)

    probes = {
        'collector_healthy': (healthy, health_detail),
        'hook_observation_present': (bool(vhal) and any(r.get('session_id') for r in vhal),
                                     '目标包无带 session_id 的 VHAL_READ 事件'),
        'read_return_semantics_clear': (bool(successful), '没有 outcome=ok 且返回值可解析的读取'),
        'identity_resolved': (read_identity_ok and flow_identity_ok,
                              'UID/用户未全部解析，或存在归因歧义流'),
        'read_identity_resolved': (read_identity_ok, '读取侧 UID/用户未全部解析'),
        'flow_identity_resolved': (flow_identity_ok,
                                   '存在归因未解析/歧义的外发流；只影响与传输相关的问题，'
                                   '不影响「是否取得值」'),
        'clock_comparable': (clock_ok, '缺少 host_received_ts，且未提供显式设备时钟偏移'),
        'request_body_available': (body_ok, '本轮没有可用的请求正文'),
        'body_structured_parsed': (body_clean, '正文截断/解码失败，或仅启发式解析'),
        'value_match_observed': (value_ok, '没有属性绑定的值级内容匹配配对'),
        'candidate_enumeration_complete': (
            enumeration_complete,
            (f"另有 {len(coverage['missing_read_ids'])} 条时序可能、同属性的成功读取未进入候选；"
             f"候选集合可能只覆盖窗口内命中（缺 {','.join(coverage['missing_read_ids'][:8])}）"
             if cand_ok and not enumeration_complete else coverage['note'])),
        'repeat_or_batch_disambiguated': (
            disambiguated, '候选集合不完整或未显式给出歧义率，不能声称已处理重复值/批传'),
        'consent_channel_available': (consent_ok, '车载本轮无可信同意信号通道；'
                                      '「未观测到同意」不可反推「用户未同意」'),
        'policy_snapshot_bound': (policy_bound,
                                  '缺少可用的隐私政策原文；用户协议、抽取失败或未绑定快照都不算'),
        'policy_clause_located': (clause_ok, '未提供具体条款/原文定位'),
        'human_semantic_review': (reviewed, '政策一致性需人工语义复核，工具不产出违规结论'),
    }
    return [dc.condition(key, DESCRIPTIONS[key], ok, None if ok else detail)
            for key, (ok, detail) in probes.items()]


def default_evidence(findings, reads, candidate_summary=None, policy=None):
    """Whether each question has positive evidence in this run (explicit bool).

    A successful VHAL read in ``reads`` IS the evidence for "did the app obtain
    a value"; requiring a ``read_event`` finding would misreport a real read as
    "no evidence" whenever the sensitive-read rule was disabled or filtered.
    Review P2-3.
    """
    findings, reads = list(findings), list(reads)
    cand = candidate_summary or {}
    return {
        Q_VALUE_OBTAINED: (any(f.get('evidence_kind') == 'read_event' for f in findings)
                           or any(r.get('ev') == 'VHAL_READ' and r.get('outcome') == 'ok'
                                  and raw_value(r) is not None for r in reads)),
        Q_CONTENT_MATCH: any(f.get('value_match') is True for f in findings),
        Q_SOURCE_LOCATED: cand.get('unique_candidate', 0) > 0,
        Q_BEFORE_CONSENT: False,  # no consent channel by design; not a negative finding
        Q_POLICY_CONSISTENCY: policy_text_usable(policy),
    }


def assess(reads, flows, findings, *, collector_health=None, consent=None,
           policy=None, candidate_summary=None, evidence_overrides=None):
    """Full condition report for one run. Pure function, no I/O, no mutation."""
    coverage = candidate_coverage(reads, flows, candidate_summary)
    conditions = probe_conditions(reads, flows, findings,
                                  collector_health=collector_health, consent=consent,
                                  policy=policy, candidate_summary=candidate_summary,
                                  candidate_coverage_result=coverage)
    evidence = default_evidence(findings, reads, candidate_summary, policy)
    if evidence_overrides:
        evidence.update(evidence_overrides)
    decisions = dc.evaluate_all(QUESTIONS, conditions, evidence)
    for decision in decisions:
        dc.assert_no_negative_verdict(decision)
    # A run that produced positive findings while the collector was unhealthy is
    # exactly the failure mode "collection fault explained as a normal result".
    health = next(c for c in conditions if c.key == 'collector_healthy')
    positive = sum(f.get('evidence_kind') in ('read_event', 'read_then_egress')
                   for f in findings)
    return {
        'generated_by': 'vehicle/analyze/observation_conditions.py::assess',
        'schema_version': 1,
        'model': 'per-question necessary observation conditions P_q',
        'questions': [d.as_dict() for d in decisions],
        'rates': dc.decidability_rates(decisions),
        'conditions': {c.key: {'description': c.description, 'satisfied': c.satisfied,
                               'detail': c.detail} for c in conditions},
        'candidate_coverage': coverage,
        'fault_as_clean_signals': positive if not health.satisfied else 0,
        'caveats': [
            'not_applicable 表示本轮观测条件不足，不是「未发生」「未传输」或「合规」。',
            '每个问题分别判定；不得用一个全局健康标记替代各问题的必要条件。',
            '候选集合来源只覆盖窗口内命中时，「来源已定位」必须弃判；缓存/批传读取可能更早。',
            '内容相等不证明因果传播；唯一来源候选不等于污点追踪结果。',
            '未观测到同意事件不可反推用户未同意；静态引用不保证本轮可执行到。',
        ],
    }
