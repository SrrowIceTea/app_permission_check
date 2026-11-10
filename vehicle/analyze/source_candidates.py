"""Ambiguity-aware source candidate sets for AAOS uploads. 仅用于授权测试。

``evaluate_data_egress`` already produces (read, flow) pairs. Those pairs are
*matches*, but a batch upload of a repeatedly-read equal value can plausibly
come from any of several reads. This module keeps the whole candidate set,
narrows it only on explicit, auditable grounds, and reports three distinct
claims separately:

  content_match        -- did the payload contain content equal to a read value?
  source_located       -- is one read the only plausible source in this run?
  causal_propagation   -- never asserted (no taint tracking in passive audit).

It deliberately does NOT collapse nested wrapper reads into one source without
a proven invocation grouping: ``pair_ambiguity.py`` already established that
they remain explicitly non-unique. Only exact duplicate event ids are merged.
"""
from __future__ import annotations

from collections import defaultdict

from core.evidence.ambiguity import MULTIPLE_CANDIDATES, CandidateSet, ambiguity_rates

PROPERTY_BOUND_BASES = ('request_property_value', 'request_property_token')
CANDIDATE_FIELDS = ('read_src', 'read_event_id', 'flow_src', 'flow_event_id',
                    'delta_ms', 'clock_basis', 'identity_scope', 'uid', 'user_id',
                    'value_match', 'value_transform', 'content_match_basis',
                    'pair_basis', 'origin_proven', 'attribution_loose',
                    'matching_read_candidates_for_flow', 'source_read_unique',
                    'token_sha256', 'claim_match_ms')


def _candidate(pair):
    row = {key: pair.get(key) for key in CANDIDATE_FIELDS if key in pair}
    row['id'] = f"{pair.get('read_src', 'vhal')}:{pair['read_event_id']}"
    return row


def _apply_batch(result, cset, batch):
    """Merge batch-level alignment into one flow's candidate set, conservatively.

    Scope first, then merge. A batch carries records for several properties, so
    only the reads of THIS candidate set's property may enter it (review P0-1:
    merging the whole batch added a gear read to a speed set, and vice versa,
    downgrading two genuinely unique sources to ambiguous).

    If the batch has no read of this property, alignment says nothing about it:
    the verdict is left untouched and the silence is recorded explicitly.

    Otherwise: reads already in the set corroborate it; reads pointing at a
    DIFFERENT batch stay as additional candidates and the verdict is downgraded.
    """
    property_key = result.get('property')
    by_property = batch.get('reads_by_property') or {}
    scoped = None if property_key is None else by_property.get(str(property_key))
    if property_key is not None and scoped is None:
        result['batch_alignment'] = {
            'status': 'no_read_for_property', 'applied': False,
            'property': property_key, 'batch_properties': sorted(by_property),
            'note': '该批不含此属性的读取，批次证据对本集合无话可说，状态不变。',
        }
        return result
    aligned_ids = {str(read_id) for read_id in (scoped if scoped is not None
                                                else batch.get('read_event_ids') or [])}
    current = {str(candidate.get('read_event_id')) for candidate in cset.candidates}
    status = ('agreeing' if aligned_ids <= current else
              'partial' if aligned_ids & current else 'conflicting')
    result['batch_alignment'] = {
        'status': status, 'applied': True, 'basis': batch.get('basis'),
        'aligned_read_ids': sorted(aligned_ids, key=int),
        'lag_ms': batch.get('lag_ms'),
        'max_deviation_ms': batch.get('max_deviation_ms'),
        'records': batch.get('records'),
    }
    if status == 'agreeing':
        return result
    source_of = batch.get('read_src_by_id') or {}
    extras = [{'id': f"{source_of.get(str(read_id), 'vhal')}:{read_id}",
               'read_event_id': int(read_id),
               'source': 'batch_alignment', 'value_match': True,
               'content_match_basis': 'request_property_value'}
              for read_id in sorted(aligned_ids - current, key=int)]
    merged = [*cset.candidates, *extras]
    result['candidates'] = merged
    result['candidate_ids'] = [candidate['id'] for candidate in merged]
    result['state'] = MULTIPLE_CANDIDATES
    result['source_located'] = False
    result['statement'] = ('批次对齐指向另一组读取；保留窗口内与批次两组候选，'
                           '来源不可定位，需批次令牌或值变化复核。')
    return result


def build_candidate_sets(findings, batch_report=None):
    """Group every matched pair by its outbound flow, then narrow per flow.

    Pure function. It never removes a source to manufacture uniqueness; each
    narrowing step records its basis and the ids it excluded. ``batch_report``
    (from ``batch_alignment.report``) is optional and only ever *adds* evidence.
    """
    aligned = {row['flow_event_id']: row
               for row in (batch_report or {}).get('aligned', [])}
    groups = defaultdict(list)
    for finding in findings:
        if finding.get('evidence_kind') != 'read_then_egress':
            continue
        for pair in finding.get('pairs') or []:
            key = (pair.get('flow_src', 'proxy'), pair['flow_event_id'],
                   pair.get('uid'), finding.get('rule_id'))
            groups[key].append((finding, pair))

    resolved = []
    for key, rows in sorted(groups.items(), key=lambda item: str(item[0])):
        target_id = f"{key[0]}:{key[1]}:{key[3]}"
        candidates = [_candidate(pair) for _, pair in rows]
        content = any(c.get('value_match') is True and
                      c.get('content_match_basis') == 'request_property_value'
                      for c in candidates)
        basis = next((c.get('content_match_basis') for c in candidates
                      if c.get('content_match_basis') == 'request_property_value'),
                     'request_property_token' if any(
                         c.get('content_match_basis') == 'request_property_token'
                         for c in candidates) else None)
        candidates.sort(key=lambda c: (not bool(c.get('value_match')),
                                       c.get('delta_ms') or 0, c['id']))
        cset = CandidateSet(target_id, candidates, content_match=content,
                            content_match_basis=basis)
        cset.narrow('identity_and_session',
                    lambda c: c.get('identity_scope') not in (None, 'unknown')
                    and c.get('uid') is not None,
                    '排除 UID/身份范围无法解析的来源（保留依据引用）')
        cset.narrow('non_negative_time_order',
                    lambda c: type(c.get('delta_ms')) in (int, float)
                    and c['delta_ms'] >= 0 and c.get('clock_basis') != 'clock_unavailable',
                    '排除时间逆序或时钟不可比的读取')
        cset.narrow('property_binding',
                    lambda c: c.get('content_match_basis') in PROPERTY_BOUND_BASES,
                    '排除没有属性绑定依据的名称/形状命中')
        # Only exact duplicate event ids are merged. Nested API wrappers stay as
        # independent candidates: without a proven call-stack grouping, treating
        # them as one source would be an unverified claim.
        cset.collapse_repeated(lambda c: c['id'],
                               '同一读取事件 ID 重复出现，不是独立来源')
        result = cset.resolve()
        result['rule_id'] = key[3]
        result['flow_event_id'] = key[1]
        result['property'] = rows[0][0].get('property')
        result['attribution_loose_ids'] = [c['id'] for c in cset.candidates
                                           if c.get('attribution_loose')]
        if key[1] in aligned:
            result = _apply_batch(result, cset, aligned[key[1]])
        resolved.append(result)

    rates = ambiguity_rates(resolved)
    return {
        'generated_by': 'vehicle/analyze/source_candidates.py::build_candidate_sets',
        'schema_version': 1,
        **rates,
        'sets': resolved,
        'caveats': [
            '唯一候选只表示「当前观测下唯一可能来源」，不是因果传播证明。',
            '内容匹配与来源定位分别判定；属性名命中不构成值级内容匹配。',
            '嵌套 wrapper 读取无调用栈分组依据时保留为多个候选，不人为合并。',
            '自有夹具批次令牌只能作为夹具独立回执，普通第三方 App 无此能力。',
            '多来源歧义时保留全部依据，不指定单一来源、不降低为「无关联」。',
        ],
    }


def annotate_findings(findings, summary):
    """Return findings with per-flow candidate verdicts attached (no mutation)."""
    by_flow = {row['target_id']: row for row in summary['sets']}
    result = []
    for finding in findings:
        if finding.get('evidence_kind') != 'read_then_egress':
            result.append(finding)
            continue
        states = []
        for pair in finding.get('pairs') or []:
            key = f"{pair.get('flow_src', 'proxy')}:{pair['flow_event_id']}:{finding['rule_id']}"
            row = by_flow.get(key)
            if row:
                states.append(row['state'])
        result.append({**finding,
                       'source_candidate_states': sorted(set(states)),
                       'source_claim_scope': ('unique_candidate_under_current_observation'
                                              if states and all(s == 'unique_candidate' for s in states)
                                              else 'ambiguous_or_unresolved'),
                       'causal_propagation_proven': False})
    return result
