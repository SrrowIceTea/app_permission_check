"""Claim-level verdicts: system stance vs adjudicated blind answer.

仅用于授权测试。

Six of the twelve items in the blind round are workflow propositions ("can this
server POST be bound to that app request?"), and they were signed but never
scored: only the six battery pair items became ``expected_pairs``. This module
turns those signed workflow answers into a table without asking anyone to review
anything again.

The classification deliberately separates *being right* from *having evidence*:

  correct_assert                     asserted, adjudication agrees
  correct_rejection                  asserted absence after observing, agrees
  false_positive                     asserted presence, adjudication disagrees
  false_negative                     adjudicated present, observed, missed
  missed_without_observation         adjudicated present, no evaluator ran
  correct_by_absence_of_observation  adjudicated absent, no evaluator ran
  unscored                           no audit output, or reviewers disagreed

The last-but-one bucket is why there is no single accuracy number here. A system
that never observes anything lands in it, and it looks correct. Reporting it as
"right" would repeat exactly the defect this project keeps finding: absence of
evidence read as evidence of absence.

2026-11-17（周二）口径修复：状态集合、counts、三个比率**一个都没改**，只补投影字段。
在此之前 ``observed = bool(evaluators_ran)`` 把「任意求值器跑过」当成「本题观测充分」，
且 ``business_evidence_total`` 是整轮合计、未按命题裁剪。现由
``vehicle/bench/claim_scope.py`` 按命题绑定所需求值器、复用
``core/evidence/decidability.py`` 三态；统计结构缺失显式记 ``not_applicable``。
未登记契约的 case（含历史离线测试合成 case）沿用旧口径并标注 ``legacy_unscoped``。
"""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from core.evidence import decidability as dc
from vehicle.bench import claim_scope as scope

STANCES = ('correct_assert', 'correct_rejection', 'false_positive', 'false_negative',
           'missed_without_observation', 'correct_by_absence_of_observation', 'unscored')
# Right answers reached without observation. Counted, never credited as evidence.
UNOBSERVED = ('correct_by_absence_of_observation', 'missed_without_observation')

SCOPE_CAVEAT = (
    '观测状态按命题绑定求值器：只有本命题所需求值器运行过、且本轮有 detection_summary，'
    '才允许说「本题已观测」。not_applicable 是本轮不可判定，不是阴性结论、不是未发生、不代表安全；'
    'legacy_unscoped 表示 case 未登记命题↔求值器契约，沿用旧统计结构且不得据以声称观测充分。'
    '七个判定状态、counts 与三个比率均未改动，新增字段只做可追溯投影。'
)


def stance(adjudicated, business_evidence, evaluators_ran, *, observation=None,
           business_scoped=None):
    """Seven-way stance. ``adjudicated`` must already be a settled present/absent.

    不传 ``observation`` 时的**兼容路径**（旧口径）仅为兼容历史上直接调用
    ``stance()`` 的纯函数测试而保留，**生产路径禁止使用**：它会把任意求值器运行
    当成本题观测充分（评审 F1）。``report()`` 对每一行都传三态，未登记契约的 case
    传 ``UNSCOPED`` ⇒ observed=False，只作统计占位。
    """
    if observation is None:
        return scope.classify(adjudicated, observed=bool(evaluators_ran),
                              evidence_present=(business_evidence or 0) > 0)
    return scope.classify(
        adjudicated,
        observed=observation in (dc.DECIDABLE, dc.DECIDABLE_NO_EVIDENCE),
        evidence_present=(business_scoped or 0) > 0)


def _num(value):
    """缺字段补 0 只为兼容既有报告字段；语义由 detection_summary_present 承担。"""
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


def read_detection(path):
    """Pull the detection fields out of an audit summary.

    旧实现把「产物没有 detection_summary」用 ``or 0`` / ``or []`` 补齐，与
    「求值器跑了且 0 命中」同形。现显式记 ``detection_summary_present``，
    并带出 per-evaluator 明细与 evaluator_gaps 供命题裁剪，旧三键保持不变。
    """
    document = json.loads(Path(path).read_text(encoding='utf-8'))
    raw = document.get('detection_summary')
    present = isinstance(raw, dict)
    summary = raw if present else {}
    per = summary.get('business_evidence')
    return {
        'business_evidence_total': _num(summary.get('business_evidence_total')),
        'rule_hits': _num((summary.get('rule_hits') or {}).get('total')),
        'evaluators_that_ran': list(summary.get('evaluators_that_ran') or []),
        'detection_summary_present': present,
        # 结构缺失时留 None（不可裁剪），有结构但空字典留 {}（明确 0 条）。
        'business_evidence': ((per if isinstance(per, dict) else {}) if present else None),
        'evaluator_gaps': [row for row in (document.get('evaluator_gaps') or [])
                           if isinstance(row, dict)],
    }


def _settled(item):
    """The agreed decision, or None when the two reviewers disagreed."""
    first, second = item.get('A') or {}, item.get('B') or {}
    if first.get('decision') and first.get('decision') == second.get('decision'):
        return first['decision']
    return None


def report(adjudications, audit_dir, *, label_tier=None):
    rows = []
    for item in adjudications:
        case, item_id = item.get('case'), item.get('id')
        decision = _settled(item)
        summary_path = Path(audit_dir) / str(case) / 'correlation-summary.json'
        if decision is None:
            rows.append({'item': item_id, 'case': case, 'status': 'unscored',
                         'unscored_reason': 'reviewers_disagreed'})
            continue
        if not summary_path.is_file():
            rows.append({'item': item_id, 'case': case, 'adjudicated': decision,
                         'status': 'unscored', 'unscored_reason': 'no_audit_output'})
            continue
        observed = read_detection(summary_path)
        obs = scope.observation(observed, case)
        scoped = obs['business_evidence_scoped']
        evidence = ((scoped if scoped is not None else 0)
                    if obs['observation_scope'] == 'scoped'
                    else observed['business_evidence_total'])
        # 评审 F1：未登记契约的 case 过去落 stance() 兼容路径，仍以
        # bool(evaluators_ran) 决定七态，等于把「任意求值器运行」当成本题观测。
        # 现在生产路径一律传三态；UNSCOPED 时 observed=False，只作统计占位。
        status = stance(decision, evidence, observed['evaluators_that_ran'],
                        observation=obs['observation_state'], business_scoped=evidence)
        rows.append({'item': item_id, 'case': case, 'adjudicated': decision,
                     'system_stance': 'present' if evidence > 0 else 'absent',
                     'status_basis': ('scoped_three_state'
                                      if obs['observation_scope'] == 'scoped'
                                      else 'unregistered_no_observation_credited'),
                     **observed, **obs, 'status': status})
    counts = Counter(row['status'] for row in rows)
    scored = len(rows) - counts['unscored']
    states = Counter(row.get('observation_state') or 'none' for row in rows)
    return {
        'generated_by': 'vehicle/bench/claim_verdicts.py::report',
        'schema_version': 1,
        'label_tier': label_tier,
        'items': rows,
        'counts': {name: counts.get(name, 0) for name in STANCES},
        'scored': scored,
        # No composite accuracy. Each ratio has a different denominator on purpose:
        # a mass-abstention system must not look better than an observant one.
        'asserted_ratio': (round((counts['correct_assert'] + counts['false_positive']) / scored, 4)
                           if scored else None),
        'wrong_assertion_ratio': (round(counts['false_positive'] / scored, 4)
                                  if scored else None),
        'unobserved_ratio': (round(sum(counts[name] for name in UNOBSERVED) / scored, 4)
                             if scored else None),
        # 新增：只做状态投影，不参与上面任何比率的分母。
        'observation_states': {name: states.get(name, 0)
                               for name in (dc.DECIDABLE, dc.DECIDABLE_NO_EVIDENCE,
                                            dc.NOT_APPLICABLE, scope.UNSCOPED)},
        'not_applicable_count': states[dc.NOT_APPLICABLE],
        'unregistered_cases': sorted({str(row['case']) for row in rows
                                      if row.get('observation_scope') == 'unregistered_case'}),
        'scope_caveat': SCOPE_CAVEAT,
        'caveat': (
            '断言正确与「没观测所以没说」必须分开看：'
            'correct_by_absence_of_observation 是结论碰巧正确、依据不成立，不得计入有效性。'
            'wrong_assertion_ratio 的分母是已计分项，不是全部样本。'
        ),
    }


def main():
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--adjudication', type=Path, required=True,
                        help='blind_round compare 产出的 workflow-reviews.json')
    parser.add_argument('--audit-dir', type=Path, required=True,
                        help='按 case id 分目录的 audit 产物根目录')
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    items = json.loads(args.adjudication.read_text(encoding='utf-8'))
    result = report(items, args.audit_dir)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps({'scored': result['scored'], 'counts': result['counts'],
                      'observation_states': result['observation_states'],
                      'out': str(args.out)}, ensure_ascii=False))


if __name__ == '__main__':
    main()
