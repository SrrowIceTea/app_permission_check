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
"""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

STANCES = ('correct_assert', 'correct_rejection', 'false_positive', 'false_negative',
           'missed_without_observation', 'correct_by_absence_of_observation', 'unscored')
# Right answers reached without observation. Counted, never credited as evidence.
UNOBSERVED = ('correct_by_absence_of_observation', 'missed_without_observation')


def stance(adjudicated, business_evidence, evaluators_ran):
    """Five-way stance. ``adjudicated`` must already be a settled present/absent."""
    if adjudicated not in ('present', 'absent'):
        return 'unscored'
    observed = bool(evaluators_ran)
    claims_present = (business_evidence or 0) > 0
    if claims_present:
        return 'correct_assert' if adjudicated == 'present' else 'false_positive'
    if adjudicated == 'present':
        return 'false_negative' if observed else 'missed_without_observation'
    return 'correct_rejection' if observed else 'correct_by_absence_of_observation'


def read_detection(path):
    """Pull the three fields the stance depends on out of an audit summary."""
    document = json.loads(Path(path).read_text(encoding='utf-8'))
    summary = document.get('detection_summary') or {}
    return {'business_evidence_total': summary.get('business_evidence_total') or 0,
            'rule_hits': (summary.get('rule_hits') or {}).get('total') or 0,
            'evaluators_that_ran': list(summary.get('evaluators_that_ran') or [])}


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
        rows.append({'item': item_id, 'case': case, 'adjudicated': decision,
                     'system_stance': ('present' if observed['business_evidence_total'] > 0
                                       else 'absent'),
                     **observed,
                     'status': stance(decision, observed['business_evidence_total'],
                                      observed['evaluators_that_ran'])})
    counts = Counter(row['status'] for row in rows)
    scored = len(rows) - counts['unscored']
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
                      'out': str(args.out)}, ensure_ascii=False))


if __name__ == '__main__':
    main()

