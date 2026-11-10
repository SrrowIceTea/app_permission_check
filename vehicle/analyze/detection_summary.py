"""Three separate detection counts for one audit run. 仅用于授权测试。

Why this module exists: ``findings_total`` counts only ``findings.jsonl``. The
specialised evaluators (HA websocket, MG4, YAABSA/ABS) write their results into
*summary* fields and never append a finding, so a run with four real detections
can still report ``findings_total = 0``. Reading that number as "nothing was
detected" is wrong, and reading the summary as "rule hits" is equally wrong --
they are different strengths of claim.

This module reports them side by side and never collapses them into one number:

  rule_hits          rule-engine findings (a rule fired and produced evidence)
  business_evidence  specialised per-sample evaluator output (business receipt,
                     websocket pair, native write, webview request ref)
  zero_observation   neither of the above: the run really observed nothing

A single "detection rate" would both overstate (counting a business receipt as a
rule hit) and understate (dropping the summary evidence entirely).
"""
from __future__ import annotations

# Each extractor returns the number of *evidence items*, not a verdict. A value
# of 0 with the field present means "the evaluator ran and matched nothing",
# which is different from the field being absent (evaluator never ran).
EXTRACTORS = {
    'ha_webhook': lambda body: body.get('matched_requests') or 0,
    'ha_websocket': lambda body: len(body.get('pairs') or []),
    'mg4_native_http': lambda body: max(len(body.get('verified_flows') or []),
                                        body.get('matched_requests') or 0),
    'mg4_webview': lambda body: len(body.get('request_refs') or []),
    'abs_native_send': lambda body: body.get('verified_requests') or 0,
}

# owntracks_location is deliberately absent: it appends findings, so its evidence
# is already counted under rule_hits. Counting it twice would inflate the total.


def summarize(findings, document):
    """Return rule/business/zero counts for one audit document.

    Pure function. ``document`` is the summary dict produced by the pipeline;
    ``findings`` is the loaded findings list. Neither is mutated.
    """
    findings = [row for row in (findings or []) if isinstance(row, dict)]
    rules = {}
    conclusions = {}
    for row in findings:
        rule_id = row.get('rule_id')
        if not rule_id:
            continue
        rules[rule_id] = rules.get(rule_id, 0) + 1
        level = row.get('conclusion_level') or 'unknown'
        conclusions[level] = conclusions.get(level, 0) + 1

    business = {}
    for key, extract in EXTRACTORS.items():
        body = (document or {}).get(key)
        if not isinstance(body, dict):
            continue  # evaluator never ran: absent, not zero
        try:
            count = int(extract(body))
        except (TypeError, ValueError):
            count = 0
        business[key] = {'count': count, 'ran': True,
                         'scope': body.get('scope') or body.get('source')}

    rule_total = sum(rules.values())
    business_total = sum(row['count'] for row in business.values())
    zero = rule_total == 0 and business_total == 0
    # Gaps only matter when nothing was detected: a HA sample legitimately has no
    # MG4 contract, so surfacing every absent contract would drown the real cause
    # in noise. When a run DID detect something, the evaluator set is simply not
    # applicable and the absence carries no diagnostic value.
    gaps = [row for row in ((document or {}).get('evaluator_gaps') or [])
            if isinstance(row, dict)] if zero else []
    return {
        'generated_by': 'vehicle/analyze/detection_summary.py::summarize',
        'schema_version': 1,
        'rule_hits': {'total': rule_total, 'by_rule': rules, 'by_conclusion': conclusions},
        'business_evidence': business,
        'business_evidence_total': business_total,
        'evaluators_that_ran': sorted(business),
        # A gap explains WHY a zero happened. Without it, "evaluator skipped
        # because the capture never bound the contract" is indistinguishable from
        # "the application did nothing".
        'evaluator_gaps': gaps,
        'zero_observation': zero,
        'zero_observation_explained': bool(gaps) if zero else None,
        'caveat': (
            '规则命中与业务证据是两类不同强度的结论，不得合并成一个「检测率」。'
            '业务证据字段存在但 count=0 表示求值器跑了且没匹配上；字段缺失表示求值器未运行，'
            '两者都不等于「应用没有行为」。evaluator_gaps 仅在本轮零观测时给出，用于解释零从何而来。'
        ),
    }
