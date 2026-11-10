"""Controlled observation-fault injection for the AAOS ablation. 仅用于授权测试。

Faults are injected into in-memory deep copies of a sealed capture; the frozen
evidence on disk is never modified. The baseline (plain window + value match)
has no condition/gap reporting field, so a collection failure shows up as a
silent zero-pair result that a reader cannot distinguish from a true negative.
The gated method is expected to name the missing condition instead.

Split out of ``ablation.py`` to keep every file under the repository's 300-line
cap. See ``ablation.py`` for the four comparison arms and label limitations.
"""
from __future__ import annotations

import copy

from vehicle.analyze.evaluation import evaluate_data_egress
from vehicle.analyze.method_evidence import attach

FAULTS = ('healthy_control', 'hook_failed', 'attach_late', 'body_truncated',
          'attribution_missing', 'clock_unavailable', 'policy_version_mismatch')
EXPECTED_GAPS = {
    'hook_failed': 'read_return_semantics_clear',
    'body_truncated': 'body_structured_parsed',
    'attribution_missing': 'flow_identity_resolved',
    'clock_unavailable': 'clock_comparable',
    'policy_version_mismatch': 'policy_snapshot_bound',
    'attach_late': None,  # recall loss, not a condition gate
}
# Three distinct kinds of gap. Only the FIRST class may count as an injected
# collection fault being misread as a normal result:
#  1. collection defects   -- the injected fault broke an observation channel.
#  2. method-scope limits  -- candidate sets only cover window hits (review
#     P1-1). This abstention is CORRECT even for a healthy control, so it must
#     never be scored as a fault misread.
#  3. design gaps          -- no consent channel on AAOS, no human policy
#     signoff; absent by design, not caused by any fault.
COLLECTION_CONDITIONS = frozenset({
    'collector_healthy', 'hook_observation_present', 'read_return_semantics_clear',
    'identity_resolved', 'read_identity_resolved', 'flow_identity_resolved',
    'clock_comparable', 'request_body_available',
    'body_structured_parsed', 'value_match_observed'})
METHOD_SCOPE_CONDITIONS = frozenset({
    'candidate_enumeration_complete', 'repeat_or_batch_disambiguated'})
NEGATIVE_CONTROLS = ('healthy_control', 'policy_version_mismatch')
DESIGN_GAPS = frozenset({'consent_channel_available', 'policy_snapshot_bound',
                         'policy_clause_located', 'human_semantic_review'})
# Synthetic *status* only, never a real policy snapshot. It exists so the
# healthy control actually satisfies policy_snapshot_bound and the mismatch
# control has something to break; otherwise both would abstain identically and
# the negative control would prove nothing. Real policy availability follows
# vehicle.policy.availability.policy_text_usable (review P2-2).
CONTROL_POLICY = {
    'status': 'available', 'document_kind': 'app_policy',
    'extraction_status': 'ok', 'apk_sha256': 'CONTROL-ONLY-NO-REAL-SNAPSHOT',
    'source_sha256': 'CONTROL-ONLY-NO-REAL-SNAPSHOT',
    'reviews': [{'finding_id': 'control'}],
    'note': 'synthetic status stub; NOT a privacy-policy snapshot',
}


def inject_fault(name, reads, flows):
    """Return deep-copied artifacts with one controlled observation fault."""
    reads, flows = copy.deepcopy(reads), copy.deepcopy(flows)
    if name == 'hook_failed':
        for read in reads:
            if read.get('ev') == 'VHAL_READ':
                read['outcome'] = 'error'
    elif name == 'attach_late':
        stamps = sorted(r['ts'] for r in reads if r.get('ev') == 'VHAL_READ'
                        and type(r.get('ts')) is int)
        cutoff = stamps[len(stamps) // 2] if stamps else 0
        reads = [r for r in reads if r.get('ev') != 'VHAL_READ' or r.get('ts', 0) >= cutoff]
    elif name == 'body_truncated':
        for flow in flows:
            flow.setdefault('request_payload', {})['text_truncated'] = True
    elif name == 'attribution_missing':
        for flow in flows:
            flow['attribution'] = 'unresolved'
    elif name == 'clock_unavailable':
        for read in reads:
            read.pop('host_received_ts', None)
    return reads, flows


def run_faults(reads, flows, rules, collector_health):
    rows = []
    for fault in FAULTS:
        f_reads, f_flows = inject_fault(fault, reads, flows)
        policy = ({**CONTROL_POLICY, 'binding_verified': False,
                   'apk_sha256': 'MISMATCHED-SNAPSHOT',
                   'note': 'deliberate policy snapshot / APK version mismatch'}
                  if fault == 'policy_version_mismatch' else CONTROL_POLICY)
        baseline = evaluate_data_egress(rules, f_reads, f_flows,
                                        window_override_ms=30000, pairing='window')
        # No batch evidence here: this section measures the condition gate only.
        document = attach({'status': 'fault'}, reads=f_reads, flows=f_flows,
                          findings=baseline, collector_health=collector_health,
                          policy=policy, enable_batch=False)
        conditions = document['observation_conditions']
        missing = {key for q in conditions['questions'] if q['status'] == 'not_applicable'
                   for key in q['missing_conditions']}
        collection_gaps = sorted(missing & COLLECTION_CONDITIONS)
        method_scope_gaps = sorted(missing & METHOD_SCOPE_CONDITIONS)
        expected = EXPECTED_GAPS.get(fault)
        positive = sum(f.get('evidence_kind') in ('read_event', 'read_then_egress')
                       for f in baseline)
        pairs = sum(len(f.get('pairs') or []) for f in baseline)
        kind = ('recall_loss' if fault == 'attach_late' else
                'negative_control' if fault in NEGATIVE_CONTROLS else 'condition_gate')
        gap_identified = expected is None or expected in missing
        rows.append({
            'fault': fault, 'experiment_kind': kind,
            'policy_control': 'synthetic_status_stub_not_real_snapshot',
            'baseline_positive_findings': positive, 'baseline_pairs': pairs,
            'baseline_has_gap_report': False,  # baseline emits no condition/gap field
            'method_question_statuses': {q['question']: q['status']
                                         for q in conditions['questions']},
            'missing_conditions': sorted(missing),
            'collection_gaps': collection_gaps,
            'method_scope_gaps': method_scope_gaps,
            'design_gaps': sorted(missing & DESIGN_GAPS),
            'expected_gap': expected, 'gap_identified': gap_identified,
            # Baseline silently returns no pairs with no explanation; a reader
            # cannot tell a collection fault from a genuine negative result.
            'silent_absence_risk': pairs == 0 and kind == 'condition_gate',
            # Only injected collection faults count as "diagnosed"; a healthy
            # control abstaining on method-scope limits is not a diagnosis.
            'abstention_diagnosed': (kind == 'condition_gate'
                                     and bool(collection_gaps) and gap_identified),
            # Strict: baseline asserts a positive finding while a collection
            # condition is broken. Method-scope and design gaps do NOT count.
            'fault_misread_as_clean': positive > 0 and bool(collection_gaps),
            'answerable_ratio': conditions['rates']['answerable_ratio'],
            'abstain_ratio': conditions['rates']['abstain_ratio'],
        })
    return rows
