"""Single attachment point for the evidence-method report. 仅用于授权测试。

Wires the three new method outputs into an existing correlation/audit summary
without changing any finding, rule or conclusion level. Kept separate from the
evaluator so the CLI (``correlate.py``), the empty-observation path and the full
pipeline (``audit.py``) all produce the same fields.
"""
from __future__ import annotations

import json
from pathlib import Path

from vehicle.analyze.batch_alignment import report as batch_report
from vehicle.analyze.coverage_layers import compute as compute_layers
from vehicle.analyze.observation_conditions import assess as assess_conditions
from vehicle.analyze.source_candidates import build_candidate_sets


def _read_json(path):
    if not path:
        return None
    file = Path(path)
    if not file.is_file():
        return None
    try:
        return json.loads(file.read_text(encoding='utf-8'))
    except (OSError, ValueError):
        return None  # unreadable input is "not supplied", never a guessed zero


def attach(document, *, reads, flows, findings, capture=None, coverage_chain=None,
           coverage_path=None, static=None, policy=None, scenarios=None,
           enabled_properties=None, evidence_overrides=None, collector_health=None,
           enable_batch=True):
    """Return a new summary dict with method fields attached. No input mutation.

    ``collector_health`` may be supplied by a caller that has already proven
    health (e.g. the preflight-gated empty-observation path). Otherwise the
    file-based probe is used, and a missing record fails closed.
    """
    capture = Path(capture) if capture else None
    health = (collector_health if collector_health is not None else
              (_read_json(capture / 'collector-health.json') if capture else None))
    chain = coverage_chain if coverage_chain is not None else _read_json(coverage_path)
    # Batch evidence is optional so an ablation arm stays a clean comparison;
    # when enabled it can only ADD candidates or expose a conflict.
    batch = batch_report(reads, flows) if enable_batch else {
        'generated_by': 'vehicle/analyze/batch_alignment.py::report',
        'enabled': False, 'aligned_flows': 0, 'aligned': [], 'unaligned': [],
        'note': '本次调用显式关闭批次证据（消融对照）。'}
    candidates = build_candidate_sets(findings,
                                      batch_report=batch if enable_batch else None)
    conditions = assess_conditions(reads, flows, findings, collector_health=health,
                                   policy=policy, candidate_summary=candidates,
                                   evidence_overrides=evidence_overrides)
    layers = compute_layers(reads, flows, findings, coverage_chain=chain,
                            static=static, candidate_summary=candidates,
                            scenarios=scenarios, enabled_properties=enabled_properties,
                            observation_conditions=conditions)
    return {
        **document,
        'observation_conditions': conditions,
        'batch_alignment': batch,
        'source_candidates': candidates,
        'coverage_layers': layers,
        'method_summary': {
            'model': 'observation-condition-gated decisions + ambiguity-aware source sets',
            'decidability': conditions['rates'],
            'ambiguity': {key: candidates[key] for key in
                          ('candidate_sets', 'unique_candidate', 'multiple_candidates',
                           'no_candidate', 'ambiguity_rate', 'content_match_rate')},
            'evidence_layers': {row['layer']: {'status': row['status'],
                                               'count': row.get('count')}
                                for row in layers['layers']},
            'fault_as_clean_signals': conditions['fault_as_clean_signals'],
            'caveat': '新增字段只描述本轮可判定范围与证据缺口，不改变任何 finding 结论。',
        },
    }
