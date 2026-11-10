"""Gap-driven test selection with an explicit budget. 仅用于授权测试。

``coverage_layers.compute`` reports which layer each property stopped at and a
list of transparent next actions. This module turns that list into an executable
schedule and compares it with two controls under the SAME cost budget:

  fixed_script -- the documented scenario order, no adaptation
  random       -- uniform random pick among remaining actions (seeded)
  gap_driven   -- highest prior evidence-per-cost among remaining actions

HONESTY BOUNDS
* ``PRIOR_EVIDENCE`` is a hand-set prior, NOT a learned estimate. It encodes
  "restoring observability usually unlocks more than re-testing a property that
  already yielded a value". It is not fitted to any data.
* The budget comparison uses ``synthetic_outcomes`` -- a controlled evidence
  model -- so it validates SCHEDULER SEMANTICS, not real-world yield. The report
  always says ``evidence_model=synthetic_control_not_measured``.
* ``record_outcome`` exists so real runs accumulate measured yields; until enough
  records exist ``estimate_yield`` returns ``insufficient`` instead of fitting.
"""
from __future__ import annotations

import json
import random
from pathlib import Path

COST_WEIGHT = {'low': 1, 'medium': 3, 'high': 6}
DEFAULT_BUDGET = 12
STRATEGIES = ('fixed_script', 'random', 'gap_driven')
# Hand-set prior (evidence units per successful execution). Not a fitted value.
PRIOR_EVIDENCE = {
    'request_body_available': 2.0, 'hook_implemented': 1.5, 'value_obtained': 1.5,
    'content_matched_upload': 1.0, 'source_located': 1.0, 'static_reference': 1.0,
}
FIXED_ORDER = ('hook_implemented', 'static_reference', 'value_obtained',
               'content_matched_upload', 'source_located')
MIN_RECORDS_FOR_ESTIMATE = 5


def actions_from_coverage(report):
    """Flatten ``next_actions`` into schedulable actions with stable ids."""
    actions, seen = [], set()
    for row in report.get('next_actions') or []:
        gap = row.get('targets_gap')
        if not gap:
            continue
        target = row.get('property') or '*'
        action_id = f'{target}::{gap}'
        if action_id in seen:
            continue
        seen.add(action_id)
        cost = row.get('cost') if row.get('cost') in COST_WEIGHT else 'medium'
        actions.append({
            'id': action_id, 'property': row.get('property'), 'gap': gap,
            'action': row.get('action'), 'precondition': row.get('precondition'),
            'expected_new_evidence': row.get('expected_new_evidence'),
            'rationale': row.get('rationale'),
            'cost': cost, 'cost_weight': COST_WEIGHT[cost],
            'prior_evidence': PRIOR_EVIDENCE.get(gap, 1.0),
            'value_per_cost': round(PRIOR_EVIDENCE.get(gap, 1.0) / COST_WEIGHT[cost], 4),
        })
    return actions


def _order(actions, strategy, seed):
    if strategy == 'gap_driven':
        return sorted(actions, key=lambda a: (-a['value_per_cost'], a['cost_weight'], a['id']))
    if strategy == 'random':
        shuffled = list(actions)
        random.Random(seed).shuffle(shuffled)
        return shuffled
    if strategy == 'fixed_script':
        rank = {gap: index for index, gap in enumerate(FIXED_ORDER)}
        return sorted(actions, key=lambda a: (rank.get(a['gap'], len(rank)), a['id']))
    raise ValueError('unknown strategy: ' + str(strategy))


def build_plan(report, *, strategy='gap_driven', budget=DEFAULT_BUDGET, seed=0):
    """Greedy schedule under a cost budget. Deterministic for gap_driven/fixed."""
    if strategy not in STRATEGIES:
        raise ValueError('unknown strategy: ' + str(strategy))
    if type(budget) is not int or budget <= 0:
        raise ValueError('budget must be a positive integer (cost units)')
    actions = actions_from_coverage(report)
    selected, skipped, spent = [], [], 0
    for action in _order(actions, strategy, seed):
        if spent + action['cost_weight'] <= budget:
            selected.append({**action, 'order': len(selected) + 1})
            spent += action['cost_weight']
        else:
            skipped.append({'id': action['id'], 'cost_weight': action['cost_weight'],
                            'reason': 'budget_exhausted'})
    return {
        'generated_by': 'vehicle/bench/gap_scheduler.py::build_plan',
        'strategy': strategy, 'budget': budget, 'spent': spent,
        'remaining': budget - spent, 'selected': selected, 'skipped': skipped,
        'predicted_evidence': round(sum(a['prior_evidence'] for a in selected), 3),
        'prior_source': 'hand_set_prior_not_fitted',
        'caveat': '启发式贪心；未估计动作收益，不宣称最优调度。',
    }


def synthetic_outcomes(actions, *, seed=0, model=None):
    """Controlled evidence model for the budget comparison (explicitly synthetic).

    ``model`` maps gap -> (min, max) evidence units. The default encodes a
    deliberately simple structure: restoring observability and obtaining a value
    unlock more than re-locating a source. It is a control, not a measurement.
    """
    model = model or {
        'request_body_available': (2, 3), 'hook_implemented': (1, 2),
        'value_obtained': (1, 2), 'content_matched_upload': (0, 2),
        'source_located': (0, 1), 'static_reference': (0, 1),
    }
    rng = random.Random(seed)
    outcomes = {}
    for action in actions:
        low, high = model.get(action['gap'], (0, 1))
        gained = rng.randint(low, high)
        outcomes[action['id']] = {
            'new_evidence': gained,
            'resolved_questions': 1 if gained > 0 else 0,
            'cost': action['cost_weight'],
        }
    return outcomes


def evaluate_plan(plan, outcomes):
    """Aggregate one schedule's observed effect. Missing outcomes count as zero."""
    evidence = resolved = spent = 0
    first_effective = None
    for action in plan['selected']:
        row = outcomes.get(action['id']) or {'new_evidence': 0, 'resolved_questions': 0,
                                             'cost': action['cost_weight']}
        evidence += row['new_evidence']
        resolved += row['resolved_questions']
        spent += row['cost']
        if first_effective is None and row['new_evidence'] > 0:
            first_effective = action['order']
    return {'new_evidence': evidence, 'resolved_questions': resolved,
            'first_effective_order': first_effective, 'spent': spent,
            'evidence_per_cost': round(evidence / spent, 4) if spent else None,
            'actions': len(plan['selected'])}


MODELS = {
    'prior_aligned': {
        'request_body_available': (2, 3), 'hook_implemented': (1, 2),
        'value_obtained': (1, 2), 'content_matched_upload': (0, 2),
        'source_located': (0, 1), 'static_reference': (0, 1)},
    # Deliberately contradicts the scheduler prior: if gap_driven still wins
    # here, the ranking is not merely the prior reflected back.
    'hook_heavy': {
        'request_body_available': (0, 1), 'hook_implemented': (2, 3),
        'value_obtained': (0, 1), 'content_matched_upload': (0, 1),
        'source_located': (0, 1), 'static_reference': (0, 1)},
    'flat': {key: (0, 1) for key in PRIOR_EVIDENCE},
}


def _run(report, strategy, budget, seeds, model):
    runs = []
    for seed in seeds:
        plan = build_plan(report, strategy=strategy, budget=budget, seed=seed)
        runs.append(evaluate_plan(plan, synthetic_outcomes(plan['selected'], seed=seed,
                                                           model=model)))
    keys = ('new_evidence', 'resolved_questions', 'spent', 'evidence_per_cost')
    mean = {key: round(sum(run[key] or 0 for run in runs) / len(runs), 4) for key in keys}
    firsts = [run['first_effective_order'] for run in runs
              if run['first_effective_order'] is not None]
    return {'strategy': strategy, 'runs': len(runs), **mean,
            'first_effective_order_mean': round(sum(firsts) / len(firsts), 2)
            if firsts else None}


def compare(report, *, budget=DEFAULT_BUDGET, seeds=range(8), model='prior_aligned'):
    """Three strategies under one budget, plus a sensitivity check.

    The main model shares its structure with ``PRIOR_EVIDENCE``, so a gap_driven
    win there is partly self-fulfilling. ``sensitivity`` re-runs the comparison
    under a contradicting model and a flat model; if the winner changes, the
    report says ``ranking_stable=False`` and no strategy may be called better.
    """
    seeds = list(seeds)
    if model not in MODELS:
        raise ValueError('unknown model: ' + str(model))
    rows = [_run(report, strategy, budget, seeds, MODELS[model]) for strategy in STRATEGIES]
    sensitivity = []
    for name, spec in MODELS.items():
        if name == model:
            continue
        alt = [_run(report, strategy, budget, seeds, spec) for strategy in STRATEGIES]
        best = max(alt, key=lambda row: (row['evidence_per_cost'] or 0, row['new_evidence']))
        sensitivity.append({'model': name, 'best_strategy': best['strategy'],
                            'strategies': [{'strategy': row['strategy'],
                                            'evidence_per_cost': row['evidence_per_cost']}
                                           for row in alt]})
    winners = {model, *(row['best_strategy'] for row in sensitivity)}
    return {
        'generated_by': 'vehicle/bench/gap_scheduler.py::compare',
        'budget': budget, 'seeds': len(seeds), 'main_model': model,
        'evidence_model': 'synthetic_control_not_measured',
        'strategies': rows, 'sensitivity': sensitivity,
        'ranking_stable': len(winners) == 1,
        'self_fulfilling_risk': ('主收益模型与调度先验同源；'
                                 + ('三种模型下排序一致，但仍不能当作真实收益证据。'
                                    if len(winners) == 1 else
                                    '换模型后最优策略改变，不得宣称缺口驱动更优。')),
        'caveat': '合成收益模型只验证调度语义；真实收益必须由 record_outcome 累积实测，'
                  '样本不足时不得宣称缺口驱动更优。',
    }


def record_outcome(path, action_id, *, new_evidence, resolved_questions=0, note=None):
    """Append one measured outcome. Append-only; never rewrites history."""
    if type(new_evidence) is not int or new_evidence < 0:
        raise ValueError('new_evidence must be a non-negative int')
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    row = {'action_id': action_id, 'new_evidence': new_evidence,
           'resolved_questions': int(resolved_questions), 'note': note}
    with path.open('a', encoding='utf-8') as handle:
        handle.write(json.dumps(row, ensure_ascii=False) + '\n')
    return row


def estimate_yield(path):
    """Mean measured yield per action; refuses to fit on a tiny sample."""
    path = Path(path)
    if not path.is_file():
        return {'status': 'insufficient', 'records': 0,
                'reason': '没有实测记录；不估计动作收益。'}
    rows = [json.loads(line) for line in path.read_text(encoding='utf-8').splitlines() if line.strip()]
    if len(rows) < MIN_RECORDS_FOR_ESTIMATE:
        return {'status': 'insufficient', 'records': len(rows),
                'reason': f'样本 {len(rows)} < {MIN_RECORDS_FOR_ESTIMATE}；不拟合，避免把噪声当收益。'}
    grouped = {}
    for row in rows:
        grouped.setdefault(row['action_id'], []).append(row)
    return {'status': 'estimated', 'records': len(rows),
            'by_action': {key: {'n': len(values),
                                'mean_new_evidence': round(sum(v['new_evidence'] for v in values) / len(values), 3)}
                          for key, values in sorted(grouped.items())},
            'caveat': '仅本机实测样本的均值，不控制混淆因素，不能直接当作因果收益。'}
