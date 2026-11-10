"""Constrained parameter optimization for vehicle review ordering. 仅用于授权测试。

This is NOT reinforcement learning. There is no sequential decision process, no
state transition and no policy -- it is reward-weighted random search over a
small bounded parameter vector (an evolution strategy). The file in the mobile
line named ``risk_rl.py`` says the same in its own docstring; this module keeps
the honest name so a filename can never be mistaken for a methodological claim.

OBJECTIVE
Maximise recall@K under a FIXED review budget K: "with K human reviews, how many
of the findings an independent expert marked as worth reviewing are surfaced?"
It deliberately does NOT fit a rule-draft ranking. Agreement with a draft only
shows agreement with that draft, not with expert judgement.

GATE
Requires ``vehicle.bench.label_gate.classify_label(...).usable_as_gold``, i.e.
two named human reviewers + named human adjudicator + human_signoff=signed.
Without it the optimiser returns ``status='not_trained'`` and emits no weights.

HOLDOUT
Split by ``family`` (app family / sample family), never by random row: rows from
one app are correlated, so a random split leaks. If only one family is supplied
the holdout is reported as ``not_supplied`` rather than silently reusing train.
"""
from __future__ import annotations

import random

from vehicle.bench.label_gate import classify_label

STATUS_TRAINED = 'trained'
STATUS_NOT_TRAINED = 'not_trained'
METHOD = 'Evolution Strategy (reward-weighted random search)'
PARAMS = {'w_sensitivity': 1.0, 'w_exposure': 1.0,
          'w_plaintext': 0.5, 'w_evidence': 0.5}
BOUNDS = {'w_sensitivity': (0.0, 2.0), 'w_exposure': (0.0, 2.0),
          'w_plaintext': (0.0, 1.0), 'w_evidence': (0.0, 1.0)}
SENSITIVITY = {'INFO_VIN': 1.0, 'PERF_VEHICLE_SPEED': .8, 'PERF_ODOMETER': .75,
               'ENGINE_RPM': .6, 'GEAR_SELECTION': .5, 'CURRENT_GEAR': .5,
               'FUEL_LEVEL': .45, 'EV_BATTERY_LEVEL': .45}
EXPOSURE = {'manifest_permission': .25, 'read_event': .5, 'read_then_egress': 1.0}
ORDER = ('w_exposure', 'w_sensitivity', 'w_evidence', 'w_plaintext')


def score(finding, params):
    """Explainable linear score. Higher = review sooner; never a risk probability."""
    sensitivity = SENSITIVITY.get(finding.get('property'), .5)
    exposure = EXPOSURE.get(finding.get('evidence_kind'), .25)
    pairs = finding.get('pairs') or []
    plaintext = 1.0 if any(pair.get('client_tls') is False for pair in pairs) else 0.0
    evidence = 1.0 if (finding.get('value_match') is True or
                       (finding.get('source_candidate_states') or [None])[0] == 'unique_candidate'
                       ) else 0.0
    return (params['w_sensitivity'] * sensitivity + params['w_exposure'] * exposure
            + params['w_plaintext'] * plaintext + params['w_evidence'] * evidence)


def recall_at_k(case, params, k):
    """Share of ALL review-worthy findings that land inside the top-k.

    Review P0-7: the earlier version divided by ``min(k, len(worthy))``, which is
    precision@k, not recall@k. With 10 worthy items and k=2 a perfect top-2
    reported 1.0, while the standard recall@2 is 0.2.
    """
    findings = case.get('findings') or []
    worthy = set(case.get('review_worthy') or [])
    if not findings or not worthy:
        return None
    ranked = sorted(findings, key=lambda row: (-score(row, params), str(row.get('finding_id'))))
    top = {row.get('finding_id') for row in ranked[:k]}
    return len(top & worthy) / len(worthy)


def precision_at_k(case, params, k):
    """Share of the top-k review slots that were worth reviewing.

    Kept under its correct name so the two quantities are never conflated again.
    """
    findings = case.get('findings') or []
    worthy = set(case.get('review_worthy') or [])
    if not findings or not worthy:
        return None
    ranked = sorted(findings, key=lambda row: (-score(row, params), str(row.get('finding_id'))))
    top = {row.get('finding_id') for row in ranked[:k]}
    return len(top & worthy) / min(k, len(worthy))


def reward(cases, params, k):
    values = [value for case in cases
              for value in (recall_at_k(case, params, k),) if value is not None]
    return sum(values) / len(values) if values else 0.0


def _clamp(params):
    """Bounded and ordered: exposure weight never below evidence/plaintext, all >= 0."""
    clamped = {key: min(max(value, BOUNDS[key][0]), BOUNDS[key][1])
               for key, value in params.items()}
    clamped['w_exposure'] = max(clamped['w_exposure'], clamped['w_evidence'],
                                clamped['w_plaintext'] * 0.5)
    return {key: clamped[key] for key in ORDER}


def _perturb(params, sigma, rng):
    out = {}
    for key, (low, high) in BOUNDS.items():
        out[key] = params[key] + rng.gauss(0.0, sigma * (high - low))
    return _clamp(out)


def optimize(cases, labels, *, k=5, steps=120, popsize=12, sigma=0.25, seed=0,
             holdout_cases=None):
    """Fit bounded weights on human-signed labels. Returns not_trained otherwise."""
    tier = classify_label(labels)
    if not tier['usable_as_gold']:
        return {
            'status': STATUS_NOT_TRAINED, 'method': METHOD,
            'label_tier': tier,
            'reason': '缺少人类签核的独立标注；训练会在 agent 初评上循环论证。',
            'required_next_step': tier['required_next_step'],
            'params': None, 'train': None, 'holdout': None,
        }
    if type(k) is not int or k <= 0:
        raise ValueError('k must be a positive int')
    cases = [case for case in cases if case.get('findings') and case.get('review_worthy')]
    if not cases:
        return {'status': STATUS_NOT_TRAINED, 'method': METHOD, 'label_tier': tier,
                'reason': '没有同时具备 findings 与 review_worthy 的样本。',
                'required_next_step': None, 'params': None, 'train': None, 'holdout': None}
    rng = random.Random(seed)
    best, best_reward = _clamp(dict(PARAMS)), reward(cases, PARAMS, k)
    baseline = best_reward
    trace = [{'step': 0, 'reward': round(best_reward, 4), 'params': dict(best)}]
    for step in range(1, steps + 1):
        population = [_perturb(best, sigma, rng) for _ in range(popsize)]
        scored = [(candidate, reward(cases, candidate, k)) for candidate in population]
        # Reward-weighted average (the ES empirical gradient).
        total = sum(max(value, 0.0) for _, value in scored) or 1.0
        mean = {key: sum(candidate[key] * max(value, 0.0) for candidate, value in scored) / total
                for key in PARAMS}
        candidate = _clamp(mean)
        candidate_reward = reward(cases, candidate, k)
        if candidate_reward >= best_reward:
            best, best_reward = candidate, candidate_reward
        trace.append({'step': step, 'reward': round(best_reward, 4), 'params': dict(best)})
    result = {
        'status': STATUS_TRAINED, 'method': METHOD,
        'not_reinforcement_learning_reason': '无序列决策/状态转移；这是有界参数的随机搜索。',
        'label_tier': tier, 'objective': 'recall_at_k', 'k': k,
        'params': {key: round(best[key], 4) for key in ORDER},
        'baseline_params': dict(PARAMS),
        'train': {'cases': len(cases), 'recall_at_k': round(best_reward, 4),
                  'baseline_recall_at_k': round(baseline, 4),
                  'gain': round(best_reward - baseline, 4)},
        'holdout': _holdout(cases, holdout_cases, best, k),
        'trace_tail': trace[-3:],
        'caveats': [
            '目标是固定复核预算下的 recall@k，不是风险概率或违规判定。',
            '训练与留出必须按 App 家族切分；同一 App 的多行相关，随机切分会泄漏。',
            '即使训练完成，增益只在人类签核标注覆盖的样本范围内成立，不外推到第三方。',
            '参数为工程排序权重，不可解释为法律或统计意义上的风险系数。',
        ],
    }
    return result


def _holdout(cases, holdout_cases, params, k):
    if not holdout_cases:
        families = {case.get('family') for case in cases if case.get('family')}
        return {'status': 'not_supplied', 'cases': 0,
                'reason': ('只有一个样本家族，无法做家族留出' if len(families) <= 1
                           else '未提供留出集；不得把训练集指标当作泛化证据')}
    values = [value for case in holdout_cases
              for value in (recall_at_k(case, params, k),) if value is not None]
    if not values:
        return {'status': 'not_supplied', 'cases': len(holdout_cases),
                'reason': '留出集没有可评分的样本'}
    test_families = {case.get('family') for case in holdout_cases if case.get('family')}
    train_families = {case.get('family') for case in cases if case.get('family')}
    return {'status': 'measured', 'cases': len(values),
            'recall_at_k': round(sum(values) / len(values), 4),
            'families_disjoint': bool(test_families and train_families
                                      and not (test_families & train_families)),
            'caveat': '留出集指标只在人类签核覆盖范围内成立。'}


def leave_one_family_out(cases, labels, *, k=5, **options):
    """Honest alternative when a separate holdout family is unavailable."""
    families = sorted({case.get('family') for case in cases if case.get('family')})
    if len(families) < 2:
        return {'status': 'not_supplied', 'families': families,
                'reason': '至少需要两个样本家族才能做留一族评估。'}
    rows = []
    for family in families:
        train = [case for case in cases if case.get('family') != family]
        test = [case for case in cases if case.get('family') == family]
        fitted = optimize(train, labels, k=k, holdout_cases=test, **options)
        rows.append({'held_out_family': family,
                     'status': fitted['status'],
                     'holdout': fitted.get('holdout')})
    measured = [row['holdout']['recall_at_k'] for row in rows
                if row['holdout'] and row['holdout'].get('status') == 'measured']
    return {'status': 'measured' if measured else 'not_supplied',
            'families': families, 'folds': rows,
            'mean_recall_at_k': round(sum(measured) / len(measured), 4) if measured else None}
