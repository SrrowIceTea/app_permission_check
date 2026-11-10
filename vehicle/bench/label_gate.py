"""Label-tier gate: which independent label sets may score method effectiveness.

仅用于授权测试。 The blind-review chain already exists in this repository and is
NOT re-implemented here:

  vehicle.bench.blind_round     prepare / compare   two independent reviewers
  vehicle.bench.blind_signoff   finalize            adjudication + signoff
  vehicle.bench.labels          adjudicated_labels  contract + evidence binding

Tiers (monotone):
  initial_review       single agent/historical review; guides engineering only.
  subagent_signed      two isolated subagents + adjudicator, possibly the SAME
                       model. Independent contexts but shared failure modes, so
                       it still cannot score method effectiveness.
  cross_model_signed   two isolated subagents from DIFFERENT model families +
                       a third family as adjudicator. Accepted as gold because
                       agreement across families argues against a single model's
                       quirk -- the exact failure seen on 2026-11-10, when one
                       boundary item flipped insufficient -> absent between two
                       rounds of the same model.
  human_signed         two named human reviewers + human adjudicator.
  invalid              origin/kind/signoff/model-family contradict each other.

`gold_kind` distinguishes the two accepted tiers. A cross-model label must never
be reported as "expert verified": model identity is self-declared by the review
record, and no human is in the loop. `review_limits` carries that wording.
"""
from __future__ import annotations

from datetime import datetime

from vehicle.bench.review_policy import AGENT_MODES, limits, model_family, validate_agents
from vehicle.pipeline.contracts import AuditError

TIER_INITIAL = 'initial_review'
TIER_SUBAGENT = 'subagent_signed'
TIER_CROSS_MODEL = 'cross_model_signed'
TIER_HUMAN = 'human_signed'
TIER_INVALID = 'invalid'
TIERS = (TIER_INITIAL, TIER_SUBAGENT, TIER_CROSS_MODEL, TIER_HUMAN, TIER_INVALID)
GOLD_KINDS = {TIER_CROSS_MODEL: 'cross_model_subagent', TIER_HUMAN: 'human'}

CROSS_MODEL_STEPS = (
    '1) python -m vehicle.bench.blind_round prepare --review-mode cross_model '
    '--out output/cross-model-package-<date>',
    '2) 用两个不同模型家族各跑一位复核人，独立填写 reviewer-A.zip / reviewer-B.zip 内的 '
    'review.json；每份须含 agent_id、context_mode=fresh、review_session_id、model_family、model_id',
    '3) python -m vehicle.bench.blind_round compare --organizer <organizer-only> '
    '--review-a <A.json> --review-b <B.json> --out output/cross-model-compare-<date>',
    '4) 由第三个模型家族担任仲裁人，填写 signoff-request.json（负控标记 + 分歧裁定）后执行 '
    'python -m vehicle.bench.blind_signoff --organizer <...> --review-a <...> --review-b <...> '
    '--signoff <...> --out output/cross-model-signed-<date>',
)

HUMAN_STEPS = (
    '1) python -m vehicle.bench.blind_round prepare --review-mode human --out output/human-label-package-<date>',
    '2) 两位人类专家各自独立填写 reviewer-A.zip / reviewer-B.zip 内的 review.json（不得互看）',
    '3) python -m vehicle.bench.blind_round compare --organizer <organizer-only> '
    '--review-a <A.json> --review-b <B.json> --out output/human-compare-<date>',
    '4) 组织者裁定分歧后，由人类签核人填写 signoff-request.json 并执行 '
    'python -m vehicle.bench.blind_signoff --organizer <...> --review-a <...> '
    '--review-b <...> --signoff <signed.json> --out output/human-signed-<date>',
)


def _named(record):
    """A usable reviewer record: named person/agent and a timezone-aware time."""
    if not isinstance(record, dict):
        return False
    reviewer = record.get('reviewer')
    if not isinstance(reviewer, str) or not reviewer.strip():
        return False
    try:
        stamp = datetime.fromisoformat(record['reviewed_at'])
    except (KeyError, ValueError, TypeError):
        return False
    return stamp.tzinfo is not None


def _independent(label):
    reviews = label.get('reviews')
    adjudication = label.get('adjudication')
    if not (isinstance(reviews, list) and len(reviews) == 2
            and all(_named(review) for review in reviews) and _named(adjudication)):
        return False
    # Review P0-6: two "independent" reviewers who are the same name, or an
    # adjudicator who is also one of them, are not an independent review. The
    # structural check alone accepted a single person filling all three slots.
    names = [review['reviewer'].strip().casefold() for review in reviews]
    names.append(adjudication['reviewer'].strip().casefold())
    return len(set(names)) == 3


def _people_kinds(label):
    rows = [*(label.get('reviews') or []), label.get('adjudication') or {}]
    return {row.get('reviewer_kind') for row in rows if isinstance(row, dict)
            and row.get('reviewer_kind') is not None}


def _model_families(label):
    rows = [*(label.get('reviews') or []), label.get('adjudication') or {}]
    return [model_family(row) for row in rows if isinstance(row, dict)]


def _result(tier, label, reasons):
    gold_kind = GOLD_KINDS.get(tier)
    mode = (label or {}).get('review_mode') if isinstance(label, dict) else None
    return {
        'tier': tier, 'usable_as_gold': gold_kind is not None, 'gold_kind': gold_kind,
        'independent_review': _independent(label) if isinstance(label, dict) else False,
        'signed': isinstance(label, dict) and ('signed' in (
            label.get('human_signoff'), label.get('subagent_signoff'))),
        'origin': (label or {}).get('origin') if isinstance(label, dict) else None,
        'review_mode': mode,
        'review_limits': limits(mode) if mode in AGENT_MODES else [],
        'human_signoff': (label or {}).get('human_signoff') if isinstance(label, dict) else None,
        'subagent_signoff': (label or {}).get('subagent_signoff') if isinstance(label, dict) else None,
        'reasons': reasons,
        'required_next_step': None if gold_kind else list(CROSS_MODEL_STEPS),
        'stronger_option': None if tier == TIER_HUMAN else list(HUMAN_STEPS),
    }


def classify_label(label):
    """Classify one label document. Pure function; never mutates the input."""
    if not isinstance(label, dict):
        return _result(TIER_INVALID, None, ['标签不是 JSON 对象'])
    origin = label.get('origin')
    kinds = _people_kinds(label)
    human_signoff = label.get('human_signoff')
    subagent_signoff = label.get('subagent_signoff')
    status = label.get('signoff_status', 'signed')

    # A historical single-agent review is a legitimate INITIAL tier, not a
    # malformed label. Only an origin that CLAIMS a signed review must carry the
    # full two-reviewer + adjudicator contract.
    if origin in (None, 'agent_review', 'owned_fixture'):
        return _result(TIER_INITIAL, label, [
            f'origin={origin!r} 是初评/历史标签；只可指导工程，不能评估方法有效性'])
    if not _independent(label):
        return _result(TIER_INVALID, label,
                       ['声称独立/签核复核，但缺少两位具名标注人与具名仲裁人（时间需含时区）'])
    if origin == 'subagent_review':
        mode = label.get('review_mode') or 'subagent'
        problems = []
        if mode not in AGENT_MODES:
            problems.append(f'origin=subagent_review 但 review_mode={mode!r} 不是 subagent/cross_model')
        if kinds - {'subagent'}:
            problems.append('subagent 标签混入了非 subagent 复核记录')
        if subagent_signoff != 'signed' or status != 'signed':
            problems.append('subagent 签核未完成')
        if human_signoff not in (None, 'not_applicable'):
            problems.append('subagent 标签不得声称人类签核')
        families = _model_families(label)
        if mode == 'cross_model':
            # Reuse the single provenance authority rather than re-deriving the
            # rule here; two copies of "what counts as distinct" is exactly the
            # divergence that produced the earlier state-mismatch defects.
            people = [*(label.get('reviews') or []), label.get('adjudication') or {}]
            try:
                validate_agents(people, require_distinct_models=True)
            except ValueError as exc:
                problems.append('cross_model 身份/模型家族不合规：' + str(exc))
        if problems:
            return _result(TIER_INVALID, label, problems)
        if mode == 'cross_model':
            return _result(TIER_CROSS_MODEL, label, [
                '两位不同模型家族的隔离 subagent + 第三家族仲裁已签核（'
                + ', '.join(families) + '）；无人工介入，模型身份为自述'])
        return _result(TIER_SUBAGENT, label, [
            '两位隔离 subagent 已签核，但可能来自同一模型；'
            '共享错误未被排除，不能评估方法有效性'])
    if origin != 'independent_review':
        return _result(TIER_INITIAL, label,
                       [f'origin={origin!r} 是初评/历史标签，只可指导工程，不能评估方法有效性'])
    mode = label.get('review_mode') or 'human'
    problems = []
    if mode != 'human':
        problems.append(f'origin=independent_review 但 review_mode={mode!r} 不是 human')
    if kinds - {'human'}:
        problems.append('人工标签混入了 subagent/ai 复核记录')
    if human_signoff != 'signed' or status != 'signed':
        problems.append('human_signoff 不是 signed（人类签核尚未完成）')
    if subagent_signoff not in (None, 'not_applicable'):
        problems.append('人工标签不得声称 subagent 签核')
    if problems:
        return _result(TIER_INITIAL, label, problems)
    return _result(TIER_HUMAN, label, ['两位具名人类标注 + 具名人类仲裁 + 人类签核'])


def require_gold(label, purpose):
    """Raise unless the label reached an accepted signoff tier."""
    report = classify_label(label)
    if not report['usable_as_gold']:
        raise AuditError(
            'label_not_gold',
            f'{purpose} 需要已签核的独立标注；当前为 {report["tier"]}：'
            + '；'.join(report['reasons']),
            '完成跨模型双盲签核（见 required_next_step）；'
            '不得把同模型 subagent 结果或 agent 初评当作金标准。')
    return report


def summarize_file(payload, name=None):
    """Accept a single label or ``{'samples': [...]}`` and classify every sample."""
    samples = payload.get('samples') if isinstance(payload, dict) else None
    rows = samples if isinstance(samples, list) else [payload]
    return {'name': name, 'labels': [classify_label(row) for row in rows],
            'any_gold': any(classify_label(row)['usable_as_gold'] for row in rows),
            'all_gold': all(classify_label(row)['usable_as_gold'] for row in rows) if rows else False}
