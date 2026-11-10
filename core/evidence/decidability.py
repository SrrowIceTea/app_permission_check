"""Observation-condition-gated evidence decisions. 仅用于授权测试。

A question may be answered only when its necessary observation conditions hold.
A missing condition makes the question NOT APPLICABLE to this run -- that is a
statement about our observation, never a negative answer about the app.

This is the platform-neutral contract. Vehicle/mobile supply their own question
sets and condition probes; neither may turn ``not_applicable`` into "did not
happen", "no violation" or "passed".

Three statuses (there is deliberately no ``false`` / ``clean`` status):

* ``decidable``            -- all conditions hold and evidence exists.
* ``decidable_no_evidence``-- all conditions hold, nothing matched in this run.
                              Only then is "not observed" a legitimate answer.
* ``not_applicable``       -- at least one necessary condition is missing; the
                              output lists exactly what is needed to recover.
"""
from __future__ import annotations

from dataclasses import dataclass, field

DECIDABLE = 'decidable'
DECIDABLE_NO_EVIDENCE = 'decidable_no_evidence'
NOT_APPLICABLE = 'not_applicable'
STATUSES = (DECIDABLE, DECIDABLE_NO_EVIDENCE, NOT_APPLICABLE)

# Text fragments that must never appear as a verdict when a condition is missing.
FORBIDDEN_NEGATIVE_WORDS = ('未发生', '没有该行为', '无泄露', '未传输', '未采集', '合规', '通过')


@dataclass(frozen=True)
class Condition:
    """One observable precondition. ``detail`` explains a failed probe."""
    key: str
    description: str
    satisfied: bool = False
    detail: str | None = None


@dataclass(frozen=True)
class Decision:
    question: str
    status: str
    satisfied: tuple[str, ...] = ()
    missing: tuple[str, ...] = ()
    missing_reasons: dict = field(default_factory=dict)
    statement: str = ''

    def as_dict(self):
        return {'question': self.question, 'status': self.status,
                'satisfied_conditions': list(self.satisfied),
                'missing_conditions': list(self.missing),
                'missing_reasons': dict(self.missing_reasons),
                'statement': self.statement}


def condition(key, description, satisfied, detail=None):
    """Build a Condition; coerce probe results to a strict bool."""
    return Condition(key, description, satisfied is True,
                     None if satisfied is True else (detail or '未满足'))


def evaluate(question, required, conditions, evidence_present):
    """Gate one question on its necessary condition set P_q.

    ``required`` is an ordered tuple of condition keys. Unknown keys are treated
    as unsatisfied (fail closed) rather than silently ignored -- a typo in a
    question definition must not widen what the system claims to be able to say.
    """
    if not required:
        raise ValueError('a question needs at least one necessary condition')
    if not isinstance(evidence_present, bool):
        raise ValueError('evidence_present must be an explicit bool')
    by_key = {c.key: c for c in conditions}
    satisfied, missing, reasons = [], [], {}
    for key in required:
        probe = by_key.get(key)
        if probe is not None and probe.satisfied:
            satisfied.append(key)
        else:
            missing.append(key)
            reasons[key] = (probe.detail if probe is not None and probe.detail
                            else '未登记该条件的探测结果')
    if missing:
        statement = ('本轮不可判定（不是阴性结论）：缺少 ' + '、'.join(missing)
                     + '。补齐这些观测条件后才允许回答该问题。')
        return Decision(question, NOT_APPLICABLE, tuple(satisfied),
                        tuple(missing), reasons, statement)
    if evidence_present:
        return Decision(question, DECIDABLE, tuple(satisfied), (),
                        {}, '观测条件齐全且有对应证据；结论强度仍受证据类型限制。')
    return Decision(question, DECIDABLE_NO_EVIDENCE, tuple(satisfied), (),
                    {}, '观测条件齐全，本轮未观测到对应证据；仅可表述为「本轮未观测到」。')


def evaluate_all(questions, conditions, evidence):
    """Evaluate a question set. ``evidence`` maps question -> bool.

    A question absent from ``evidence`` is fail-closed as not_applicable via
    an extra synthetic condition, so an unprobed question never scores as
    decidable.
    """
    decisions = []
    for question, required in questions.items():
        present = evidence.get(question)
        local = list(conditions)
        required = tuple(required)
        if present is None:
            # The synthetic condition must also join P_q, otherwise an
            # unprobed question would still be scored as answerable.
            local.append(condition('_evidence_probe', '该问题本轮有证据探测结果',
                                   False, '求值器未提供此问题的证据探测'))
            required += ('_evidence_probe',)
            present = False
        decisions.append(evaluate(question, required, local, present))
    return decisions


def decidability_rates(decisions):
    """Report how much the run could actually answer.

    Guards against a system getting a low error rate by abstaining on
    everything: decidable_ratio and abstain_ratio are always reported together
    with the absolute counts.
    """
    decisions = list(decisions)
    total = len(decisions)
    answered = sum(d.status in (DECIDABLE, DECIDABLE_NO_EVIDENCE) for d in decisions)
    with_evidence = sum(d.status == DECIDABLE for d in decisions)
    abstained = sum(d.status == NOT_APPLICABLE for d in decisions)
    return {'questions_total': total, 'answerable': answered,
            'answerable_ratio': round(answered / total, 4) if total else None,
            'decidable': with_evidence,
            'decidable_ratio': round(with_evidence / total, 4) if total else None,
            'abstained': abstained,
            'abstain_ratio': round(abstained / total, 4) if total else None,
            'absent_observations': sum(d.status == DECIDABLE_NO_EVIDENCE for d in decisions),
            'caveat': '不可判定不是阴性结论；低错误率若伴随高弃判率，不构成方法有效性证据。'}


def assert_no_negative_verdict(decision):
    """Fail loudly if a consumer tried to phrase abstention as a clean result."""
    if decision.status == NOT_APPLICABLE:
        for word in FORBIDDEN_NEGATIVE_WORDS:
            if word in decision.statement:
                raise ValueError('not_applicable must not be phrased as a negative verdict: ' + word)
    return decision
