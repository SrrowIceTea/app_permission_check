"""Source-candidate sets with explicit ambiguity. 仅用于授权测试。

Keeps *all* plausible source reads for one outbound observation instead of
picking a winner by time proximity alone. Three claims stay separate and must
never be collapsed into one "correlation successful" label:

* ``content_match``       -- the payload contains content consistent with a read
                             value (possibly the strongest evidence available).
* ``source_located``      -- under current observation, one read is the only
                             plausible source. This is NOT causal proof.
* ``causal_propagation``  -- never asserted here: without taint/flow tracking
                             the value's path through the program is unproven.

Filters are ordered and auditable: every narrowing step records what it kept,
what it removed and on what basis, so a reviewer can reconstruct why a source
was excluded. Nothing is deleted from the evidence trail.
"""
from __future__ import annotations

from dataclasses import dataclass, field

UNIQUE_CANDIDATE = 'unique_candidate'
MULTIPLE_CANDIDATES = 'multiple_candidates'
NO_CANDIDATE = 'no_candidate'
# A property-name / shape hit is not value-level evidence. Even a single
# candidate must never be upgraded to "source located" on that basis.
MARKER_ONLY_CANDIDATE = 'marker_only_candidate'
CANDIDATE_STATES = (UNIQUE_CANDIDATE, MULTIPLE_CANDIDATES, NO_CANDIDATE,
                    MARKER_ONLY_CANDIDATE)

UNIQUE_STATEMENT = ('当前观测下唯一候选读取；未做传播追踪，不构成「该值来自本次读取」'
                    '的因果证明。')
AMBIGUOUS_STATEMENT = ('存在多个合理来源读取；只保留候选集合与全部依据，不指定单一来源。')
MARKER_ONLY_STATEMENT = ('只有属性名/形状命中，没有属性绑定的值级内容匹配；'
                         '即使仅剩一个候选也不得升级为「来源已定位」。')


@dataclass(frozen=True)
class FilterStep:
    name: str
    basis: str
    kept: tuple[str, ...]
    removed: tuple[str, ...]


@dataclass
class CandidateSet:
    """One outbound observation -> ordered, progressively narrowed read sources."""
    target_id: str
    candidates: list = field(default_factory=list)
    steps: list = field(default_factory=list)
    content_match: bool = False
    content_match_basis: str | None = None

    def narrow(self, name, predicate, basis):
        """Keep candidates satisfying predicate; record removals, never drop refs."""
        kept = [c for c in self.candidates if predicate(c)]
        removed = [c['id'] for c in self.candidates if not predicate(c)]
        self.steps.append(FilterStep(name, basis, tuple(c['id'] for c in kept),
                                     tuple(removed)))
        self.candidates = kept
        return self

    def collapse_repeated(self, group_key, justification):
        """Merge nested duplicate observations of ONE invocation.

        Requires an explicit justification (e.g. a proven call-stack grouping).
        Without it, repeated equal values stay independent candidates -- that
        ambiguity is the honest result, not a bug to be smoothed away.
        """
        if not justification:
            return self
        groups = {}
        for candidate in self.candidates:
            groups.setdefault(group_key(candidate), []).append(candidate)
        merged = []
        for members in groups.values():
            first = dict(members[0])
            first['collapsed_refs'] = [m['id'] for m in members[1:]]
            first['collapse_justification'] = justification
            merged.append(first)
        before = tuple(c['id'] for c in self.candidates)
        self.steps.append(FilterStep('collapse_nested_repeats', justification,
                                     tuple(c['id'] for c in merged),
                                     tuple(i for i in before
                                           if i not in {c['id'] for c in merged})))
        self.candidates = merged
        return self

    def resolve(self):
        ids = [c['id'] for c in self.candidates]
        if not ids:
            state, statement = NO_CANDIDATE, '没有满足筛选条件的来源候选；本轮无法关联。'
        elif not self.content_match:
            state, statement = MARKER_ONLY_CANDIDATE, MARKER_ONLY_STATEMENT
        elif len(ids) == 1:
            state, statement = UNIQUE_CANDIDATE, UNIQUE_STATEMENT
        else:
            state, statement = MULTIPLE_CANDIDATES, AMBIGUOUS_STATEMENT
        return {
            'target_id': self.target_id, 'state': state, 'statement': statement,
            'candidate_ids': ids, 'candidates': list(self.candidates),
            'content_match': self.content_match,
            'content_match_basis': self.content_match_basis,
            'source_located': state == UNIQUE_CANDIDATE,
            'causal_propagation': False,
            'causal_propagation_note': '无污点/传播追踪，任何状态下均不得升级为因果证明。',
            'filter_trace': [{'name': s.name, 'basis': s.basis,
                              'kept': list(s.kept), 'removed': list(s.removed)}
                             for s in self.steps],
            'claim_scope': ('property_marker_only' if not self.content_match else
                            'content_match_only' if state != UNIQUE_CANDIDATE else
                            'content_match_plus_unique_candidate'),
        }


def ambiguity_rates(results):
    """Aggregate candidate-set states; always paired with an answerable count."""
    results = list(results)
    total = len(results)
    counts = {state: sum(r['state'] == state for r in results)
              for state in CANDIDATE_STATES}
    return {'candidate_sets': total, **counts,
            'ambiguity_rate': round(counts[MULTIPLE_CANDIDATES] / total, 4) if total else None,
            'marker_only_rate': round(counts[MARKER_ONLY_CANDIDATE] / total, 4) if total else None,
            'unique_candidate_rate': round(counts[UNIQUE_CANDIDATE] / total, 4) if total else None,
            'unattributable_rate': round(counts[NO_CANDIDATE] / total, 4) if total else None,
            'content_match_rate': round(sum(bool(r['content_match']) for r in results) / total, 4)
            if total else None,
            'causal_claims': sum(bool(r['causal_propagation']) for r in results),
            'caveat': '唯一候选不是因果证明；歧义率必须和可判定比例一起报告。'}
