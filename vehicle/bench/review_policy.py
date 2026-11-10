"""Review provenance: human, same-model subagent and cross-model subagent signoff.

仅用于授权测试。The three modes are distinguishable and must never be conflated:

  human        two named human reviewers + a named human adjudicator.
  subagent     two isolated subagents + an adjudicator; MAY be the same model.
  cross_model  two isolated subagents from DIFFERENT model families + a third
               family as adjudicator.

`cross_model` exists because `subagent` alone does not defend against a shared
model error: on 2026-11-10 the same model answered one boundary item
`insufficient` in round 1 and `absent` in round 2. Agreement across families is
evidence against a single model's quirk, but it is still not human review, and
`model_family` is self-declared by the reviewer record. Both limits travel with
the label so downstream reports cannot drop them.
"""
from uuid import UUID

DEFAULT_REVIEW_MODE = 'subagent'
REVIEW_MODES = ('human', 'subagent', 'cross_model')
# Modes whose reviewers are agents rather than people. Membership decides which
# *_signoff field must be 'signed' and which reviewer_kind is expected.
AGENT_MODES = ('subagent', 'cross_model')
AGENT_FIELDS = ('agent_id', 'context_mode', 'review_session_id')
MODEL_FIELDS = ('model_family', 'model_id')
SUBAGENT_LIMITS = ['shared_model_errors_possible', 'context_isolation_is_procedural']
CROSS_MODEL_LIMITS = ['no_human_in_the_loop', 'model_identity_is_self_declared',
                      'families_can_share_upstream_weights']


def reviewer_kind(mode):
    """The reviewer_kind a mode requires. Cross-model reviewers are still subagents."""
    if mode not in REVIEW_MODES:
        raise ValueError('unknown review mode')
    return 'human' if mode == 'human' else 'subagent'


def limits(mode):
    """Limits that must be repeated verbatim by anything consuming this label."""
    if mode == 'cross_model':
        return list(CROSS_MODEL_LIMITS)
    if mode == 'subagent':
        return list(SUBAGENT_LIMITS)
    return []


def model_family(record):
    value = (record or {}).get('model_family')
    return value.strip().casefold() if isinstance(value, str) and value.strip() else None


def identity(record):
    keys = ('reviewer', 'reviewer_kind', 'reviewed_at', *AGENT_FIELDS, *MODEL_FIELDS)
    return {key: record[key] for key in keys if key in record}


def validate_agents(records, require_distinct_models=False):
    """Check declared provenance; this is not an attestation of tool execution."""
    agents, sessions = [], []
    for record in records:
        agent = record.get('agent_id')
        if (record.get('reviewer_kind') != 'subagent' or record.get('context_mode') != 'fresh'
                or not isinstance(agent, str) or not agent.strip()):
            raise ValueError('subagent review requires agent_id and a fresh context')
        try:
            session = str(UUID(record['review_session_id']))
        except (KeyError, ValueError, TypeError, AttributeError) as exc:
            raise ValueError('subagent review requires a UUID review_session_id') from exc
        agents.append(agent.strip().casefold())
        sessions.append(session)
    if len(set(agents)) != len(agents) or len(set(sessions)) != len(sessions):
        raise ValueError('subagent reviewers need distinct agent identities and review sessions')
    if require_distinct_models:
        families = [model_family(record) for record in records]
        if any(name is None for name in families):
            raise ValueError('cross-model review requires a declared model_family on every record')
        if len(set(families)) != len(families):
            raise ValueError('cross-model review requires a different model family per record')


def comparison_mode(plan, reviews):
    mode = plan.get('review_mode')
    if mode is None:
        mode = 'subagent' if all(row.get('reviewer_kind') == 'subagent' for row in reviews) else 'human'
    if mode not in REVIEW_MODES:
        raise ValueError('unknown review mode')
    kinds = {row.get('reviewer_kind') for row in reviews}
    if mode == 'human':
        # A subagent answer cannot masquerade as a human one. Legacy `ai`
        # initial reviews are still allowed through: they produce an
        # origin=agent_review comparison with no signoff form, which is how the
        # repository has always represented a single-agent first pass.
        if 'subagent' in kinds:
            raise ValueError('subagent answers cannot enter a human review round')
        return mode
    if 'human' in kinds:
        raise ValueError('human answers cannot enter a subagent review round')
    if kinds - {'subagent'}:
        raise ValueError('agent review requires reviewer_kind=subagent')
    validate_agents(reviews, require_distinct_models=(mode == 'cross_model'))
    return mode


def signoff_fields(mode, status):
    if mode not in REVIEW_MODES:
        raise ValueError('unknown review mode')
    agent = mode in AGENT_MODES
    return {'review_mode': mode, 'signoff_status': status,
            'human_signoff': 'not_applicable' if agent else status,
            'subagent_signoff': status if agent else 'not_applicable'}


def label_mode(label):
    origin = label.get('origin')
    expected = ('subagent' if origin == 'subagent_review'
                else 'human' if origin == 'independent_review' else None)
    if expected is None:
        raise ValueError('unsupported label origin')
    mode = label.get('review_mode') or expected
    if mode not in REVIEW_MODES:
        raise ValueError('unknown review mode')
    if (mode == 'human') != (expected == 'human'):
        raise ValueError('label origin and review mode disagree')
    kind = reviewer_kind(mode)
    if label.get(kind + '_signoff') != 'signed':
        raise ValueError('label is not signed by its declared reviewer kind')
    if label.get('signoff_status', 'signed') != 'signed':
        raise ValueError('label signoff status is inconsistent')
    if kind == 'subagent' and label.get('human_signoff') != 'not_applicable':
        raise ValueError('subagent labels cannot claim human signoff')
    if kind == 'human' and label.get('subagent_signoff') not in (None, 'not_applicable'):
        raise ValueError('human labels cannot claim subagent signoff')
    if mode in AGENT_MODES:
        people = [*(label.get('reviews') or []), label.get('adjudication') or {}]
        validate_agents(people, require_distinct_models=(mode == 'cross_model'))
    return mode
