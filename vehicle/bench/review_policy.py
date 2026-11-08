"""Review provenance: subagent signoff and human signoff stay separate."""
from uuid import UUID

DEFAULT_REVIEW_MODE = 'subagent'
REVIEW_MODES = ('human', 'subagent')
AGENT_FIELDS = ('agent_id', 'context_mode', 'review_session_id')
SUBAGENT_LIMITS = ['shared_model_errors_possible', 'context_isolation_is_procedural']


def identity(record):
    return {key: record[key] for key in ('reviewer', 'reviewer_kind', 'reviewed_at', *AGENT_FIELDS)
            if key in record}


def validate_agents(records):
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


def comparison_mode(plan, reviews):
    mode = plan.get('review_mode')
    if mode is None:
        mode = 'subagent' if all(row.get('reviewer_kind') == 'subagent' for row in reviews) else 'human'
    if mode not in REVIEW_MODES:
        raise ValueError('unknown review mode')
    if any(row.get('reviewer_kind') == 'subagent' for row in reviews):
        if mode != 'subagent':
            raise ValueError('subagent answers cannot enter a human review round')
        validate_agents(reviews)
    elif mode == 'subagent' and any(row.get('reviewer_kind') == 'human' for row in reviews):
        raise ValueError('human answers cannot enter a subagent review round')
    return mode


def signoff_fields(mode, status):
    return {'review_mode': mode, 'signoff_status': status,
            'human_signoff': status if mode == 'human' else 'not_applicable',
            'subagent_signoff': status if mode == 'subagent' else 'not_applicable'}


def label_mode(label):
    mode = 'subagent' if label.get('origin') == 'subagent_review' else 'human'
    if label.get('review_mode', mode) != mode:
        raise ValueError('label origin and review mode disagree')
    if label.get(mode + '_signoff') != 'signed':
        raise ValueError('label is not signed by its declared reviewer kind')
    if label.get('signoff_status', 'signed') != 'signed':
        raise ValueError('label signoff status is inconsistent')
    if mode == 'subagent' and label.get('human_signoff') != 'not_applicable':
        raise ValueError('subagent labels cannot claim human signoff')
    if mode == 'human' and label.get('subagent_signoff') not in (None, 'not_applicable'):
        raise ValueError('human labels cannot claim subagent signoff')
    return mode
