"""Expose multiple read candidates; value equality never proves unique origin."""
from collections import defaultdict

from vehicle.analyze.event_ref import MISSING_REFERENCE, ref_is_complete


def _flow_key(pair):
    return (pair.get('flow_src', 'proxy'), pair['flow_event_id'], pair.get('uid'),
            pair.get('flow_pid'), pair.get('session_id'))


def _broad_key(pair):
    """A flow must not be split into several 'unique' groups by flow_pid.

    The same flow_event_id carrying two different flow_pid values is not two
    flows. Without this coarse grouping an attacker (or a mixed proxy/native
    record) can make each group look like exactly one source.
    """
    return (pair.get('flow_src', 'proxy'), pair['flow_event_id'],
            pair.get('uid'), pair.get('session_id'))


def _read_key(pair):
    return (pair.get('read_src', 'vhal'), pair['read_event_id'],
            pair.get('read_pid'), pair.get('session_id'))


def _complete(pair):
    read = {'src': pair.get('read_src', 'vhal'), 'evt_id': pair.get('read_event_id'),
            'pid': pair.get('read_pid'), 'session_id': pair.get('session_id')}
    flow = {'src': pair.get('flow_src', 'proxy'), 'evt_id': pair.get('flow_event_id'),
            'pid': pair.get('flow_pid'), 'session_id': pair.get('session_id')}
    # Structured references are checked independently instead of trusting a
    # flattened session_id copied from the read side.
    rr, fr = pair.get('read_ref'), pair.get('flow_ref')
    if isinstance(rr, dict) and isinstance(fr, dict):
        if rr.get('session_id') is None or rr.get('session_id') != fr.get('session_id'):
            return False
    # Host-side proxy flows have no device pid; that is fine, but the *read*
    # side must be process-scoped or "unique source" is not a defensible claim.
    return (ref_is_complete(read) and ref_is_complete(flow, require_pid=False)
            and pair.get('session_consistent') is not False
            and pair.get('read_reference_complete') is not False)


def annotate_candidates(pairs):
    """Called per property/data type. Does not drop or invent candidate pairs.

    ``evt_id`` is process-local. Both grouping keys therefore include pid and
    session, so two processes emitting the same evt_id stay two distinct origins.
    A pair whose read reference lacks pid/session is explicitly marked
    ``reference_incomplete`` and can never be reported as a unique source
    (2026-11-11 P0: the general evaluator used to emit exactly such pairs).
    Ambiguity is the MAXIMUM of the fine (flow_pid-namespaced) and broad
    (flow-level) candidate counts, so a pid mismatch can never reduce it.
    """
    candidates, broad = defaultdict(set), defaultdict(set)
    for pair in pairs:
        ref = _read_key(pair)
        candidates[_flow_key(pair)].add(ref)
        broad[_broad_key(pair)].add(ref)
    for pair in pairs:
        count = max(len(candidates[_flow_key(pair)]), len(broad[_broad_key(pair)]))
        complete = _complete(pair)
        pair['matching_read_candidates_for_flow'] = count
        pair['source_read_unique'] = bool(complete and count == 1)
        pair['reference_incomplete'] = not complete
        if not complete:
            pair['reference_gap'] = MISSING_REFERENCE
        pair.setdefault('origin_proven', False)
    return sum(len(rows) > 1 for rows in candidates.values())
