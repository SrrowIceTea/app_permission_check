"""Process-scoped event references for every correlation path. 授权测试专用。

``evt_id`` is a **process-local** sequence: two processes can both emit evt_id=1.
Any path that treats it as a global identifier (choosing hits, deciding a
"unique source", de-duplicating) silently merges events from different processes
into one origin. This module is the single contract all vehicle evaluators use.

Legacy rows without a pid/session are never upgraded to a complete reference:
they stay visible as ``reference_incomplete`` instead of being guessed.
"""
from core.collector.identity import uid_of, user_of

MISSING_REFERENCE = 'process_or_session_reference_missing'


def event_ref(row, *, src=None):
    """Build a replayable reference; absent fields stay None, never invented."""
    return {
        'src': src or row.get('src'),
        'evt_id': row.get('evt_id'),
        'pid': row.get('pid'),
        'uid': uid_of(row),
        'user_id': user_of(row),
        'session_id': row.get('session_id'),
        'device_serial': row.get('device_serial'),
    }


def ref_is_complete(ref, *, require_pid=True):
    """A reference is only replayable with src + evt_id + pid + session."""
    return (isinstance(ref.get('src'), str) and bool(ref['src'])
            and type(ref.get('evt_id')) is int and ref['evt_id'] >= 0
            and (not require_pid or type(ref.get('pid')) is int and ref['pid'] > 0)
            and isinstance(ref.get('session_id'), str) and bool(ref['session_id']))


def ref_key(row, *, src=None):
    ref = event_ref(row, src=src)
    return (ref['src'], ref['pid'], ref['evt_id'], ref['session_id'])


def select_by_refs(rows, refs):
    """Select hits by full reference; equal evt_ids from two pids never merge."""
    wanted = {(r.get('src'), r.get('pid'), r.get('evt_id'), r.get('session_id'))
              for r in refs if isinstance(r, dict)}
    return [row for row in rows if isinstance(row, dict) and ref_key(row) in wanted]


def audit_refs(rows, *, src=None):
    """Count reference gaps without changing inputs or producing conclusions."""
    refs = [event_ref(row, src=src) for row in rows]
    return {'events': len(refs),
            'complete': sum(1 for r in refs if ref_is_complete(r)),
            'missing_pid': sum(1 for r in refs if type(r['pid']) is not int or r['pid'] <= 0),
            'missing_session': sum(1 for r in refs if not isinstance(r['session_id'], str)
                                   or not r['session_id']),
            'missing_event_id': sum(1 for r in refs if type(r['evt_id']) is not int),
            'missing_uid': sum(1 for r in refs if r['uid'] is None)}


def pair_refs(read, flow, *, read_src=None, flow_src=None):
    """Fields every ``pairs`` row must carry before ambiguity is computed.

    ``session_id`` is taken from the read; a flow from another session must not
    be paired at all, so the mismatch is exposed instead of being silently
    accepted. flow pid may be absent (host-side proxy stream), read pid may not.
    """
    rr, fr = event_ref(read, src=read_src), event_ref(flow, src=flow_src)
    session = rr['session_id']
    return {
        'read_ref': rr, 'flow_ref': fr,
        'read_pid': rr['pid'], 'flow_pid': fr['pid'],
        'read_src': rr['src'], 'flow_src': fr['src'],
        'read_event_id': rr['evt_id'], 'flow_event_id': fr['evt_id'],
        'session_id': session,
        'session_consistent': fr['session_id'] in (None, session),
        'uid': rr['uid'], 'user_id': rr['user_id'],
        'device_serial': rr['device_serial'] or fr['device_serial'],
        'read_reference_complete': ref_is_complete(rr),
        'flow_reference_complete': ref_is_complete(fr, require_pid=False),
    }
