"""Capture gaps are facts independent of the versioned HA pairing contract."""
from collections import Counter

from vehicle.privacy.ha_socket_evidence import _target_events


def add_capture_gaps(summary, events, session, user):
    reasons = {}
    for src, event, key in (('ha_transport', 'HA_BODY_GAP', 'webhook_capture_gaps'),
                            ('ha_socket', 'HA_WS_GAP', 'websocket_capture_gaps')):
        gaps = [{'src': src, 'event_id': r['evt_id'], 'reason': r.get('reason', 'unknown')}
                for r in _target_events(events, session, user, src) if r.get('ev') == event]
        summary[key] = gaps
        reasons.update({f'{src}.{reason}': count for reason, count in
                        Counter(row['reason'] for row in gaps).items()})
    summary['capture_gap_counts'] = reasons
    responses = {r['evt_id']: r.get('status') for r in _target_events(events, session, user, 'ha_transport')
                 if r.get('ev') == 'HA_CONTROL_HTTP'}
    reasons = Counter()
    for gap in summary.get('control_gaps', []):
        status = responses.get(gap['event_id'])
        if type(status) is int and 100 <= status <= 599:
            gap['http_status'] = status
        reasons[gap['reason'] + (f' HTTP {status}' if 'http_status' in gap else '')] += 1
    summary['control_gap_counts'] = dict(reasons)
    return summary
