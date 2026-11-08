"""Fresh-value checks for bounded permission controls. 仅用于授权测试。"""
import re
from vehicle.lab.owntracks_run import pairs
from vehicle.privacy.owntracks_evidence import location_read, summarize_body

PERMISSIONS = tuple('android.permission.' + name for name in (
    'ACCESS_COARSE_LOCATION', 'ACCESS_FINE_LOCATION', 'ACCESS_BACKGROUND_LOCATION'))


def permissions(text, user=10):
    block = re.search(rf'(?ms)^\s*User {user}:.*?(?=^\s*User \d+:|\Z)', text)
    if not block:
        raise ValueError('missing explicit runtime permission user block')
    result = {}
    for permission in PERMISSIONS:
        row = re.search(re.escape(permission) + r': granted=(true|false), flags=\[([^\]]*)\]', block[0])
        if not row:
            raise ValueError('missing runtime grant record: ' + permission)
        result[permission] = {'granted': row[1] == 'true', 'flags': row[2].strip()}
    return result


def check_phase(reads, flows, receipts, session, endpoint, step, grants, healthy):
    start, end = step['ts'], step['end_ms']
    key, injected = step['coordinate_sha256_16'], step['device_injected_ms']
    fresh = [r for r in reads if location_read(r, session, 10) and start <= r['host_received_ts'] <= end
             and r['coordinate_sha256_16'] == key and r['location_time_ms'] >= injected]
    new_receipts = [r for r in receipts if start <= r['ts'] <= end and r.get('coordinate_sha256_16') == key
                    and r.get('location_timestamp_seconds', 0) >= injected // 1000]
    phase_flows = [f for f in flows if start <= f['ts'] <= end]
    new_flows = [f for f in phase_flows if summarize_body((f.get('request_payload') or {}).get('text', ''))
                 .get('coordinate_sha256_16') == key]
    wanted = step['name'] != 'denied'
    grant_match = set(grants) == set(PERMISSIONS) and all(r['granted'] is wanted for r in grants.values())
    linked = pairs(fresh, phase_flows, new_receipts, session, endpoint, step) if wanted else []
    passed = bool(linked) if wanted else not fresh and not new_receipts and not new_flows
    return {'passed': bool(healthy and grant_match and passed), 'grant_match': grant_match,
            'capture_healthy': healthy, 'fresh_location_events': len(fresh),
            'fresh_value_receipts': len(new_receipts), 'fresh_value_flows': len(new_flows),
            'verified_pairs': linked, 'observation_ms': end - start,
            'scope': 'fresh synthetic value in this bounded phase; cached/queued older values are separate'}
