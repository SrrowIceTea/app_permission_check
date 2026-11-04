"""Narrow endpoint socket ownership observations for the ABS lab. 仅用于授权测试。"""
import re
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from threading import Event


def socket_samples(text):
    stamp, _, rows = text.partition('\n')
    if not stamp.isdecimal():
        raise ValueError('missing device clock for socket sample')
    for line in rows.splitlines():
        local = r'(?:127\.0\.0\.1|\[::ffff:127\.0\.0\.1\])'
        endpoints = re.search(rf'{local}:(\d+)\s+{local}:18125\b', line)
        if not endpoints:
            continue
        pids = {int(pid) for pid in re.findall(r'pid=(\d+)', line)}
        inode = re.search(r'\bino:(\d+)\b', line)
        yield {'ts': int(stamp), 'port': int(endpoints[1]), 'pids': sorted(pids),
               'inode': int(inode[1]) if inode else None}


@contextmanager
def observe_sockets(device, enabled):
    if not enabled:
        yield None
        return
    stop = Event()
    command = 'date +%s%3N; ss -tnpe state established | grep -F ":18125" || true'

    def sample():
        rows = []
        while not stop.is_set():
            rows.extend(socket_samples(device.call('shell', command)))
            if len(rows) > 512:
                raise ValueError('socket sampling limit exceeded')
            stop.wait(.2)
        return rows

    with ThreadPoolExecutor(max_workers=1) as worker:
        future = worker.submit(sample)
        try:
            yield future
        finally:
            stop.set()


def attribute_requests(requests, samples, pid, uid):
    """Confirm a TCP client port only when the same inode brackets the send."""
    results = []
    for row in requests:
        stamp = row['device_ts_ms']
        nearby = [s for s in samples if s['port'] == row['connection_port'] and abs(s['ts'] - stamp) <= 1500]
        identities = {(s['inode'], tuple(s['pids'])) for s in nearby}
        reason = None
        if not nearby:
            reason = 'no_nearby_sample'
        elif len(identities) != 1 or any(not s['inode'] or s['pids'] != [pid] for s in nearby):
            reason = 'socket_owner_or_inode_unverified'
        elif not min(s['ts'] for s in nearby) <= stamp <= max(s['ts'] for s in nearby):
            reason = 'samples_do_not_bracket_send'
        attributed = reason is None
        results.append({'session_id': row['session_id'], 'connection_port': row['connection_port'],
            'device_ts_ms': stamp, 'status': 'uid_verified' if attributed else 'ownership_unresolved',
            'uid': uid if attributed else None, 'nearby_sample_count': len(nearby),
            'reason': reason,
            'socket_samples': [s for s in nearby if s['pids'] == [pid]]})
    return results
