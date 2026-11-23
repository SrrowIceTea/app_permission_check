"""Replay the Car Stats Viewer store-and-forward evidence. 仅用于授权测试。"""
import argparse
import re
import sqlite3
import struct
import sys
from contextlib import closing
from pathlib import Path
from shutil import copyfile
from tempfile import TemporaryDirectory

from core.io_utils import load_jsonl
from vehicle.pipeline.contracts import AuditError, digest, read_json, write_json
from vehicle.pipeline.preflight import validate_capture

PACKAGE = 'com.ixam97.carStatsViewer'
KEY = 'driving_point_epoch_time'
FLOATS = ('energy_delta', 'distance_delta', 'state_of_charge')
SQL = f'SELECT {KEY}, {", ".join(FLOATS)}, point_marker_type FROM DrivingPoint ORDER BY {KEY}'


def require(condition, message):
    if not condition:
        raise AuditError('queue_evidence_mismatch', message, '核对原始采集、SQLite 快照与 HTTPS 回执。')


def snapshot(source):
    """Read the DB and its WAL from a scratch copy, leaving the original untouched."""
    with TemporaryDirectory() as scratch:
        folder = Path(scratch)
        for name in ('TripDatabase', 'TripDatabase-wal'):
            if (source / name).is_file():
                copyfile(source / name, folder / name)
        local = folder / 'TripDatabase'
        require(local.is_file(), f'缺少 {source.name} 的 SQLite 主文件。')
        with closing(sqlite3.connect(local.as_uri() + '?mode=ro', uri=True)) as db:
            db.row_factory = sqlite3.Row
            require(db.execute('PRAGMA quick_check').fetchone()[0] == 'ok', 'SQLite 快照校验失败。')
            return [dict(row) for row in db.execute(SQL)]


def load_receipts(source):
    receipts = load_jsonl(source / 'receiver.jsonl')
    require(receipts, '缺少 HTTPS 接收端回执。')
    sent = []
    for receipt in receipts:
        sha = receipt['request_sha256']
        require(isinstance(sha, str) and re.fullmatch(r'[0-9a-f]{64}', sha), '正文摘要格式无效。')
        path = source / 'request-bodies' / (sha + '.json')
        require(receipt['http_status'] == 200 and digest(path) == sha
                and path.stat().st_size == receipt['request_size'], f'正文与 HTTPS 回执不符：{sha}。')
        doc = read_json(path)
        require(doc.get('timestamp') == receipt['body_timestamp_ms'] and
                doc.get('apiVersion') == receipt['api_version'] == '2.1' and
                doc.get('appVersion') == receipt['app_version'],
                f'HTTPS 正文版本或时间与回执不符：{sha}。')
        sent.extend((receipt, point) for point in doc.get('drivingPoints') or [])
    return receipts, sent


def same_point(point, remote):
    return (point[KEY] == remote[KEY]
            and point['point_marker_type'] == remote.get('point_marker_type')
            and all(struct.pack('!f', point[k]) == struct.pack('!f', remote[k]) for k in FLOATS)
            and all(remote.get(k) is None for k in ('lat', 'lon', 'alt', 'speed', 'readAtUtcMs')))


def replay(source, reference=None):
    source = Path(source).resolve()
    cap = source / 'capture'
    manifest = read_json(cap / 'session-manifest.json')
    checks = read_json(cap / 'verification.json')
    require(manifest['packages'] == [PACKAGE] and checks['tls_bypass'] is False, '采集目标或 TLS 开关不符合补传验证。')
    validate_capture(cap, PACKAGE, '15', source / 'rules.db')
    vehicle = read_json(source / 'vhal-after.json')
    require(vehicle and all(v['restored'] is True for v in vehicle.values()), '挡位或车速没有恢复证据。')
    require(read_json(source / 'environment-cleanup.json')['cleanup_ok'] is True, 'Wi-Fi 没有恢复证据。')
    for name, status in (('offline', 'Wifi is disabled'), ('online', 'Wifi is connected')):
        network = read_json(source / f'queue-{name}-environment.json')
        require(status in network['wifi_status'], f'缺少 {name} 状态读回。')

    phase = read_json(source / 'timeline.json')
    start, restore = phase['offline_confirmed_ms'], phase['reconnect_started_ms']
    require(start <= phase['offline_database_read_ms'] <= restore - 45000
            and restore <= phase['reconnected_confirmed_ms'],
            '离线读库和恢复的时序不足以证明 45 秒等待。')
    receipts, sent = load_receipts(source)
    require(not any(start <= r['host_received_ms'] < restore for r in receipts), '断网区间收到了 HTTPS 请求。')
    online = snapshot(source / 'db-online')
    online_ids = {p[KEY] for p in online}
    offline = [p for p in snapshot(source / 'db-offline') if p[KEY] not in online_ids]
    require(online and offline and online == read_json(source / 'online-points.json')
            and offline == read_json(source / 'offline-points.json'), '行驶点导出与原始 SQLite 快照不一致。')

    online_matches = [{KEY: p[KEY], 'device_age_ms': r['body_timestamp_ms'] - p[KEY]} for r, p in sent
                      if r['host_received_ms'] < start and any(same_point(local, p) for local in online)]
    require({p[KEY] for p in online_matches} == online_ids
            and all(p['device_age_ms'] >= 0 for p in online_matches), '在线对照缺点或时间倒序。')
    backlog = []
    for point in offline:
        matches = [r for r, p in sent if same_point(point, p)]
        require(len(matches) == 1 and matches[0]['host_received_ms'] >= restore,
                f'离线点缺失、提前送达或重复：{point[KEY]}。')
        receipt = matches[0]
        age = receipt['body_timestamp_ms'] - point[KEY]
        require(age >= 45000, f'离线点未达到 45 秒：{point[KEY]}。')
        backlog.append({**point, 'device_point_age_ms': age, 'request_sha256': receipt['request_sha256'],
                        'receipt_host_ms': receipt['host_received_ms'], 'receipts_for_this_point': 1})
    paths = ['capture/verification.json', 'capture/session-manifest.json', 'capture/reads.jsonl',
             'timeline.json', 'receiver.jsonl', 'offline-points.json', 'online-points.json', 'vhal-actions.json',
             'vhal-after.json', 'queue-offline-environment.json', 'queue-online-environment.json',
             'environment-cleanup.json']
    paths.extend(f'{folder}/{name}' for folder in ('db-online', 'db-offline')
                 for name in ('TripDatabase', 'TripDatabase-wal') if (source / folder / name).is_file())
    paths.extend(f'request-bodies/{sha}.json' for sha in sorted({r['request_sha256'] for r in receipts}))
    result = {'status': 'passed', 'session_id': manifest['session'], 'capture_check_count': len(checks['checks']),
              'http_200': len(receipts), 'offline_interval_ms': restore - start, 'http_receipts_during_offline': 0,
              'online_point_matches': online_matches, 'offline_points': backlog,
              'window_scored': False,
              'read_pair_eligibility': 'point_aggregate_or_derived_state_without_raw_read_event_identity',
              'artifact_sha256': {name: digest(source / name) for name in paths}}
    if reference is not None:
        require(result == read_json(reference), '重放与封存的补传结果或原始证据摘要不符。')
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--reference', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.out.exists():
            raise FileExistsError(f'输出文件已存在：{args.out}')
        result = replay(args.source, args.reference)
        args.out.parent.mkdir(parents=True, exist_ok=True)
        write_json(args.out, result)
    except (ValueError, OSError, sqlite3.Error, KeyError, TypeError, struct.error) as error:
        print(f'{getattr(error, "code", "queue_replay_failed")}: {error}', file=sys.stderr)
        return 2
    print(f"补传重放通过，在线 {len(result['online_point_matches'])} 点，离线 {len(result['offline_points'])} 点。")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
