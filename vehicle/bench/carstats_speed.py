"""Replay signed VHAL speed stimuli and Car Stats Viewer HTTPS receipts. 仅用于授权测试。"""
import argparse
import sys
from decimal import Decimal, InvalidOperation
from pathlib import Path

from core.io_utils import load_jsonl
from vehicle.bench.carstats_queue import PACKAGE, verified_requests
from vehicle.pipeline.contracts import digest, read_json, write_json
from vehicle.pipeline.preflight import validate_capture

PROPERTY = 'PERF_VEHICLE_SPEED'
ENDPOINT = '/b1-carstatsviewer'


def number(value):
    try:
        result = Decimal(str(value))
    except InvalidOperation as error:
        raise ValueError('车速数值格式无效。') from error
    if not result.is_finite():
        raise ValueError('车速必须为有限数值。')
    return result


def speed_reads(rows, session):
    reads = []
    ids = set()
    for row in rows:
        if (row.get('src'), row.get('ev'), row.get('prop_name'), row.get('outcome')) != (
                'vhal', 'VHAL_READ', PROPERTY, 'ok'):
            continue
        evt_id = row['evt_id']
        if (row.get('session_id') != session or row.get('pkg') != PACKAGE
                or type(evt_id) is not int or evt_id <= 0 or evt_id in ids):
            raise ValueError('车速读取的会话、包名或事件编号不一致。')
        ids.add(evt_id)
        reads.append(row)
    return reads


def online_speed_requests(source):
    for receipt, body in verified_requests(source):
        if (receipt.get('path') != ENDPOINT or type(body.get('speed')) not in (int, float)
                or number(body['speed']) < 0
                or number(body['speed']) != number(receipt['speed_mps'])):
            raise ValueError('车速正文与独立接收端回执不一致。')
        yield receipt


def replay_phases(actions, reads, receipts):
    if len(actions) < 2 or not any(number(a['speed_mps']) < 0 for a in actions):
        raise ValueError('缺少含负车速的两段绝对值转换对照。')
    starts = [a['command_started_ms'] for a in actions]
    speeds = [number(a['speed_mps']) for a in actions]
    if sorted(set(starts)) != starts or len({abs(v) for v in speeds}) < 2:
        raise ValueError('车速对照时序或绝对值缺少区分。')
    phases = []
    for index, (action, speed) in enumerate(zip(actions, speeds, strict=True)):
        start = starts[index]
        stop = starts[index + 1] if index + 1 < len(starts) else float('inf')
        if number(action['readback_mps']) != speed or not start <= action['command_finished_ms'] < stop:
            raise ValueError('VHAL 动作缺少同值读回，或阶段时间有重叠。')
        phase_reads = [r for r in reads if start <= r['host_received_ts'] < stop
                       and number(r['value_raw']) == speed]
        matches = []
        for receipt in receipts:
            received = receipt['host_received_ms']
            if not start <= received < stop or number(receipt['speed_mps']) != abs(speed):
                continue
            candidates = [r['evt_id'] for r in phase_reads if r['host_received_ts'] <= received
                          and r['ts'] <= receipt['body_timestamp_ms']]
            if not candidates:
                raise ValueError('接收端车速没有同阶段且先于请求的读取观测。')
            matches.append({'request_sha256': receipt['request_sha256'],
                            'receipt_host_ms': received, 'same_value_read_event_ids': candidates})
        if not matches:
            raise ValueError(f'未收到与 VHAL 阶段 {speed} m/s 对应的 HTTPS 正文。')
        phases.append({'stimulus_mps': action['speed_mps'], 'request_speed_mps': float(abs(speed)),
                       'observed_reads': len(phase_reads), 'receipts': matches})
    return phases


def replay(source, reference=None):
    source = Path(source).resolve()
    capture = source / 'capture'
    manifest = read_json(capture / 'session-manifest.json')
    verification = read_json(capture / 'verification.json')
    session = manifest['session']
    if (manifest['packages'] != [PACKAGE] or manifest['data_scope'] != 'all'
            or verification['session'] != session or verification['tls_bypass'] is not False):
        raise ValueError('采集范围、会话身份或 TLS 开关不符合车速验证。')
    validate_capture(capture, PACKAGE, '15', source / 'rules.db')
    before = read_json(source / 'vhal-before.json')
    after = read_json(source / 'vhal-after.json')
    if after['restored'] is not True or number(after['speed_mps']) != number(before['speed_mps']):
        raise ValueError('VHAL 车速缺少恢复读回。')
    reads = speed_reads(load_jsonl(capture / 'reads.jsonl'), session)
    receipts = list(online_speed_requests(source))
    phases = replay_phases(read_json(source / 'actions.json'), reads, receipts)
    paths = ['actions.json', 'vhal-before.json', 'vhal-after.json', 'rules.db', 'receiver.jsonl',
             'capture/session-manifest.json', 'capture/verification.json', 'capture/reads.jsonl']
    paths.extend(f'request-bodies/{sha}.json' for sha in sorted({r['request_sha256'] for r in receipts}))
    result = {'status': 'passed', 'session_id': session,
              'apk_sha256': manifest['installed_apk_sha256'], 'capture_check_count': len(verification['checks']),
              'http_200': len(receipts), 'phases': phases, 'window_scored': False,
              'read_pair_eligibility': 'serialized_speed_lacks_source_read_identity',
              'artifact_sha256': {name: digest(source / name) for name in paths}}
    if reference is not None and result != read_json(reference):
        raise ValueError('车速重放与封存结果或原始证据摘要不一致。')
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True, type=Path)
    parser.add_argument('--reference', type=Path)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        if args.out.exists():
            raise FileExistsError(f'输出文件已存在：{args.out}')
        result = replay(args.source, args.reference)
        args.out.parent.mkdir(parents=True, exist_ok=True)
        write_json(args.out, result)
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f'{getattr(error, "code", "speed_replay_failed")}: {error}', file=sys.stderr)
        return 2
    print(f"车速上传重放通过，{result['http_200']} 条 HTTPS 回执。")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
