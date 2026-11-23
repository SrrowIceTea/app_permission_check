"""Replay the owned read-only and read-and-send AAOS controls. 仅用于授权测试。"""
import argparse
import hashlib
import sys
from pathlib import Path

from core.io_utils import load_jsonl
from vehicle.analyze.batch_pairing import CROSS_CHECK_FRAME, FIXTURE_PACKAGE, PRIMARY_FRAME
from vehicle.analyze.correlate import load_rules
from vehicle.analyze.evaluation import evaluate_data_egress, evaluate_sensitive_read
from vehicle.analyze.value_match import equal_value, raw_value
from vehicle.bench.metrics import matched_pairs
from vehicle.pipeline.contracts import digest, read_json, write_json
from vehicle.pipeline.preflight import validate_capture

SPEED = 'PERF_VEHICLE_SPEED'
USER = 10
MODES = ('read_only', 'plain')


def verify_receiver(out, mode, action, actor, flows):
    receipts = read_json(out / 'receiver.json')
    if not isinstance(receipts, list):
        raise ValueError(f'{mode} 缺少接收端请求清单。')
    if mode == 'read_only':
        if receipts or flows or 'http_status' in actor:
            raise ValueError('只读轮存在请求或发送回执。')
        return None, None
    if len(receipts) != 1 or len(flows) != 1 or actor.get('http_status') != 200:
        raise ValueError('发送轮须有恰好一条归因流和一条独立接收回执。')
    receipt, = receipts
    flow, = flows
    body = out / 'body-0.bin'
    sha = digest(body)
    payload = flow.get('request_payload') or {}
    text = payload.get('text')
    if (receipt.get('body') != body.name or receipt.get('body_sha256') != sha
            or payload.get('raw_sha256') != sha or payload.get('text_sha256') != sha
            or not isinstance(text, str) or hashlib.sha256(text.encode()).hexdigest() != sha
            or receipt.get('status') != 200 or flow.get('status_code') != 200
            or receipt.get('method') != 'POST' or receipt.get('path') != '/collect'
            or flow.get('method') != 'POST' or flow.get('path') != '/collect'
            or flow.get('target_host') != '127.0.0.1' or flow.get('target_port') != 8890
            or not action['start_ms'] <= receipt['received_at_ms'] <= action['end_ms']):
        raise ValueError('发送正文、归因流或 HTTP 回执无法互相核对。')
    doc = read_json(body)
    if (doc.get('package') != FIXTURE_PACKAGE or doc.get('scenarioToken') != action['token']
            or len(doc['reads']) != actor['reads']):
        raise ValueError('独立接收端取得的正文与夹具动作不一致。')
    return flow, body


def capture_identity(capture, manifest, fixture, database):
    validate_capture(capture, FIXTURE_PACKAGE, '15', database)
    if (manifest.get('packages') != [FIXTURE_PACKAGE] or manifest.get('data_scope') != 'all'
            or manifest.get('capture_mode') != 'attach_preserve_proxy'
            or manifest.get('capture_switches', {}).get('tls_bypass') is not False
            or not all(manifest[key] == fixture[key] for key in
                       ('installed_apk_sha256', 'device_sdk', 'device_fingerprint', 'user_id'))
            or not all(name in manifest.get('input_sha256', {}) for name in
                       ('reads.jsonl', 'flows.jsonl', 'egress.jsonl', 'collector-health.json'))):
        raise ValueError('采集身份、范围、开关或输入封存状态不符。')


def primary_reads(reads, action):
    return [row for row in reads if row.get('ev') == 'VHAL_READ' and row.get('outcome') == 'ok'
            and row.get('src') == 'vhal' and row.get('api') == 'cpm.getProperty(II)'
            and row.get('user_id') == USER and row.get('pkg') == FIXTURE_PACKAGE
            and row.get('thread_name') == 'vsc-scenario' and PRIMARY_FRAME.search(row.get('stack') or '')
            and '.AuditScenarioReceiver.' in row['stack']
            and action['start_ms'] <= row.get('host_received_ts', -1) <= action['end_ms']]


def verify_pairing_modes(rules, reads, flows, window, pairs):
    expected = {(p['rule_id'], p['read_src'], p['read_event_id'], p['flow_src'], p['flow_event_id'])
                for p in pairs}
    baseline = matched_pairs(window)
    window_only = baseline - expected
    diagnostic = {(r['src'], r['evt_id']) for r in reads if r.get('ev') == 'VHAL_READ'
                  and CROSS_CHECK_FRAME.search(r.get('stack') or '')}
    if any(pair[1:3] not in diagnostic for pair in window_only):
        raise ValueError('对照中的额外窗口候选未能归到诊断复读。')
    counts = {'window': len(baseline)}
    for mode in ('token', 'both'):
        findings = evaluate_data_egress(rules, reads, flows, pairing=mode)
        actual = matched_pairs(findings)
        details = [p for hit in findings for p in hit['pairs']]
        if (actual != expected or len(details) != len(actual)
                or any(p.get('pair_basis') != 'token_read_claim' or p.get('origin_proven') is not True for p in details)):
            raise ValueError(f'{mode} 模式与独立回执确认的主读取配对不一致。')
        counts[mode] = len(actual)
    return {'pair_counts': counts, 'diagnostic_window_only_pairs': sorted(window_only)}


def replay_arm(out, mode, fixture, database, rules):
    capture = out / 'capture'
    manifest_file = capture / 'session-manifest.json'
    manifest = read_json(manifest_file)
    capture_identity(capture, manifest, fixture, database)
    network_file = out / 'fixture-network.json'
    network = read_json(network_file)
    attempts = network.get('network_cleanup', {}).get('device_reverse_restored')
    if (network['checks'].get('device_reverse_restored') is not True or not attempts
            or attempts[-1].get('status') != 'restored'):
        raise ValueError(f'{mode} 未验证设备回环转发的清理。')
    action = read_json(out / 'action.json')
    actor = read_json(out / 'actor.json')
    if (action['mode'] != mode or actor['mode'] != mode or action['token'] != actor['token']
            or not action['token'] or actor.get('completed') is not True or actor['reads'] < 1
            or not 0 < action['start_ms'] < action['end_ms']):
        raise ValueError(f'{mode} 缺少有效的设备动作回执。')

    reads = load_jsonl(capture / 'reads.jsonl')
    flows = load_jsonl(capture / 'flows.jsonl')
    target_flows = [flow for flow in flows if flow.get('package') == FIXTURE_PACKAGE]
    flow, body = verify_receiver(out, mode, action, actor, target_flows)
    primary = primary_reads(reads, action)
    speed_reads = [row for row in primary if row.get('prop_name') == SPEED]
    if len(speed_reads) != 1 or raw_value(speed_reads[0]) is None:
        raise ValueError(f'{mode} 缺少唯一成功车速主读取。')
    speed, = speed_reads
    read_rules = [hit['rule_id'] for hit in evaluate_sensitive_read(rules, primary)
                  if hit.get('property') == SPEED and speed['evt_id'] in hit['event_ids']]
    if not read_rules:
        raise ValueError(f'{mode} 车速读取未命中启用的读取规则。')
    window = evaluate_data_egress(rules, reads, flows)
    pairs = []
    if mode == 'read_only':
        if window or flows:
            raise ValueError('只读轮出现代理流或外发候选。')
    else:
        token = evaluate_data_egress(rules, primary, [flow], pairing='token')
        expected = {(hit['rule_id'], pair['read_event_id'], pair['flow_event_id'])
                    for hit in token for pair in hit['pairs'] if pair['origin_proven']}
        pairs = [{'rule_id': hit['rule_id'], 'property': hit['property'], **pair}
                 for hit in window for pair in hit['pairs']
                 if (hit['rule_id'], pair['read_event_id'], pair['flow_event_id']) in expected
                 and pair.get('value_transform') == 'raw']
        confirmed = {(p['rule_id'], p['read_event_id'], p['flow_event_id']) for p in pairs}
        if (confirmed != expected or len(pairs) != len(confirmed)
                or not any(p['read_event_id'] == speed['evt_id'] for p in pairs)):
            raise ValueError('窗口重放未找到独立回执确认的同值车速配对。')
    names = [manifest_file, network_file, out / 'action.json', out / 'actor.json', out / 'receiver.json']
    if body is not None:
        names.append(body)
    evidence = {'session_id': manifest['session'], 'action_token_sha256': hashlib.sha256(action['token'].encode()).hexdigest(),
            'capture_health_checks': len(read_json(capture / 'verification.json')['checks']),
            'primary_successful_reads': len(primary), 'speed_value': raw_value(speed),
            'speed_read_event_id': speed['evt_id'], 'speed_read_rules': read_rules,
            'receiver_requests': int(body is not None), 'target_flows': len(target_flows),
            'upstream_status': flow['status_code'] if flow else None,
            'window_candidate_pairs': sum(hit['pair_count'] for hit in window),
            'corroborated_pairs': pairs,
            'input_sha256': {p.relative_to(out).as_posix(): digest(p) for p in names}}
    return evidence, verify_pairing_modes(rules, reads, flows, window, pairs)


def replay(out, reference=None, *, include_pairing=False):
    out = Path(out)
    fixture_file, database = out / 'fixture.json', out / 'rules.db'
    fixture = read_json(fixture_file)
    if (fixture['package'] != FIXTURE_PACKAGE or fixture['user_id'] != USER or fixture['device_sdk'] != 35):
        raise ValueError('对照仅接受专用 AAOS 35 上的自有测试包。')
    rules = load_rules(database, '15')
    (read_only, negative_modes), (positive, positive_modes) = (
        replay_arm(out / mode, mode, fixture, database, rules) for mode in MODES)
    if (read_only['session_id'] == positive['session_id']
            or read_only['action_token_sha256'] == positive['action_token_sha256']):
        raise ValueError('只读轮和发送轮必须是独立会话及动作。')
    if not equal_value(read_only['speed_value'], positive['speed_value']):
        raise ValueError('两轮的实际车速值不同。')
    report = {'schema_version': 1, 'status': 'passed', 'sample_origin': 'owned_fixture',
              'package': FIXTURE_PACKAGE, 'apk_sha256': fixture['installed_apk_sha256'],
              'apk_count': 1, 'session_count': 2, 'window_scored': False,
              'input_sha256': {p.name: digest(p) for p in (fixture_file, database)},
              'read_only': read_only, 'positive': positive}
    if reference is not None and read_json(reference) != report:
        raise ValueError('原始对照证据与封存报告不一致。')
    if include_pairing:
        report['pairing_modes'] = {'read_only': negative_modes, 'positive': positive_modes}
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--reference', type=Path)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.out.exists():
            raise FileExistsError(f'输出文件已存在：{args.out}')
        write_json(args.out, replay(args.source, args.reference))
    except (ValueError, OSError, KeyError, TypeError) as error:
        print(f'{getattr(error, "code", "read_send_control_failed")}: {error}', file=sys.stderr)
        return 2
    print('AAOS 只读负控与发送对照重放通过。')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
