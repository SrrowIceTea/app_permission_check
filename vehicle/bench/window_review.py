"""Prepare a blind B1 subagent review from the owned AAOS fixture. 仅用于授权测试。"""
import argparse
import json
import sys
from collections import Counter
from pathlib import Path

from core.io_utils import load_jsonl
from vehicle.analyze.correlate import load_rules
from vehicle.bench.ablation_integrity import resolve_rules
from vehicle.bench.blind_round import freeze_review
from vehicle.bench.labels import reference_identity
from vehicle.pipeline.contracts import ROOT, digest, read_json
from vehicle.pipeline.preflight import validate_capture


CASE = 'b1-window'
PACKAGE = 'com.vscanner.targetapp'
READ_ACTIONS = ('network_enqueue', 'plain', 'mismatch')
FLOW_ACTIONS = ('cache_flush', 'plain', 'mismatch')
SOURCE_FILES = ('fixture-cache-source.kt', 'fixture-vhal-reader-source.kt')
GUIDE = """# B1 自有夹具盲评

仅使用此包中的证据。不要查看旧标注、窗口回放结果或另一名复核者的答卷。
逐项判断指定主读取是否与指定 HTTP 请求中的属性值属于同一来源批次。
只有会话、身份、属性、值、时间和独立动作回执一致时才填 present。
有明确反证填 absent。证据不足或无法区分来源填 insufficient，并说明原因。
设备时钟仅用于对齐 Hook 读取与正文的 readAtUtcMs。宿主时钟用于匹配动作窗口及 HTTP 请求。
确认正负时附事件来源和编号、回执或正文中支持判断的字段。
review.json 使用实际 agent_id、全新上下文与独立 UUID，时间须含时区。
"""


def _ref(path, expected=None):
    return {'path': str(path.resolve()), 'sha256': expected if expected is not None else digest(path)}


def _action_evidence(actions_path, source):
    actions = read_json(actions_path)
    if Counter(a['mode'] for a in actions) != Counter(('cache_clear', 'network_enqueue', 'plain',
                                                      'cache_flush', 'mismatch')):
        raise ValueError('B1 requires the five distinct offline fixture actions')
    rows, refs = {}, {}
    for action in actions:
        mode = action['mode']
        path = source / (mode + '-receipt.json')
        refs[mode] = _ref(path, action['sha256'])
        if digest(path) != action['sha256']:
            raise ValueError(f'B1 receipt digest mismatch: {mode}')
        receipt = read_json(path)
        if (receipt.get('completed') is not True or receipt.get('token') != action['token']
                or receipt.get('mode') != mode or action['start_ms'] > action['end_ms']):
            raise ValueError(f'B1 receipt and action disagree: {mode}')
        rows[mode] = {**{key: action[key] for key in ('token', 'start_ms', 'end_ms')}, 'receipt': receipt}
    seed = rows['network_enqueue']['receipt']
    if seed.get('network_failed') is not True or seed.get('cached_batches') != 1:
        raise ValueError('B1 requires a failed offline send with exactly one cached batch')
    return rows, refs


def _in_action(event_ms, action):
    return action['start_ms'] <= event_ms <= action['end_ms']


def _reads(capture, actions, by_prop):
    groups = {mode: [] for mode in READ_ACTIONS}
    for event in load_jsonl(capture / 'reads.jsonl'):
        if (event.get('src') != 'vhal' or event.get('ev') != 'VHAL_READ' or event.get('pkg') != PACKAGE
                or event.get('outcome') != 'ok' or event.get('prop_id') not in by_prop):
            continue
        stack = event.get('stack') or ''
        if '.readOne(' not in stack or '.readFloatCrossCheck(' in stack:
            continue
        for mode in groups:
            if _in_action(event['host_received_ts'], actions[mode]):
                groups[mode].append({**{key: event[key] for key in (
                    'src', 'evt_id', 'pkg', 'uid', 'pid', 'session_id', 'ts', 'host_received_ts', 'prop_id',
                    'prop_name', 'outcome', 'value_raw')},
                    'stack_evidence': [line.strip() for line in stack.splitlines() if 'VhalReader.' in line]})
    if any(not rows or len({row['prop_id'] for row in rows}) != len(rows) for rows in groups.values()):
        raise ValueError('B1 requires one unambiguous primary read per captured property and action')
    props = {row['prop_id'] for row in groups['plain']}
    if any({row['prop_id'] for row in rows} != props for rows in groups.values()):
        raise ValueError('B1 action groups must cover the same primary properties')
    return groups


def _flows(capture, actions):
    groups = {mode: [] for mode in FLOW_ACTIONS}
    for event in load_jsonl(capture / 'flows.jsonl'):
        if event.get('src') != 'proxy' or event.get('package') != PACKAGE:
            continue
        modes = [mode for mode in groups if _in_action(event['ts'], actions[mode])]
        if not modes:
            continue
        payload = event.get('request_payload') or {}
        if any(payload.get(flag) for flag in ('raw_truncated', 'text_truncated', 'decode_error')):
            raise ValueError('B1 request body is incomplete')
        body = json.loads(payload['text'])
        for mode in modes:
            if body.get('scenarioToken') == actions[mode]['token']:
                groups[mode].append({**{key: event[key] for key in (
                    'src', 'evt_id', 'package', 'uid', 'session_id', 'ts', 'path', 'method', 'status_code',
                    'attribution', 'attribution_ambiguous')},
                    'body': {key: body[key] for key in ('reads', 'scenarioToken', 'sourceBatchTokens') if key in body}})
    if any(len(rows) != 1 for rows in groups.values()):
        raise ValueError('B1 requires exactly one request per flow action')
    return {mode: rows[0] for mode, rows in groups.items()}


def _render(evidence):
    lines = ['# B1 冻结证据', '']
    lines += [f'- {item["id"]} {item["prompt"]}' for item in evidence['questions']]
    lines.extend(('', '事件与回执详见 evidence.json。'))
    return '\n'.join(lines) + '\n'


def prepare(source, reference, rules, out, *, root=ROOT):
    source = Path(source).resolve()
    capture = source / 'capture'
    manifest_path = capture / 'session-manifest.json'
    manifest = read_json(manifest_path)
    label = read_json(reference)
    apk, session = manifest['installed_apk_sha256'], manifest['session']
    if (manifest.get('packages') != [PACKAGE] or not manifest.get('input_sha256')
            or manifest.get('android_version') != '15' or label.get('sample_class') != 'owned_fixture'
            or label.get('apk_sha256') != apk or label.get('session_id') != session):
        raise ValueError('B1 requires the same sealed AAOS 35 owned fixture and reference')
    database = resolve_rules(root, manifest, rules)
    validate_capture(capture, PACKAGE, '15', database)
    refs = {Path(ref['file']).name: {'path': ref['file'], 'sha256': ref['sha256']}
            for ref in label['reference_evidence']}
    if len(refs) != len(label['reference_evidence']):
        raise ValueError('B1 reference contains duplicate evidence filenames')
    actions_path = source / 'actions.json'
    sources = {'business': _ref(actions_path, refs['actions.json']['sha256']),
               'manifest': _ref(manifest_path), 'rules': _ref(database, manifest['rules_sha256']),
               **{name: refs[name] for name in SOURCE_FILES}}
    for name, expected in manifest['input_sha256'].items():
        sources[name] = _ref(capture / name, expected)
    reference_identity(list(sources.values()), root)
    actions, receipt_refs = _action_evidence(actions_path, source)
    if any(receipt_refs[mode]['sha256'] != refs[mode + '-receipt.json']['sha256'] for mode in receipt_refs):
        raise ValueError('B1 receipt digests do not match the reference')
    sources.update(receipt_refs)
    by_prop = {json.loads(row['condition_json']).get('property_id'): row['rule_id']
               for row in load_rules(database, '15') if row['rule_type'] == 'data_egress' and row['enabled']}
    reads, flows = _reads(capture, actions, by_prop), _flows(capture, actions)
    items, questions = [], []
    for event in sorted((row for rows in reads.values() for row in rows), key=lambda row: row['evt_id']):
        for flow in sorted(flows.values(), key=lambda row: row['evt_id']):
            item = f'P{len(items) + 1:02d}'
            pair = [by_prop[event['prop_id']], event['src'], event['evt_id'], flow['src'], flow['evt_id']]
            items.append({'id': item, 'case': CASE, 'pair': pair})
            questions.append({'id': item, 'pair': pair, 'prompt':
                f'{event["prop_name"]} 的 vhal:{event["evt_id"]} 与 proxy:{flow["evt_id"]} 是否为同一来源批次？'})
    evidence = {'schema_version': 1, 'questions': questions, 'actions': actions, 'reads': reads, 'flows': flows,
                'fixture_sources': {name: Path(sources[name]['path']).read_text(encoding='utf-8')
                                    for name in SOURCE_FILES}}
    reference_identity(list(sources.values()), root)
    plan = {'schema_version': 1, 'review_mode': 'subagent', 'reviewer_kind': 'subagent', 'pair_case': CASE,
            'cases': [{'id': CASE, 'apk_sha256': apk, 'session_id': session, 'sample_origin': 'owned_fixture',
                       'sources': sources, 'reference_evidence': list(sources.values())}],
            'items': items, 'status': 'awaiting_independent_reviews'}
    return freeze_review(Path(out), evidence, plan, guide=GUIDE, renderer=_render)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('source', 'reference', 'rules', 'out'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    try:
        plan = prepare(args.source, args.reference, args.rules, args.out)
    except (ValueError, KeyError, OSError) as error:
        print(f'B1 待补证据。{error}', file=sys.stderr)
        return 1
    print(json.dumps({'status': plan['status'], 'pairs': len(plan['items'])}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
