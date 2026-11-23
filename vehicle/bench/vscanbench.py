"""Play the frozen VScanBench engineering pilot. 仅用于授权测试。"""
import argparse
import sqlite3
import sys
from pathlib import Path

from core.io_utils import load_jsonl
from vehicle.analyze.value_match import match_content
from vehicle.bench.carstats_queue import replay as replay_queue
from vehicle.bench.labels import adjudicated_labels, reference_identity
from vehicle.bench.read_send_control import replay as replay_read_send
from vehicle.bench.window_calibration import calibrate, supports_token_replay
from vehicle.pipeline.contracts import AuditError, ROOT, digest, read_json, write_json

PILOT = Path(__file__).with_name('vscanbench-pilot.json')


def bound(ref, root):
    return next(iter(reference_identity([ref], root)))


def select_events(rows, wanted):
    result = {}
    for row in rows:
        key = (row.get('src'), row.get('evt_id'))
        if key not in wanted:
            continue
        if key in result:
            raise ValueError(f'同来源事件编号重复，无法唯一重放：{key}')
        result[key] = row
    if set(result) != wanted:
        raise ValueError('签核配对引用了缺失的读取或流。')
    return result


def same_value_cross_batch(truth, reads, flows):
    """Pick raw same-value negatives from the pilot's adjudicated cross-batch cases."""
    negatives = truth['universe'] - truth['positive'] - truth['negative_controls']
    same = set()
    for pair in negatives:
        match = match_content(reads[pair[1:3]], flows[pair[3:5]])
        if match and match.get('value_transform') == 'raw':
            same.add(pair)
    return same


def score(row, truth, same):
    actual = {tuple(pair) for pair in row['matched_pairs']}
    controls = truth['negative_controls']
    extras = actual - truth['positive']
    return {
        'window_ms': row['window_ms'], 'tp': row['tp'], 'fn': row['fn'], 'extra_candidates': len(extras),
        'same_value_cross_batch_total': len(same), 'same_value_cross_batch_flagged': len(actual & same),
        'negative_controls_total': len(controls), 'negative_controls_flagged': len(actual & controls),
        'other_reviewed_extra': len((extras & truth['universe']) - same - controls),
        'outside_reviewed_scope': len(actual - truth['universe']),
        'same_value_cross_batch_pairs': sorted(actual & same),
        'flagged_negative_control_pairs': sorted(actual & controls),
    }


def pairing_delta(row, baseline, truth, same):
    if row['window_ms'] != baseline['window_ms']:
        raise ValueError('配对模式对照的窗口不一致。')
    current = {tuple(pair) for pair in row['matched_pairs']}
    previous = {tuple(pair) for pair in baseline['matched_pairs']}
    removed, added = previous - current, current - previous
    return {**score(row, truth, same), 'by_pair_basis': row['by_pair_basis'],
            'lost_window_positive_pairs': sorted(removed & truth['positive']),
            'gained_signed_positive_pairs': sorted(added & truth['positive']),
            'removed_same_value_cross_batch_pairs': sorted(removed & same),
            'added_same_value_cross_batch_pairs': sorted(added & same)}


def compare_modes(play, baseline, supported, truth, same):
    if not supported:
        return {mode: {'status': 'not_applicable', 'reason': 'fixture_token_contract_unavailable'}
                for mode in ('token', 'both')}
    result = {}
    for mode in ('token', 'both'):
        rows = play(mode)['windows']
        deltas = [pairing_delta(row, prior, truth, same)
                  for row, prior in zip(rows, baseline, strict=True)]
        result[mode] = {'status': 'evaluated', 'windows': deltas}
    return result


def run_fixture(case, root):
    cap_manifest = bound(case['capture_manifest'], root)
    labels = bound(case['labels'], root)
    rules = bound(case['rules'], root)
    capture = cap_manifest.parent
    if cap_manifest.name != 'session-manifest.json':
        raise ValueError('采集入口须为封存的 session-manifest.json。')
    identity = read_json(cap_manifest)
    if identity['packages'] != [case['package']] or identity['data_scope'] != 'all':
        raise ValueError('目标包或采集范围与清单不一致。')
    sample, = read_json(labels)['samples']
    apk, session = identity['installed_apk_sha256'], identity['session']
    if sample['id'] != case['label_id']:
        raise ValueError('标签案例身份不一致。')
    truth = adjudicated_labels(sample, apk, session, 'owned_fixture', root=root)
    inputs = [{'path': str(capture / name), 'sha256': identity['input_sha256'][name]}
              for name in ('reads.jsonl', 'flows.jsonl')]
    reference_identity(inputs, root)
    reads = select_events(load_jsonl(capture / 'reads.jsonl'), {p[1:3] for p in truth['universe']})
    flows = select_events(load_jsonl(capture / 'flows.jsonl'), {p[3:5] for p in truth['universe']})
    same = same_value_cross_batch(truth, reads, flows)

    def play(mode):
        replay = calibrate(capture, labels, rules=rules, include_pairs=True, pairing=mode)
        if replay['rules_sha'] != case['rules']['sha256'] or replay['label_sha256'] != case['labels']['sha256']:
            raise ValueError('重放使用的规则库或标签摘要发生变化。')
        return replay

    baseline = play('window')['windows']
    comparison = compare_modes(play, baseline, supports_token_replay(identity, sample), truth, same)
    reference_identity(inputs, root)
    for name in ('capture_manifest', 'rules', 'labels'):
        bound(case[name], root)
    first = baseline[0]
    return {'id': case['id'], 'package': case['package'], 'apk_sha256': apk, 'session_id': session,
            'sample_origin': 'owned_fixture', 'label_tier': first['label_tier'],
            'usable_as_gold': first['usable_as_gold'], 'review_limits': first['review_limits'],
            'reviewed_pairs': len(truth['universe']), 'positive_pairs': len(truth['positive']),
            'source_artifacts': {k: case[k] for k in ('capture_manifest', 'rules', 'labels')},
            'windows': [score(row, truth, same) for row in baseline], 'pairing_comparison': comparison}


def run(manifest, root=ROOT):
    doc = read_json(manifest)
    if (not isinstance(doc, dict) or doc.get('schema_version') != 1
            or not isinstance(doc.get('fixtures'), list) or not doc['fixtures']
            or not all(isinstance(case, dict) for case in doc['fixtures'])):
        raise ValueError('基准清单缺少版本或自有样本。')
    fixtures = []
    used_ids, sessions, apks = set(), set(), set()
    for case in doc['fixtures']:
        try:
            result = run_fixture(case, root)
            if case['id'] in used_ids or result['session_id'] in sessions or result['apk_sha256'] in apks:
                raise ValueError('案例、采集会话或 APK 重复。')
        except (ValueError, OSError, KeyError, TypeError) as error:
            raise AuditError('vscanbench_fixture_failed', f'{case.get("id", "?")} 重放失败：{error}',
                             '检查本案例的原始采集、规则快照与签核标签。') from error
        used_ids.add(case['id'])
        sessions.add(result['session_id'])
        apks.add(result['apk_sha256'])
        fixtures.append(result)

    workflow = bound(doc['carstats_queue'], root)
    queue = replay_queue(workflow.parent, workflow)
    bound(doc['carstats_queue'], root)
    workflows = [{'id': 'carstats-offline-queue', 'session_id': queue['session_id'],
                  'online_points': len(queue['online_point_matches']),
                  'confirmed_offline_points': len(queue['offline_points']),
                  'offline_interval_ms': queue['offline_interval_ms'], 'window_scored': False,
                  'source': doc['carstats_queue']}]
    if 'read_send_control' in doc:
        reference = doc['read_send_control']
        proof = bound(reference, root)
        control = replay_read_send(proof.parent, proof, include_pairing=True)
        bound(reference, root)
        workflows.append({'id': 'read-send-control', **control, 'source': reference})
    return {
        'schema_version': 1, 'status': 'passed', 'scope': 'owned_fixture_engineering_pilot',
        'manifest_sha256': digest(manifest), 'fixtures': fixtures, 'independent_pair_cases': 0,
        'workflow_only': workflows,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path, default=PILOT)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.out.exists():
            raise FileExistsError(f'输出文件已存在：{args.out}')
        result = run(args.manifest)
        args.out.parent.mkdir(parents=True, exist_ok=True)
        write_json(args.out, result)
    except (ValueError, OSError, sqlite3.Error, KeyError, TypeError) as error:
        print(f'{getattr(error, "code", "vscanbench_failed")}: {error}', file=sys.stderr)
        return 2
    print(f"VScanBench 重放通过，{len(result['fixtures'])} 个自有 APK，{len(result['workflow_only'])} 条工作流验证。")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
