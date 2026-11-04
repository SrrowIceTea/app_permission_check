"""Prepare or compare the first independent O3 blind review. 仅用于授权测试。"""
import argparse
import json
from datetime import datetime
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

from vehicle.bench.blind_evidence import PILOT_IDS, REVIEW_TITLES, WORKFLOWS, Sources, battery
from vehicle.bench.labels import LABEL_SCHEMA, canonical_sha, reference_identity
from vehicle.pipeline.contracts import ROOT, digest, read_json, write_json

SUITE = ROOT / 'vehicle/bench/aaos35-suite.json'
CHOICES = {'present', 'absent', 'insufficient'}
GUIDE = """# O3 首轮独立标注

只用本包内的材料判断。先读 evidence.md，再填写 review.json，保留每个问题编号。
请独立作答，提交前不要与另一位审阅者交换判断，也不要打开旧的审计报告或初评记录。

- present 表示本题命题得到证据支持。
- absent 表示证据足以否定本题命题。
- insufficient 表示证据不足或有歧义。说明缺什么，保留为待补证。

每题填写 decision 和 reason。reason 可引用证据中的来源与事件编号。
reviewer 填本人姓名，reviewed_at 填带时区的 ISO 8601 时间，例如 2026-11-04T15:00:00+08:00。
两位审阅者分别把填写完的 review.json 交回组织者。

电量题逐对判断同一次读取与请求是否能对齐。可核对 level、scale、实际请求字段、
请求时序、进程身份和独立服务端状态。同一个 evt_id 在不同来源下可能重复。
ts 和 request_started_ts 属设备时钟，host_received_ts 和外部动作记录属宿主时钟。
跨时钟请分别核对，外部动作的记录点本身不能证明设备读取的先后。业务复核题按题意作答。
"""


def render(evidence):
    lines = ['# 复核证据', '', '以下记录来自授权测试。正文中仅保留本轮判断所需字段。']
    for case in evidence['cases']:
        lines.extend(['', '## ' + case['title'], '', *[
            '- **' + item['id'] + '** ' + item['prompt'] for item in case['questions']],
            '', '```json', json.dumps(case['facts'], ensure_ascii=False, indent=2), '```'])
    return '\n'.join(lines) + '\n'


def prepare(suite, out, root=ROOT):
    root = Path(root).resolve()
    source_cases = read_json(suite)['cases']
    cases = {case['id']: case for case in source_cases}
    if len(source_cases) != len(PILOT_IDS) or set(cases) != set(PILOT_IDS):
        raise ValueError('blind pilot requires exactly the seven sealed cases')
    cards, bindings, items = [], [], []
    for key in PILOT_IDS:
        case = cases[key]
        if not case.get('authorization') or case['apk'].get('signature_verified') is not True:
            raise ValueError('pilot sample lacks authorization or verified APK signature: ' + key)
        source = Sources(case, root)
        questions = []
        if key == 'ha-battery':
            facts, pairs = battery(source)
            for index, pair in enumerate(sorted(pairs, key=canonical_sha), 1):
                item_id = f'P{index:02d}'
                questions.append({'id': item_id, 'prompt':
                    f'{pair[1]} 事件 {pair[2]} 与 {pair[3]} 事件 {pair[4]} 是否构成同一轮电量读取与请求？'})
                items.append({'id': item_id, 'case': key, 'pair': pair})
        else:
            project, prompt = WORKFLOWS[key]
            facts = project(source)
            item_id = f'W{len(cards):02d}'
            questions.append({'id': item_id, 'prompt': prompt})
            items.append({'id': item_id, 'case': key})
        cards.append({'title': REVIEW_TITLES[key], 'questions': questions, 'facts': facts})
        bindings.append(source.binding())

    evidence = {'schema_version': 1, 'cases': cards}
    rendered = render(evidence)
    out.mkdir(parents=True, exist_ok=False)
    private = out / 'organizer-only'
    private.mkdir()
    evidence_path = private / 'evidence.json'
    write_json(evidence_path, evidence)
    evidence_sha = digest(evidence_path)
    plan = {'schema_version': 1, 'suite_sha256': digest(suite), 'evidence_sha256': evidence_sha,
            'cases': bindings, 'items': items, 'status': 'awaiting_independent_reviews'}
    plan_path = private / 'plan.json'
    write_json(plan_path, plan)
    plan_sha = digest(plan_path)
    for slot in ('A', 'B'):
        review = {'schema_version': 1, 'slot': slot, 'evidence_sha256': evidence_sha,
                  'plan_sha256': plan_sha,
                  'reviewer': None, 'reviewed_at': None,
                  'decisions': [{'id': item['id'], 'decision': None, 'reason': None} for item in items]}
        with ZipFile(out / f'reviewer-{slot}.zip', 'x', compression=ZIP_DEFLATED) as archive:
            archive.writestr('README.md', GUIDE)
            archive.writestr('evidence.md', rendered)
            archive.write(evidence_path, 'evidence.json')
            archive.writestr('review.json', json.dumps(review, ensure_ascii=False, indent=2) + '\n')
    write_json(private / 'adjudication-pending.json', {'status': 'awaiting_independent_reviews',
               'evidence_sha256': evidence_sha, 'plan_sha256': plan_sha,
               'pending_items': [item['id'] for item in items],
               'disagreements': None, 'pair_items_with_insufficient_evidence': None,
               'reviewer': None, 'reviewed_at': None})
    return plan


def reviewer(path, slot, evidence_sha, plan_sha, expected):
    submission = read_json(path)
    if (submission.get('schema_version') != 1 or submission.get('slot') != slot
            or submission.get('evidence_sha256') != evidence_sha or submission.get('plan_sha256') != plan_sha):
        raise ValueError('review slot or frozen digest mismatch: ' + slot)
    name = submission.get('reviewer')
    if not isinstance(name, str) or not name.strip():
        raise ValueError('missing reviewer name: ' + slot)
    try:
        timestamp = datetime.fromisoformat(submission['reviewed_at'])
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError('invalid review time: ' + slot) from exc
    if timestamp.utcoffset() is None:
        raise ValueError('review time requires a timezone: ' + slot)
    decisions = {}
    for row in submission.get('decisions', []):
        item, choice, reason = row.get('id'), row.get('decision'), row.get('reason')
        if (not isinstance(item, str) or item not in expected or item in decisions
                or not isinstance(choice, str) or choice not in CHOICES
                or not isinstance(reason, str) or not reason.strip()):
            raise ValueError('missing, duplicate or invalid review decision: ' + slot)
        decisions[item] = row
    if set(decisions) != expected:
        raise ValueError('review must cover all frozen items: ' + slot)
    return submission, decisions


def compare(private, first, second, out, root=ROOT):
    plan_path = private / 'plan.json'
    plan = read_json(plan_path)
    plan_sha = digest(plan_path)
    evidence_sha = plan['evidence_sha256']
    if digest(private / 'evidence.json') != evidence_sha:
        raise ValueError('frozen evidence digest mismatch')
    for binding in plan['cases']:
        reference_identity(list(binding['sources'].values()), root)
    expected = {item['id'] for item in plan['items']}
    a, a_rows = reviewer(first, 'A', evidence_sha, plan_sha, expected)
    b, b_rows = reviewer(second, 'B', evidence_sha, plan_sha, expected)
    if a['reviewer'].strip().casefold() == b['reviewer'].strip().casefold():
        raise ValueError('independent reviews require two different reviewers')
    disagreements, insufficient = [], []
    pair_items = [item for item in plan['items'] if 'pair' in item]
    for item in plan['items']:
        key = item['id']
        a_row, b_row = a_rows[key], b_rows[key]
        if a_row['decision'] != b_row['decision']:
            disagreements.append({**item, 'A': a_row, 'B': b_row, 'decision': None, 'reason': None})
        if 'insufficient' in (a_row['decision'], b_row['decision']):
            insufficient.append(key)
    result = {'status': 'awaiting_human_adjudication', 'evidence_sha256': evidence_sha, 'plan_sha256': plan_sha,
              'review_sha256': {'A': digest(first), 'B': digest(second)},
              'disagreements': disagreements, 'insufficient_items': insufficient,
              'pair_items_with_insufficient_evidence': [x['id'] for x in pair_items if x['id'] in insufficient],
              'reviewer': None, 'reviewed_at': None}
    out.mkdir(parents=True, exist_ok=False)
    write_json(out / 'adjudication.json', result)
    write_json(out / 'workflow-reviews.json', [{'id': item['id'], 'case': item['case'],
        'A': a_rows[item['id']], 'B': b_rows[item['id']]} for item in plan['items'] if 'pair' not in item])
    if not result['pair_items_with_insufficient_evidence']:
        binding = next(case for case in plan['cases'] if case['id'] == 'ha-battery')
        label = {key: binding[key] for key in ('id', 'apk_sha256', 'session_id')}
        label.update(schema_version=LABEL_SCHEMA, pair_schema=2, sample_origin='independent',
            origin='independent_review', human_signoff='pending',
            reference_evidence=[binding['sources']['business']],
            universe=[{'pair': item['pair'], 'negative_control': None} for item in pair_items],
            reviews=[{'reviewer': submission['reviewer'], 'reviewed_at': submission['reviewed_at'],
                      'decisions': [{'pair': item['pair'],
                                     'present': rows[item['id']]['decision'] == 'present'}
                                    for item in pair_items]}
                     for submission, rows in ((a, a_rows), (b, b_rows))],
            adjudication={'reviewer': None, 'reviewed_at': None,
                          'decisions': [{'pair': item['pair'], 'present': None}
                                        for item in disagreements if 'pair' in item]})
        write_json(out / 'labels-draft.json', {'samples': [label]})
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_subparsers(dest='action', required=True)
    new = actions.add_parser('prepare')
    new.add_argument('--suite', type=Path, default=SUITE)
    new.add_argument('--out', type=Path, required=True)
    collect = actions.add_parser('compare')
    collect.add_argument('--organizer', type=Path, required=True)
    collect.add_argument('--review-a', type=Path, required=True)
    collect.add_argument('--review-b', type=Path, required=True)
    collect.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    result = (prepare(args.suite, args.out) if args.action == 'prepare'
              else compare(args.organizer, args.review_a, args.review_b, args.out))
    print(json.dumps({'status': result['status'], 'out': str(args.out)}, ensure_ascii=False))


if __name__ == '__main__':
    main()
