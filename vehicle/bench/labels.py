"""Sealed, independently adjudicated pair labels. 仅用于授权测试。"""
import hashlib
import json
from datetime import datetime
from pathlib import Path

from core.io_utils import load_jsonl
from vehicle.pipeline.contracts import ROOT, AuditError, digest
from vehicle.bench.review_policy import label_mode, validate_agents

LABEL_SCHEMA = 1
SAMPLE_ORIGINS = {'owned_fixture', 'independent'}


def reject(reason):
    raise AuditError('invalid_review_labels', reason, '使用两份独立标注与一份仲裁记录，绑定原始参考证据。')


def canonical_sha(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=True,
                                     separators=(',', ':')).encode()).hexdigest()


def pair_key(value):
    if (not isinstance(value, list) or len(value) != 5
            or any(not isinstance(value[i], str) or not value[i].strip() for i in (0, 1, 3))
            or any(type(value[i]) is not int or value[i] <= 0 for i in (2, 4))):
        reject('标注配对必须包含规则、双向事件来源及正整数事件编号。')
    return tuple(value)


def reference_identity(refs, root=ROOT):
    root = Path(root).resolve()
    if not isinstance(refs, list) or not refs:
        reject('缺少独立参考证据。')
    paths = {}
    for ref in refs:
        if not isinstance(ref, dict) or not isinstance(ref.get('path'), str):
            reject('参考证据路径无效。')
        path = (root / ref['path']).resolve()
        if (not path.is_relative_to(root) or path in paths
                or not path.is_file() or digest(path) != ref.get('sha256')):
            reject('参考证据重复、越界、缺失或摘要不一致。')
        paths[path] = ref['sha256']
    return paths


def _person(record):
    reviewer = record.get('reviewer')
    if not isinstance(reviewer, str) or not reviewer.strip():
        reject('缺少复核者身份。')
    try:
        timestamp = datetime.fromisoformat(record['reviewed_at'])
    except (KeyError, ValueError, TypeError):
        reject('复核时间无效。')
    if timestamp.tzinfo is None:
        reject('复核时间须包含时区。')
    return reviewer.strip().casefold()


def _decisions(record, expected):
    result = {}
    for row in record.get('decisions') or []:
        if not isinstance(row, dict):
            reject('标注决策格式无效。')
        pair = pair_key(row.get('pair'))
        if pair in result or type(row.get('present')) is not bool:
            reject('标注决策重复或缺少明确的正负判断。')
        result[pair] = row['present']
    if set(result) != expected:
        reject('标注未覆盖本次要求复核的全部配对。')
    return result


def captured_event_refs(capture):
    return {(row.get('src'), row.get('evt_id')) for name in ('reads', 'flows', 'egress')
            for row in load_jsonl(Path(capture) / (name + '.jsonl'))}


def adjudicated_labels(label, apk_sha, session, sample_origin, *, refs=None, root=ROOT, events=None):
    if (type(label.get('schema_version')) is not int or label['schema_version'] != LABEL_SCHEMA
            or label.get('pair_schema') != 2 or label.get('origin') not in ('independent_review', 'subagent_review')
            or not session
            or label.get('session_id') != session or label.get('apk_sha256') != apk_sha
            or label.get('sample_origin') != sample_origin or sample_origin not in SAMPLE_ORIGINS):
        reject('标签版本、签核状态、APK、会话或样本来源不匹配。')
    try:
        mode = label_mode(label)
    except ValueError as exc:
        reject('标签版本、签核状态无效：' + str(exc))
    evidence = reference_identity(label.get('reference_evidence'), root)
    if refs is not None and evidence != reference_identity(refs, root):
        reject('标签参考证据与本案例绑定的独立参考不一致。')
    universe, controls = set(), set()
    for entry in label.get('universe') or []:
        if not isinstance(entry, dict):
            reject('配对评估范围格式无效。')
        pair = pair_key(entry.get('pair'))
        if pair in universe or type(entry.get('negative_control')) is not bool:
            reject('配对评估范围重复或缺少负控标记。')
        if events is not None and (pair[1:3] not in events or pair[3:5] not in events):
            reject('配对引用了封存会话中不存在的事件。')
        universe.add(pair)
        if entry['negative_control']:
            controls.add(pair)
    if not universe:
        reject('没有经复核的配对范围。')
    reviews, adjudication = label.get('reviews'), label.get('adjudication')
    if (not isinstance(reviews, list) or len(reviews) != 2
            or not all(isinstance(review, dict) for review in reviews) or not isinstance(adjudication, dict)):
        reject('必须提供两份独立标注及一份仲裁记录。')
    people = [*reviews, adjudication]
    typed = any('reviewer_kind' in record for record in people)
    if mode == 'subagent':
        try:
            validate_agents(people)
        except ValueError as exc:
            reject(str(exc))
        if label.get('reviewer_kind') != 'subagent':
            reject('subagent 标签必须明确标注签核来源。')
        if any(label.get(key) != adjudication.get(key) for key in (
                'reviewer', 'reviewer_kind', 'reviewed_at', 'agent_id', 'context_mode', 'review_session_id')):
            reject('subagent 签核身份与仲裁记录不一致。')
    elif label.get('reviewer_kind') not in (None, 'human') or (
            typed and any(record.get('reviewer_kind') != 'human' for record in people)):
        reject('AI 或身份未确认的复核记录不能用于人工签核计分。')
    if len({_person(record) for record in people}) != 3:
        reject('两位标注人与仲裁人必须分别具名。')
    first, second = (_decisions(review, universe) for review in reviews)
    disagreements = {pair for pair in universe if first[pair] != second[pair]}
    resolved = _decisions(adjudication, disagreements)
    positives = {pair for pair in universe if resolved.get(pair, first[pair])}
    if positives & controls:
        reject('已确认负控与仲裁后的正例冲突。')
    if 'expected_pairs' in label:
        expected = label['expected_pairs']
        if (not isinstance(expected, list) or len(expected) != len(positives)
                or {pair_key(pair) for pair in expected} != positives):
            reject('expected_pairs 必须与双人标注和仲裁确定的正例一致。')
    return {'universe': universe, 'positive': positives, 'negative_controls': controls,
            'label_origin': label['origin'], 'review_mode': mode,
            'reviewer_a': first, 'reviewer_b': second, 'label_set_sha256': canonical_sha(label)}
