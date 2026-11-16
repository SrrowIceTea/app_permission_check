"""结论行复核结果：每任务一文件，原子写 + 进程内串行。

仅用于授权测试。这里只存"谁在什么时候对哪条 finding_uid 做了什么复核"，
不写回 audit 产物、不改变 conclusion_level；reviewer 只能是人。
"""
import json
import os
import re
import threading
import uuid
from pathlib import Path

from vehicle.pipeline.contracts import AuditError

SCHEMA = 1
STATUSES = ('confirmed', 'rejected', 'needs_more_evidence')
HUMAN = 'human'
FIELDS = ('finding_uid', 'status', 'reviewer_kind', 'reviewer', 'reviewed_at', 'note')
MAX_NOTE = 500
MAX_REVIEWER = 100
TIME = re.compile(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2})?(\.\d+)?(Z|[+-]\d{2}:\d{2})')
_LOCKS, _GUARD = {}, threading.Lock()


def path_for(out):
    return Path(out) / 'review/finding-review.json'


def _lock_for(path):
    with _GUARD:
        return _LOCKS.setdefault(str(path), threading.Lock())


def load(path):
    """返回复核文档；没有文件时 None。结构非法时抛错，绝不返回半截数据。"""
    path = Path(path)
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding='utf-8'))
    except (OSError, ValueError) as error:
        raise AuditError('review_unreadable', '复核文件无法解析。',
                         '人工检查 review/finding-review.json 是否为合法 JSON；未见过的复核记录不会被覆盖。'
                         ) from error
    if not isinstance(data, dict) or not isinstance(data.get('findings'), dict):
        raise AuditError('review_invalid', '复核文件结构无效。',
                         'findings 必须是 finding_uid → 记录的字典，先修正该文件。')
    return data


def _reject(code, message, next_action):
    raise AuditError(code, message, next_action)


def validate(record, allowed_uids):
    """写入前校验；任何一条不满足都拒绝，不做"尽量写入"。"""
    if not isinstance(record, dict):
        _reject('review_invalid', '复核请求必须是 JSON 对象。', '按字段契约提交。')
    extra = sorted(set(record) - set(FIELDS))
    if extra:
        _reject('review_unknown_field', '复核请求包含未定义字段：%s。' % '、'.join(extra),
                '只提交 finding_uid/status/reviewer_kind/reviewer/reviewed_at/note。')
    uid = record.get('finding_uid')
    if not isinstance(uid, str) or uid not in allowed_uids:
        _reject('unknown_finding_uid', '本轮结论里没有这个 finding_uid。',
                '从 /findings 取当前任务的 finding_uid 再提交。')
    if record.get('status') not in STATUSES:
        _reject('review_invalid_status', 'status 只能是 %s。' % ' / '.join(STATUSES),
                '检查 status 取值；未复核的行不写记录，读取时自然为 null。')
    if record.get('reviewer_kind') != HUMAN:
        # 与 labels.py 一致：AI/自动标注不得进入人工签核路径。
        _reject('reviewer_kind_rejected', 'reviewer_kind 必须是人（human）；AI 或自动来源不得写入人工复核。',
                '由人工复核后以 reviewer_kind=human 提交，或走独立 AI 复核字段。')
    reviewer = record.get('reviewer')
    if not isinstance(reviewer, str) or not reviewer.strip() or len(reviewer.strip()) > MAX_REVIEWER:
        _reject('review_invalid_reviewer', 'reviewer 必须是 1–%d 字的真实复核人。' % MAX_REVIEWER,
                '填写人工复核人姓名或工号。')
    if any(character < ' ' for character in reviewer):
        _reject('review_invalid_reviewer', 'reviewer 含控制字符。', '重新填写复核人。')
    when = record.get('reviewed_at')
    if not isinstance(when, str) or not TIME.fullmatch(when):
        _reject('review_invalid_time', 'reviewed_at 必须是带时区的 ISO 8601，例如 2026-11-10T12:00:00+08:00。',
                '按契约补上带时区的复核时间。')
    note = record.get('note')
    if note is not None and (not isinstance(note, str) or len(note) > MAX_NOTE):
        _reject('review_invalid_note', 'note 必须是不超过 %d 字的字符串。' % MAX_NOTE, '精简复核说明。')
    return {'status': record['status'], 'reviewer_kind': HUMAN, 'reviewer': reviewer.strip(),
            'reviewed_at': when, 'note': note}


def _write(path, data):
    """临时文件 + 替换：失败只可能留下临时文件，正式文件要么旧要么新。"""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.parent / ('.%s.%s.tmp' % (path.name, uuid.uuid4().hex))
    try:
        with temporary.open('w', encoding='utf-8') as handle:
            handle.write(json.dumps(data, ensure_ascii=False, indent=2) + '\n')
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            temporary.unlink(missing_ok=True)
        except OSError as cleanup_error:
            print(f'[finding_reviews] 临时文件清理失败（不覆盖原始异常）: '
                  f'{type(cleanup_error).__name__}: {cleanup_error}', flush=True)
        raise


def save(path, record, allowed_uids):
    """读-改-写在锁内完成：并发提交不同 finding 的记录不会互相覆盖。"""
    path = Path(path)
    entry = validate(record, allowed_uids)
    with _lock_for(path):
        data = load(path) or {'schema_version': SCHEMA, 'findings': {}}
        data['schema_version'] = SCHEMA
        data.setdefault('findings', {})[record['finding_uid']] = entry
        _write(path, data)
    return entry


def attach(rows, document, error=None):
    """把复核记录合并到结论行；没有记录时显式 null + 原因，不默认 pending。"""
    records = (document or {}).get('findings') if isinstance(document, dict) else None
    records = records if isinstance(records, dict) else {}
    for row in rows:
        uid = row.get('finding_uid')
        record = records.get(uid) if uid else None
        if not isinstance(record, dict):
            row['review_status'] = None
            row['reviewer'] = None
            row['reviewed_at'] = None
            row['review_note'] = None
            row['review_status_reason'] = error or '该结论行没有复核记录，不能当作已复核。'
            continue
        row['review_status'] = record.get('status')
        row['reviewer'] = record.get('reviewer')
        row['reviewed_at'] = record.get('reviewed_at')
        row['review_note'] = record.get('note')
        row['review_status_reason'] = None
    return rows
