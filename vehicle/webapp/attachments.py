"""Explicit, bounded evidence uploads; never rewrite policy/session bindings.

仅用于授权测试。Files are copied into each job before execution. Uploading an
input does not validate its semantics: the existing audit validators own that.
"""
import base64
import binascii
import re
import shutil
import uuid
from pathlib import Path, PurePosixPath

from vehicle.pipeline.contracts import AuditError

MAX_BODY = 6 * 1024 * 1024
MAX_FILES = 64
MAX_BYTES = 4 * 1024 * 1024


def reject(message):
    raise AuditError('invalid_attachment', message, '选择本轮政策清单/正文或场景清单/回执，保留原始摘要与身份。')


def create(root, record):
    if not isinstance(record, dict) or not isinstance(record.get('files'), list):
        reject('附件必须是文件列表。')
    files, total = {}, 0
    if not 1 <= len(record['files']) <= MAX_FILES:
        reject('每轮附件须为 1–64 个文件。')
    for row in record['files']:
        if not isinstance(row, dict) or not isinstance(row.get('path'), str):
            reject('附件文件名无效。')
        name = row['path']
        path = PurePosixPath(name)
        if (not name or not path.parts or len(name) > 200 or '\\' in name or ':' in name or path.is_absolute()
                or '..' in path.parts or path.as_posix() != name or name.casefold() in {n.casefold() for n in files}
                or any(p.rstrip(' .') != p or re.fullmatch(r'(?i)(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?', p)
                       for p in path.parts)):
            reject('附件路径无效或重复。')
        try:
            raw = base64.b64decode(row.get('content_base64', ''), validate=True)
        except (ValueError, TypeError, binascii.Error):
            reject('附件内容不是合法 base64。')
        total += len(raw)
        if total > MAX_BYTES:
            reject('附件总大小超过 4 MiB。')
        files[name] = raw
    selected = {key: record.get(key) for key in ('policy', 'scenarios') if record.get(key)}
    if not selected or any(not isinstance(v, str) or v not in files for v in selected.values()):
        reject('请选择已上传的政策或场景入口文件。')
    parent = Path(root) / '.attachments'
    parent.mkdir(exist_ok=True)
    if len(list(parent.iterdir())) >= 128:
        reject('附件暂存已满，请重启独立工作目录或复用已提交任务。')
    identity = 'a-' + uuid.uuid4().hex
    target = parent / identity
    target.mkdir()
    from vehicle.pipeline.contracts import write_json
    for name, raw in files.items():
        path = target / 'files' / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
    write_json(target / 'selection.json', selected)
    return {'id': identity, 'files': len(files), 'bytes': total}


def copy_into(root, identity, out):
    if not isinstance(identity, str) or not re.fullmatch(r'a-[0-9a-f]{32}', identity):
        reject('附件编号无效。')
    from vehicle.pipeline.contracts import read_json
    source = Path(root) / '.attachments' / identity
    if not source.is_dir():
        reject('附件暂存不存在，请重新选择文件。')
    selection = read_json(source / 'selection.json')
    shutil.copytree(source / 'files', Path(out) / 'inputs')
    return {key: 'inputs/' + value for key, value in selection.items()}
