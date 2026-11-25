"""Explicit retries and bounded per-job diagnostics. 仅用于授权测试。"""
import tempfile
import shutil
from pathlib import Path
from vehicle.pipeline.contracts import AuditError
from vehicle.webapp.jobs import options


def retry(registry, job, query):
    original = job.snapshot()
    if original['state'] != 'failed':
        raise AuditError('retry_not_failed', '只有失败任务可以重试。', '正在运行的任务请等待结束。')
    # Browser must explicitly authorize this new operation, even for a retained APK.
    selected = dict(query)
    previous = original['options']
    for key in ('mode', 'version', 'scope', 'tls_bypass', 'multi_process', 'serial', 'user', 'seconds', 'ai_review',
                'auto_explore'):
        if key in previous:
            value = str(previous[key]).lower() if isinstance(previous[key], bool) else str(previous[key])
            selected.setdefault(key, [value])
    if selected.get('mode', ['static'])[0] == 'replay' and not selected.get('capture', [''])[0]:
        path = Path(previous.get('capture', ''))
        match = next((key for key, value in registry.catalog.paths.items() if value == path), '')
        selected['capture'] = [match]
    settings = options(selected, registry.catalog)
    for key in ('policy', 'scenarios'):
        if previous.get(key):
            settings[key] = previous[key]
    apk = job.out / 'uploaded.apk'
    if not apk.is_file():
        raise AuditError('retry_apk_missing', '失败任务未保留完整 APK。', '重新选择授权 APK 上传。')
    with tempfile.TemporaryDirectory(dir=registry.root, prefix='retry-') as temporary:
        target = Path(temporary) / 'uploaded.apk'
        shutil.copyfile(apk, target)
        return registry.submit(target, original['name'], settings, retry_of=job)


def logs(job):
    records = []
    for name in ('failure.log', 'events.jsonl', 'static/jadx.log', 'capture/reads.log', 'capture/mitm.log'):
        path = job.out / name
        if not path.is_file():
            continue
        with path.open('rb') as handle:
            size = path.stat().st_size
            handle.seek(max(0, size - 32768))
            text = handle.read(32768).decode('utf-8', errors='replace')
        records.append({'name': name, 'text': text, 'truncated': size > 32768})
    return {'job_id': job.data['id'], 'state': job.snapshot()['state'], 'logs': records,
            'note': '仅当前任务日志尾部；原始日志保留在本机，不发布为审计结论。'}
