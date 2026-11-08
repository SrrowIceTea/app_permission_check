"""Serve only named job artifacts; no arbitrary disk reads or mixed-session fallback."""
import json

from core.static import jadx
from vehicle.pipeline.contracts import AuditError


def document(path):
    if not path.is_file():
        raise AuditError('artifact_missing', '当前任务尚无此项产物。', '等待对应阶段完成或查看失败原因。')
    return json.loads(path.read_text(encoding='utf-8'))


def serve(handler, job, action, query):
    out = job.out
    state = job.snapshot()['state']
    if action == 'static':
        return handler.json(document(out / 'static/static.json'))
    if action == 'tree':
        path = jadx.index_json(out / 'static')
        return handler.json(document(path) if path.exists() else [])
    if action == 'source':
        try:
            data = jadx.read_source(out / 'static', query.get('path', [''])[0])
        except ValueError as error:
            raise AuditError('invalid_source_path', '源码路径越界。', '从当前文件树选择源码。') from error
        return handler.json(data)
    if action == 'decompile':
        return handler.json(document(out / 'static/decompile.json'))
    # A completed internal summary is not a completed web workflow after a later failure.
    if state != 'done':
        raise AuditError('audit_not_completed', '动态审计尚未完整完成。', '查看任务状态；静态结果仍可单独查看。')
    if action == 'summary':
        return handler.json(document(out / 'audit/summary.json'))
    if action == 'findings':
        rows = (out / 'audit/findings.jsonl').read_text(encoding='utf-8').splitlines()
        return handler.json([json.loads(row) for row in rows if row.strip()])
    if action == 'report':
        return handler.file(out / 'audit/vehicle-audit.pdf', 'application/pdf')
    if action == 'dashboard':
        return handler.file(out / 'audit/dashboard.html', 'text/html; charset=utf-8')
    if action == 'bundle':
        # The relocatable evidence manifest names and hashes the retained bundle files.
        return handler.json(document(out / 'audit/summary.json'))
    raise AuditError('unknown_artifact', '未知的产物类型。', '从工作台结果页重新打开。')
