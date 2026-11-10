"""Serve only named job artifacts; no arbitrary disk reads or mixed-session fallback."""
import json
from pathlib import Path

from core.static import jadx
from vehicle.pipeline.contracts import AuditError
from vehicle.webapp import finding_reviews
from vehicle.webapp.presentation import finding_uids, project_summary
from vehicle.webapp.rule_titles import resolve
from vehicle.webapp.workflow import RULES


def document(path):
    if not path.is_file():
        raise AuditError('artifact_missing', '当前任务尚无此项产物。', '等待对应阶段完成或查看失败原因。')
    return json.loads(path.read_text(encoding='utf-8'))


def rows_of(out):
    """读取 audit/findings.jsonl 原始行；文件还没生成时返回空列表。"""
    path = Path(out) / 'audit/findings.jsonl'
    if not path.is_file():
        return []
    return [json.loads(line) for line in path.read_text(encoding='utf-8').splitlines() if line.strip()]


def with_titles(rows, version):
    """只读 join 规则标题：中文优先取展示层映射，未映射回退库内原值，都取不到给 None + 原因。"""
    resolved, reasons, basis = resolve(RULES, version)
    for row in rows:
        rule_id = row.get('rule_id')
        label = resolved.get(rule_id)
        if label:
            row['rule_title'] = label['title']
            row['rule_title_locale'] = label['locale']
            row['rule_title_source'] = label['source']
            if rule_id in reasons:
                row['rule_title_source'] += '；' + reasons[rule_id]
            continue
        row['rule_title'] = None
        row['rule_title_locale'] = None
        row['rule_title_source'] = reasons.get(rule_id) or (
            '结论行没有 rule_id。' if not rule_id else '规则库 risk_rules 没有该 rule_id。')
    return rows


def review_rows(rows, out):
    """合并复核记录；文件损坏时逐行标原因，不让整个 findings 视图崩掉。"""
    try:
        return finding_reviews.attach(rows, finding_reviews.load(finding_reviews.path_for(out)))
    except AuditError as error:
        return finding_reviews.attach(rows, None, '复核文件不可用：%s' % error)


def findings(rows, out, version):
    for row, uid in zip(rows, finding_uids(rows)):
        row['finding_uid'] = uid
    return review_rows(with_titles(rows, version), out)


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
    if action == 'finding-reviews':
        document_reviews = finding_reviews.load(finding_reviews.path_for(out))
        return handler.json(document_reviews or {'schema_version': finding_reviews.SCHEMA, 'findings': {}})
    # A completed internal summary is not a completed web workflow after a later failure.
    if state != 'done':
        raise AuditError('audit_not_completed', '动态审计尚未完整完成。', '查看任务状态；静态结果仍可单独查看。')
    if action == 'summary':
        return handler.json(project_summary(document(out / 'audit/summary.json')))
    if action == 'findings':
        version = (job.data.get('options') or {}).get('version')
        summary = out / 'audit/summary.json'
        if summary.is_file():
            version = document(summary).get('android_version') or version
        return handler.json(findings(rows_of(out), out, version))
    if action == 'report':
        return handler.file(out / 'audit/vehicle-audit.pdf', 'application/pdf')
    if action == 'dashboard':
        return handler.file(out / 'audit/dashboard.html', 'text/html; charset=utf-8')
    if action == 'bundle':
        # The relocatable evidence manifest names and hashes the retained bundle files.
        return handler.json(document(out / 'audit/summary.json'))
    raise AuditError('unknown_artifact', '未知的产物类型。', '从工作台结果页重新打开。')
