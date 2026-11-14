"""Workbench action routes; no arbitrary paths or silent job re-execution."""
from vehicle.pipeline.contracts import AuditError
from vehicle.webapp import attachments, job_actions


def dispatch(handler, path, query, post):
    if post and path == '/api/attachments':
        if not handler.same_origin():
            raise AuditError('origin_required', '附件只接受本机工作台页面提交。', '从工作台上传本轮资料。')
        with handler.payload(attachments.MAX_BODY) as record:
            data = attachments.create(handler.registry.root, record)
        handler.json(data, 201)
        return True
    parts = path.strip('/').split('/')
    if len(parts) != 4 or parts[:2] != ['api', 'pipeline']:
        return False
    if not ((post and parts[3] == 'retry') or (not post and parts[3] == 'logs')):
        return False
    job = handler.registry.get(parts[2])
    if not job:
        handler.json({'error': {'code': 'not_found', 'message': '任务不存在。'}}, 404)
        return True
    if post:
        if not handler.same_origin():
            raise AuditError('origin_required', '重试只接受本机工作台页面提交。', '从失败任务重新发起。')
        with handler.payload() as record:
            if record != {}:
                raise AuditError('invalid_body', '重试请求体须为空 JSON 对象。', '从工作台重新提交。')
        new_job = job_actions.retry(handler.registry, job, query)
        handler.json(handler.registry.snapshot(new_job), 202)
    else:
        handler.json(job_actions.logs(job))
    return True
