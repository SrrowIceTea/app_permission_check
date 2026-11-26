"""Read persisted pipeline jobs without re-running a detector. 仅用于授权测试。"""
import re
import os
from mobile.workbench.audit_process import creation_token
from pathlib import Path
from types import SimpleNamespace
from mobile.workbench.store import read_json,write_json


def remember(job):
    write_json(job.out/'pipeline.json',{'id':job.id,'name':job.name,'state':job.state,
        'error':job.error,'apk':str(job.apk),'result':job.result,
        'options':getattr(job,'options',None),'apk_sha256':getattr(job,'apk_sha256',None),
        'retry_of':getattr(job,'retry_of',None),
        'owner_pid':os.getpid(),'owner_token':creation_token(os.getpid())})


def lookup(registry,job_id):
    if not re.fullmatch(r'[a-f0-9]{12}',job_id):return None
    if job_id in registry._jobs:return registry._jobs[job_id]
    directory=registry.workdir/job_id
    value=read_json(directory/'pipeline.json',{})
    if value.get('id')!=job_id:return None
    if value.get('state') in ('queued','running'):
        try: alive = bool(value.get('owner_token')) and creation_token(value['owner_pid']) == value['owner_token']
        except (OSError, KeyError, ValueError): alive = False
        if not alive:
            value.update(state='failed',error='服务重启，运行中任务已中断；本轮不得当作成功',interrupted=True)
    job=SimpleNamespace(**value,out=directory,events=directory/'events.jsonl')
    job.apk=directory/'uploaded.apk'
    if registry.runtime and job.result.get('task_id'):
        task=registry.runtime.store.get(job.result['task_id'])
        if task:job.static_dir=registry.runtime.store.cache_dir(task)
    return job


def catalog(registry):
    ids=set(registry._jobs.copy())
    ids.update(p.parent.name for p in registry.workdir.glob('*/pipeline.json'))
    values=[]
    for job_id in ids:
        job=lookup(registry,job_id)
        if job:
            values.append({'id':job.id,'name':job.name,'state':job.state,'error':job.error,
                'retry_of':getattr(job,'retry_of',None),
                'result':job.result,'updated_at':(job.out/'pipeline.json').stat().st_mtime})
    return sorted(values,key=lambda x:x['updated_at'],reverse=True)
