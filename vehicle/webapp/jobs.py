"""Durable jobs, atomic admission and retained failures. 授权测试专用。"""
import json
import shutil
import threading
import time
import traceback
import uuid
from pathlib import Path

from vehicle.pipeline.contracts import AuditError, read_json, write_json

STAGES = [{'id': key, 'label': label} for key, label in (
    ('static', '车载规则静态分析'), ('decompile', '反编译源码'),
    ('capture', 'AAOS 设备采集'), ('audit', '证据校验与关联审计'),
    ('dashboard', '审计看板与报告'))]
TERMINAL = {'done', 'static_only', 'failed'}


def options(query, catalog):
    def value(key, default=''):
        return query.get(key, [default])[0]
    mode = value('mode', 'static')
    if mode not in ('static', 'replay', 'live'):
        raise AuditError('invalid_mode', '未知的审计模式。', '重新选择审计方式。')
    if value('authorized') != 'true':
        raise AuditError('authorization_required', '请确认当前 APK 和设备的测试授权。',
                         '勾选授权声明后再上传。')
    result = {'mode': mode, 'version': '15'}
    result['version'] = value('version', '15')
    if result['version'] not in ('13', '14', '15', '16'):
        raise AuditError('invalid_version', '不支持的 Android 规则版本。', '选择 13–16 的对应规则版本。')
    if value('attachment_id'):
        result['attachment_id'] = value('attachment_id')
    if 'ai_review' in query:
        if value('ai_review') not in ('true', 'false'):
            raise AuditError('invalid_switch', 'AI 开关必须是 true/false。', '重新选择辅助复核设置。')
        result['ai_review'] = value('ai_review') == 'true'
    if mode == 'replay':
        result['capture'] = str(catalog.resolve(value('capture')))
    if mode == 'live':
        import re
        serial = value('serial')
        if not re.fullmatch(r'[A-Za-z0-9_.:-]{1,100}', serial):
            raise AuditError('invalid_device', '设备序列号无效。', '填写已连接的授权 AAOS 序列号。')
        try:
            user, seconds = int(value('user', '10')), int(value('seconds', '30'))
        except ValueError as error:
            raise AuditError('invalid_duration', '用户编号或时长无效。', '填写整数。') from error
        if user < 0 or not 5 <= seconds <= 300:
            raise AuditError('invalid_duration', '采集时长须为 5–300 秒，用户编号须非负。', '修改采集参数。')
        result.update(serial=serial, user=user, seconds=seconds)
        scope = value('scope', 'all')
        if scope not in ('all', 'general') or (scope == 'all' and result['version'] != '15'):
            raise AuditError('invalid_scope', '完整车辆范围只验证了 Android 15；其他版本请选择通用来源。', '调整采集范围。')
        result['scope'] = scope
        for key, default in (('tls_bypass', 'false'), ('multi_process', 'true')):
            if value(key, default) not in ('true', 'false'):
                raise AuditError('invalid_switch', '采集开关必须是 true/false。', '重新选择采集设置。')
            result[key] = value(key, default) == 'true'
    return result


class Job:
    def __init__(self, out, data):
        self.out, self.data = Path(out), data
        self.lock = threading.RLock()

    def save(self):
        with self.lock:
            write_json(self.out / 'job.json', self.data)

    def snapshot(self):
        with self.lock:
            return json.loads(json.dumps(self.data))

    def event(self, stage, status, message):
        with self.lock:
            row = {'ts': time.time(), 'stage': stage, 'status': status, 'message': message}
            with (self.out / 'events.jsonl').open('a', encoding='utf-8') as handle:
                handle.write(json.dumps(row, ensure_ascii=False) + '\n')

    def finish(self, state, result):
        with self.lock:
            self.data.update(state=state, result=result)
            self.save()


class Registry:
    def __init__(self, root, catalog, ai_config=None, worker=None):
        from vehicle.webapp.workflow import run
        self.root, self.catalog = Path(root).resolve(), catalog
        self.ai_config, self.worker = ai_config, worker or run
        self.root.mkdir(parents=True, exist_ok=True)
        from vehicle.webapp.lease import Lease
        self.lease = Lease(self.root / '.service.lock')
        self.lock, self.jobs, self.threads = threading.RLock(), {}, []
        self.accepting = True
        for path in self.root.glob('v-*/job.json'):
            data = read_json(path)
            job = Job(path.parent, data)
            if data['state'] not in TERMINAL:
                job.finish('failed', {'error': {'code': 'service_interrupted',
                    'message': '服务在上次审计完成前退出，结果不完整。',
                    'next_action': '保留本轮证据；检查设备与代理状态后新建审计。'}})
            self.jobs[data['id']] = job

    def submit(self, uploaded, name, settings, retry_of=None):
        with self.lock:
            if settings.get('ai_review') and not self.ai_config:
                raise AuditError('ai_not_configured', '服务尚未配置 AI，不能执行辅助复核。', '先关闭辅助复核，或由服务启动配置模型。')
            if not self.accepting or any(j.data['state'] not in TERMINAL for j in self.jobs.values()):
                raise AuditError('service_busy', '当前审计仍在运行。', '等待本轮结束后再新建。')
            identity = 'v-' + uuid.uuid4().hex
            out = self.root / identity
            out.mkdir()
            settings = dict(settings)
            if retry_of is not None and (retry_of.out / 'inputs').is_dir():
                shutil.copytree(retry_of.out / 'inputs', out / 'inputs')
            elif settings.get('attachment_id'):
                from vehicle.webapp.attachments import copy_into
                settings.update(copy_into(self.root, settings['attachment_id'], out))
            shutil.move(str(uploaded), str(out / 'uploaded.apk'))
            job = Job(out, {'id': identity, 'name': name, 'state': 'queued',
                           'created': time.time(), 'options': settings, 'result': {}})
            if retry_of is not None:
                job.data['retry_of'] = retry_of.data['id']
            job.save()
            self.jobs[identity] = job
            thread = threading.Thread(target=self._execute, args=(job,), name=identity)
            self.threads.append(thread)
            thread.start()
            return job

    def _execute(self, job):
        stage = 'static'
        try:
            job.data['state'] = 'running'
            job.save()
            self.worker(job, self.ai_config)
        except BaseException as error:
            (job.out / 'failure.log').write_text(traceback.format_exc(), encoding='utf-8')
            events = (job.out / 'events.jsonl')
            if events.exists():
                rows = [json.loads(r) for r in events.read_text(encoding='utf-8').splitlines()]
                if rows:
                    stage = rows[-1]['stage']
            detail = error.record() if isinstance(error, AuditError) else {
                'code': 'workflow_failed', 'message': '审计未完成，失败日志已保留。',
                'next_action': '查看本轮 failure.log，修复原因后新建审计。'}
            job.event(stage, 'failed', detail['message'])
            job.finish('failed', {'error': detail})

    def get(self, identity):
        with self.lock:
            return self.jobs.get(identity)

    def snapshot(self, job):
        """对外快照：在原 job.json 字段上补身份、分档计数与阶段耗时。"""
        from vehicle.webapp.presentation import decorate
        return decorate(job.snapshot(), job.out, STAGES)

    def rows(self):
        with self.lock:
            jobs = list(self.jobs.values())
        return sorted((self.snapshot(j) for j in jobs), key=lambda r: r['created'], reverse=True)

    def close(self):
        with self.lock:
            self.accepting = False
        for thread in self.threads:
            thread.join()
        self.lease.close()
