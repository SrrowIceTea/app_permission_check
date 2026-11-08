"""Adapt the existing vehicle pipeline; never reuse MOB rules or mobile stages."""
from pathlib import Path
from types import SimpleNamespace

from vehicle.pipeline.contracts import AuditError, ROOT, digest, read_json

RULES = ROOT / 'vehicle/rules/rules_library/rules.db'


def step(job, stage, operation):
    job.event(stage, 'running', '执行中')
    value = operation()
    job.event(stage, 'done', '已完成')
    return value


def capture(job, package):
    import re
    from vehicle.pipeline.capture import capture_app
    from vehicle.pipeline.capture_device import Device
    if not re.fullmatch(r'[A-Za-z]\w*(?:\.\w+)+', package):
        raise AuditError('invalid_capture_target', 'APK 包名格式无效。', '选择有效的授权 APK。')
    settings = job.data['options']
    device = Device(settings['serial'])
    identity = device.ordinary_identity(package, settings['user'])
    if identity['installed_apk_sha256'] != digest(job.out / 'uploaded.apk'):
        raise AuditError('installed_apk_mismatch', '上传的 APK 与设备装机版本不一致。',
                         '在指定用户下安装同一授权 APK 后重新创建审计。')
    try:
        device.call('shell', 'pidof', package)
    except AuditError as error:
        if error.code == 'device_command_failed' and error.details.get('exit_code') == 1:
            raise AuditError('app_not_running', '未检测到运行中的授权 App，未启动采集。',
                             '确认设备连接，并在指定 AAOS 用户下打开目标 App 后新建审计。',
                             cause=error.record()) from error
        raise
    output = job.out / 'capture'
    result = capture_app(package, settings['serial'], settings['user'],
                         settings['seconds'], output)
    if result.get('passed') is not True:
        cause = result.get('error') or {}
        raise AuditError('capture_unhealthy', '采集健康校验未通过。' + cause.get('message', ''),
                         cause.get('next_action', '查看本轮 capture/verification.json；失败不能当作未发现风险。'),
                         capture_error=cause)
    return output


def run(job, ai_config=None):
    from core.static.analysis import scan_static, decompile
    from vehicle.pipeline.audit import run_audit
    from vehicle.dashboard.dashboard import build

    apk, output = job.out / 'uploaded.apk', job.out / 'static'
    output.mkdir()
    static = step(job, 'static', lambda: scan_static(apk, RULES, '15', output))
    def source():
        result = decompile(apk, output, threads=2) or {}
        if result.get('returncode') not in (None, 0) and not result.get('classes_written'):
            raise AuditError('decompile_failed', '反编译进程失败，未生成可用源码。',
                             '查看本轮 static/decompile.json 与工具日志；静态候选仍可单独查看。')
        return result
    step(job, 'decompile', source)
    settings = job.data['options']
    if settings['mode'] == 'static':
        for stage in ('capture', 'audit', 'dashboard'):
            job.event(stage, 'skipped', '仅静态分析；未执行动态采集与审计')
        job.finish('static_only', {'mode': 'static', 'package': static['apk']['package'],
                   'message': '静态分析完成；候选不代表运行时行为。',
                   'ai': {'status': 'skipped', 'reason': '仅静态分析未调用 AI。'}})
        return
    package = static['apk']['package']
    if settings['mode'] == 'live':
        import hashlib
        from vehicle.webapp.lease import Lease
        key = hashlib.sha256(settings['serial'].encode()).hexdigest()
        def collect():
            with Lease(ROOT / 'output/vehicle-web-locks' / (key + '.lock')):
                return capture(job, package)
        captured = step(job, 'capture', collect)
    else:
        captured = Path(settings['capture'])
        job.event('capture', 'skipped', '重放已有采集；未发起新设备操作')
    manifest = read_json(captured / 'session-manifest.json')
    version = manifest.get('device_sdk', '35')
    # All package, APK, rule, hook and session bindings are checked by run_audit.
    summary = step(job, 'audit', lambda: run_audit(captured, job.out / 'audit', package,
                   str(version), ai_config=ai_config, apk=apk))
    def dashboard():
        args = SimpleNamespace(findings=job.out / 'audit/findings.jsonl',
            summary=job.out / 'audit/summary.json', verify=None, rules=RULES)
        (job.out / 'audit/dashboard.html').write_text(build(args), encoding='utf-8')
    step(job, 'dashboard', dashboard)
    job.finish('done', {'mode': settings['mode'], 'package': package,
               'session': summary['capture_validation']['session_id'],
               'findings_total': summary['findings_total'],
               'ai': summary.get('ai_review'), 'report': True, 'dashboard': True,
               'message': '审计流程完成；结论等级与方法边界见证据。'})
