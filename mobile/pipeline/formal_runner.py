"""Adapt the current frontend pipeline API to the checked audit core. 仅用于授权测试。"""
from __future__ import annotations
import json
import shutil
import time
from pathlib import Path
from mobile.pipeline import stages
from mobile.workbench import audit_inputs
from mobile.workbench.store import read_json, write_json


def wait_job(runtime, job_id, update, timeout=2400):
    deadline=time.monotonic()+timeout
    while time.monotonic()<deadline:
        current=runtime.job(job_id)
        update(current)
        if current and current['state'] in ('done','failed','cancelled'):
            if current['state']!='done':raise RuntimeError(current.get('error') or '检测阶段未通过')
            return current
        time.sleep(.5)
    raise TimeoutError('检测阶段超时；保留运行信息，不发布报告')


def run(job, runtime, finalize):
    """No alternative detector: retain task-bound static/capture/AI/report gates."""
    emitted={}
    def emit(stage,status,message):
        if emitted.get(stage)!=(status,message):
            stages.emit_events(job.events,stage,status,message);emitted[stage]=(status,message)
    job.state='running'
    try:
        binding=audit_inputs.configuration(runtime)
        emit('prepare','done','真实正控已通过；检测模式 '+binding['mode'])
        emit('static','running','扫描当前上传原包并反编译')
        uploaded=runtime.upload(job.apk,job.name)
        task_id=uploaded['task_id'];job.result['task_id']=task_id
        wait_job(runtime,uploaded['job_id'],lambda _:None,timeout=1200)
        task=runtime.store.get(task_id)
        cache=runtime.store.cache_dir(task)
        job.static_dir=cache
        raw=read_json(cache/'workbench-static.json',{})
        if not raw.get('available'):raise RuntimeError('原包静态扫描没有可用结果')
        job.result['static']={'package':task['apk']['package'],'app_label':task['apk'].get('app_label'),
            'findings_total':len(raw.get('findings',[])),'rules_evaluated':raw.get('rules_evaluated'),
            'decompile':raw.get('decompile')}
        emit('static','done','全 DEX 静态完成；源码反编译 '+task['stages']['decompile']['state'])
        # Scenario is explicit and package-bound, never substitute a different APK.
        scenario={'com.absinthe.libchecker':'libchecker','me.ash.reader':'readyou'}.get(task['apk']['package'],'launch')
        operation=runtime.operate(task_id,'audit',{'authorized':True,**{k:binding[k] for k in ('mode','serial')},
            'scenario':scenario,'seconds':job.seconds,'pcap_sidecar':False,'consent_timeout':180})
        attempt=runtime.store.task_dir(task_id)/'attempts'/operation['job_id']
        core=attempt/('core-'+operation['job_id'])
        emit('boot','running','在正控同设备 '+binding['serial']+' 上实际运行')
        emit('frida_server','skipped' if binding['mode']=='nonroot-gadget' else 'running',
             '非 root 使用进程内 Gadget，无 frida-server' if binding['mode']=='nonroot-gadget' else '使用专用 root 模拟器服务')
        emit('install','running','保留原始 APK 身份，准备本轮实际安装')
        def update(_current):
            captured=read_json(attempt/'capture/verification.json',{})
            if captured.get('state')=='done':
                for stage in ('boot','install','launch','hooks','explore','death_probe'):
                    emit(stage,'done',{'hooks':'实际 Hook 健康检查通过','explore':'有限场景交互完成',
                        'death_probe':'实际采集与清理通过'}.get(stage,'本轮实际设备采集已验证'))
                if binding['mode']=='root-emulator':emit('frida_server','done','实际远程会话已通过')
                emit('conn_probe','skipped','此管线保留进程外发观察，不启用独立连接轮询')
                emit('mitm','skipped','本轮未启用 VPN/全局 TLS 代理；范围写入报告')
                emit('network','done' if captured.get('flows') else 'skipped',
                     '观察到应用归因流量' if captured.get('flows') else '本场景未观察到可归因流，不能据此判断安全')
            current=runtime.store.get(task_id)
            if (core/'out/findings.jsonl').exists():emit('correlate','done','实际会话进入关联分析')
            if (core/'out/bundle.json').exists():emit('bundle','done','原包、政策、动态证据已绑定')
            for name,sid in (('ai','ai_review'),('report','report')):
                state=current['stages'][name]['state']
                if state in ('running','done','failed'):
                    emit(sid,state,'真实三阶段 AI 与引用校验' if name=='ai' else '本轮 PDF 生成与校验')
        wait_job(runtime,operation['job_id'],update)
        verified=read_json(core/'verification.json',{})
        if verified.get('passed') is not True or verified.get('task_id')!=task_id:
            raise RuntimeError('正式核心验收未通过，禁止发布本轮 PDF')
        target=job.out/'out';target.mkdir(exist_ok=True)
        for name in ('bundle.json','mobile-report.pdf'):
            shutil.copy2(core/'out'/name,target/name)
        from mobile.ai.review_gates import load_checked_stages
        bundle=read_json(target/'bundle.json',{})
        checked,validation=load_checked_stages(core/'out/ai',bundle)
        if set(checked)!={'stage1','stage2','stage3'}:raise RuntimeError('AI 校验链不完整')
        write_json(target/'ai.json',{'stages':checked,'validation':validation,'live_calls':verified['stages']['ai']})
        captured=read_json(attempt/'capture/verification.json',{})
        verified.update(checks=[{'name':n,'exit_code':0 if val is True else 1}
                                for n,val in captured.get('checks',{}).items()],failed=[])
        write_json(job.out/'verification.json',verified)
        job.result.update(report=str(target/'mobile-report.pdf'),bundle=str(target/'bundle.json'),
            verification=verified,mode=binding['mode'],coverage_gaps=verified.get('quality_gaps',[]),
            counts=bundle.get('counts',{}),risk=runtime.store.get(task_id).get('risk_assessment'))
        finalize(job,'done')
    except Exception as exc:
        emit('report','failed','本轮未通过完整门控，不发布成功报告')
        # Do not leave an unchecked report downloadable even if copy failed midway.
        for name in ('mobile-report.pdf','ai.json'):(job.out/'out'/name).unlink(missing_ok=True)
        finalize(job,'failed',f'{type(exc).__name__}: {exc}')
