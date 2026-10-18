"""Rebind retained live AI before report regeneration. 仅用于授权测试；不调用模型。"""
from __future__ import annotations
import shutil
from pathlib import Path
from mobile.ai.review_gates import load_checked_stages
from mobile.workbench.core_publish import check_live_calls
from mobile.workbench.device_bridge import sha
from mobile.workbench.store import ROOT, read_json

STAGES = ('static', 'policy', 'capture', 'correlate', 'bundle', 'ai', 'report')


def checked_calls(ai_dir, bundle):
    stages, validation = load_checked_stages(ai_dir, bundle)
    if (set(stages) != {'stage1', 'stage2', 'stage3'} or
            set(validation) != set(stages) or not all(v['ok'] for v in validation.values())):
        raise ValueError('已有 AI 三阶段绑定失效或缺失，拒绝降级为工具报告')
    return check_live_calls(ai_dir, stages, bundle)


def snapshot(task, bundle_path, bundle, attempt):
    """None only means a task never claimed formal live AI, not failed AI binding."""
    core = task.get('core_run') or {}
    wants_live = (task.get('ai_state') == 'live_validated' or
                  (task.get('report_metadata') or {}).get('ai_state') == 'live_validated' or
                  core.get('state') == 'done')
    if not wants_live:
        return None
    source = core.get('source_run')
    if not isinstance(source, str) or not source:
        raise ValueError('已有在线 AI 缺少核心运行来源，拒绝降级为工具报告')
    run = Path(source).resolve()
    if not run.is_relative_to((ROOT / 'output').resolve()):
        raise ValueError('已有 AI 来源不属于项目保留产物')
    verification = read_json(run / 'verification.json', {})
    app = task.get('apk') or {}
    if (core.get('state') != 'done' or verification.get('passed') is not True or
            verification.get('task_id') != task['id'] or
            verification.get('package') != app.get('package') or
            verification.get('apk_sha256') != app.get('sha256') or
            any(verification.get('stages', {}).get(s, {}).get('state') != 'done' for s in STAGES)):
        raise ValueError('已有 AI 核心运行未通过或原包/任务身份不一致')
    source_bundle = run / 'out/bundle.json'
    if not source_bundle.is_file() or sha(source_bundle) != sha(bundle_path):
        raise ValueError('已有 AI 源证据包与当前证据文件不完全一致')
    checked_calls(run / 'out/ai', bundle)
    retained = attempt / 'report-ai'
    shutil.copytree(run / 'out/ai', retained)
    calls = checked_calls(retained, bundle)
    return {'directory': retained, 'source_run': str(run), 'request_count': len(calls),
            'validation_repairs': sum(c['tag'].endswith('-repair1') for c in calls)}
