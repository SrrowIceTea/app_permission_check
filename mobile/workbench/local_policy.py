"""Bind an uploaded APK to pre-collected local policy; never fetch during analysis."""
from __future__ import annotations
from mobile.policy import policy_library, policy_lint
from mobile.workbench.store import read_json, write_json


def bind(runtime, task_id):
    task = runtime.store.get(task_id)
    app = task['apk']
    policy = policy_library.load_policy(package=app.get('package') or '',
        version_code=app.get('version_code'), apk_sha256=app.get('sha256'))
    if policy.get('available'):
        policy['lint'] = policy_lint.lint(policy['text'],
            policy_lint.load_requirements(runtime.rules, runtime.version), policy.get('cjk_ratio') or 0)
        policy['disclosure_scan'] = policy_lint.disclosure_scan(policy['text'], policy_lint.load_keywords())
    write_json(runtime.store.task_dir(task_id) / 'policy.json', policy)
    runtime.store.patch(task_id, policy_available=policy.get('available') is True)
    return policy


def envelope(store, task):
    """Policy-only view, not a capture or a fabricated session on disk."""
    policy = read_json(store.task_dir(task['id']) / 'policy.json')
    if not policy or not policy.get('available'):
        return None
    return {'bundle_version': '1', 'app': task['apk'], 'rules': task['rules'],
            'policy': policy, 'dynamic': {'reads': [], 'consent_timeline': [], 'hook_health': {}},
            'traffic': {'flows': []}, 'findings': [], 'counts': {},
            'gaps': ['尚未执行动态采集；这里只提供预先保存且绑定本 APK 的本地政策。']}
