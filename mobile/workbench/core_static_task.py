"""Bind prior complete DEX evidence to a corpus APK task; source decompilation stays explicit."""
from __future__ import annotations
import hashlib
import re
import zipfile
from pathlib import Path
from core.static import static_rules
from mobile.tools.static_supplement import INTERNET_PERMISSION, supplement
from mobile.workbench import health, local_policy
from mobile.workbench.store import ROOT, Store, read_json, write_json
from mobile.workbench.static_adapter import _findings
from types import SimpleNamespace


def create(apk: Path, source: Path, storage: Path):
    source = source.resolve()
    if not source.is_relative_to(ROOT / 'output'):
        raise ValueError('static source must be retained project evidence')
    result = read_json(source / 'result.json', {})
    summary = result.get('static_summary') or {}
    with apk.open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    if result.get('apk_sha256') != digest or summary.get('whole_dex_scanned') is not True:
        raise ValueError('static source is incomplete or belongs to a different APK')
    raw = read_json(source / 'static/static.json', {})
    if raw.get('dex_gaps') or raw.get('apk', {}).get('package') != result.get('package'):
        raise ValueError('whole-DEX static source has gaps or mismatched package')
    original_facts = read_json(source / 'static/dexfacts.json')
    if not isinstance(original_facts, dict) or not isinstance(original_facts.get('method_refs'), list):
        raise ValueError('static source has no retained DEX method facts')
    with zipfile.ZipFile(apk) as archive:
        expected = {name for name in archive.namelist() if re.fullmatch(r'classes\d*\.dex', name)}
    if (original_facts.get('gaps') or not expected or
            expected != set(original_facts.get('per_dex_lines') or {})):
        raise ValueError('retained DEX facts have parse gaps or incomplete coverage')
    facts = {key: set(value) if isinstance(value, list) else value for key, value in original_facts.items()
             if key not in ('counts', 'per_dex_lines')}
    rules = ROOT / 'mobile/rules/rules_mobile.db'
    extra = supplement(facts, rules, '36', static_rules,
                       has_internet=INTERNET_PERMISSION in (
                           (raw.get('apk') or {}).get('permissions') or []))
    loaded = static_rules.load_rules(rules, '36')
    enabled = {r['rule_id']: r for r in loaded['rules'] if r['enabled']}
    evaluated = {rid for rid, rule in enabled.items() if rule['rule_type'] == 'over_permission'}
    evaluated.update(r['rule_id'] for r in extra['rules_considered'])
    core_findings = _findings(raw.get('findings', []), 'core_static', enabled)
    extra_findings = _findings(extra['findings'], 'mobile_supplement', enabled)
    store = Store(storage)
    app = {**raw['apk'], 'sha256': digest, 'name': apk.name}
    metadata = health.rules_info(rules, '36')
    task = store.create(mode='core_audit', origin='corpus_apk', name=result.get('case_id', apk.name), apk=app, rules=metadata)
    directory = store.task_dir(task['id'])
    payload = {'available': True, 'status': 'done', 'apk': app, 'rules': metadata,
        'findings': core_findings + extra_findings, 'core_findings': core_findings,
        'supplement_findings': extra_findings, 'core_rules_visited': raw.get('rules_evaluated'),
        'rules_loaded': metadata['count'], 'rules_evaluated': len(evaluated),
        'supplement_rules_considered': len(extra['rules_considered']),
        'supplement_downgraded': len(extra['downgraded_findings']),
        'supplement_internet_declared': extra['permissions']['internet_declared'],
        'coverage': {'supplement': extra['rules_considered'],
                     'unhandled_rule_types': raw.get('unhandled_rule_types', [])},
        'gaps': raw.get('dex_gaps', []) + raw.get('apk_gaps', []),
        'decompile': {'state': 'not_requested', 'reason': '本轮复用完整 DEX 事实，未将源码反编译冒充完成'},
        'source_evidence': str(source), 'whole_dex_scanned': True}
    write_json(directory / 'workbench-static.json', payload)
    store.stage(task['id'], 'static', 'done', '实际全 DEX 原始证据及本轮移动补充规则')
    store.stage(task['id'], 'decompile', 'not_requested', payload['decompile']['reason'])
    store.patch(task['id'], state='done', counts={**task['counts'], 'findings': len(payload['findings'])},
                static_evidence_source=str(source), gaps=payload['gaps'])
    local_policy.bind(SimpleNamespace(store=store, rules=rules, version='36'), task['id'])
    return store.get(task['id'])
