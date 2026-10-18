"""Read-only same-APK delivery index; never runs a device, scanner, model or publisher."""
from __future__ import annotations
import argparse
from datetime import datetime, timezone, timedelta
import json
from pathlib import Path
from mobile.lab.domestic_static import ready_entries
from mobile.policy.policy_library import DEFAULT_STORE, load_policy
from mobile.ai.review_gates import load_checked_stages
from mobile.workbench.core_publish import check_live_calls

ROOT = Path(__file__).resolve().parents[2]
STATIC = [ROOT / 'output' / name for name in
          ('root-benchmark-domestic-20261018', 'root-benchmark-domestic-retry-20261018')]


def read(path):
    try:
        value = json.loads(path.read_text(encoding='utf-8'))
        return value if isinstance(value, dict) else {}
    except (OSError, ValueError):
        return {}


def bound(value, entry):
    return value.get('package') == entry['package'] and value.get('apk_sha256') == entry['sha256']


def modified(value, path):
    stamp = value.get('completed_at', value.get('started_at'))
    try:
        return float(stamp) if isinstance(stamp, (int, float)) else datetime.fromisoformat(stamp.replace('Z', '+00:00')).timestamp()
    except (AttributeError, ValueError, TypeError):
        return path.stat().st_mtime


def failures(value):
    reasons = [str(value[k]) for k in ('error', 'blocked_reason') if value.get(k)]
    checks = value.get('checks') or {}
    reasons.extend('failed check: ' + key for key, status in checks.items() if status is not True)
    reasons.extend(str(x) for x in value.get('cleanup_errors') or [])
    return reasons


def inspect_static(folder, value):
    summary = value.get('static_summary') or {}
    raw, facts = read(folder / 'static/static.json'), read(folder / 'static/dexfacts.json')
    expected, parsed = set(summary.get('dex_names') or []), set(facts.get('per_dex_lines') or {})
    complete = (summary.get('whole_dex_scanned') is True and bool(expected) and expected == parsed
                and raw.get('apk', {}).get('package') == value.get('package')
                and isinstance(facts.get('method_refs'), list) and not facts.get('gaps') and not raw.get('dex_gaps'))
    return {'passed': complete, 'whole_dex': complete, 'dex_count': summary.get('dex_count'),
            'candidate_count': summary.get('candidate_count'),
            'reasons': [] if complete else failures(value) or ['whole-DEX evidence incomplete or missing']}


def inspect_capture(folder, value):
    checks = value.get('checks') or {}
    complete = (value.get('state') == 'done' and bool(checks) and all(v is True for v in checks.values())
                and (folder / 'session/reads.jsonl').is_file())
    return {'passed': complete, 'state': 'done' if complete else 'failed',
            'reads': value.get('real_privacy_reads'), 'flows': value.get('flows'),
            'installed_original_apk': checks.get('original_apk_installed'),
            'original_pid_alive': checks.get('original_pid_alive'),
            'serial': (value.get('device') or {}).get('serial'),
            'ui_scenario_version': value.get('ui_scenario_version'), 'startup_mode': value.get('startup_mode'),
            'reasons': [] if complete else failures(value) or ['capture not complete or raw read file missing']}


def inspect_formal(folder, value, entry):
    ai = folder / 'out/ai'
    bundle, stage3 = read(folder / 'out/bundle.json'), read(ai / 'stage3.json')
    validation = read(ai / 'validation.json')
    publication = value.get('published') or {}
    report = folder / 'out/mobile-report.pdf'
    try:
        with report.open('rb') as stream:
            pdf = stream.read(5) == b'%PDF-'
        calls = [json.loads(line) for line in (ai / 'llm-calls.jsonl').read_text(encoding='utf-8').splitlines() if line.strip()]
    except (OSError, ValueError):
        pdf, calls = False, []
    app = bundle.get('app') or {}
    stages = ('static', 'policy', 'capture', 'correlate', 'bundle', 'ai', 'report')
    triple = (set(validation) == {'stage1', 'stage2', 'stage3'}
              and all(c.get('ok') is True for c in validation.values())
              and all(read(ai / f'stage{n}.json') for n in (1, 2, 3)))
    accepted = {}
    if triple:
        accepted, _ = load_checked_stages(ai, bundle)
        triple = set(accepted) == {'stage1', 'stage2', 'stage3'}
    live_error, live = None, False
    if triple:
        try:
            calls = check_live_calls(ai, accepted, bundle)
            live = True
        except (OSError, ValueError, KeyError, TypeError) as error:
            live_error = 'live AI provenance: ' + str(error)
    complete = (value.get('passed') is True and triple and live and pdf
                and app.get('package') == entry['package'] and app.get('apk_sha256') == entry['sha256']
                and all(value.get('stages', {}).get(s, {}).get('state') == 'done' for s in stages)
                and bool(value.get('task_id')) and publication.get('task_id') == value.get('task_id') and bool(publication.get('report_url'))
                and Path(publication.get('source_run', '')).resolve() == folder.resolve())
    reasons = failures(value)
    if not complete:
        if live_error:
            reasons.append(live_error)
        for stage, checked in validation.items():
            if checked.get('ok') is not True:
                reasons.extend(stage + ': ' + str(p) for p in checked.get('problems') or [])
        if not reasons:
            reasons = ['formal review lacks bound success, three live validated stages or published PDF']
    risk = bundle.get('risk_assessment') or {} if complete else {}
    score = risk.get('score')
    if type(score) not in (int, float) or not 0 <= score <= 100 or risk.get('level') == 'unknown':
        score = None
    state = value.get('state') if value.get('state') in ('blocked', 'ready', 'running', 'not_run') else 'failed'
    return {'passed': complete, 'state': 'done' if complete else state,
            'failed_stage': value.get('failed_stage'), 'recorded_model_calls': len(calls),
            'validated_three_stages': triple, 'published': bool(complete),
            'report_path': str(report.resolve()) if complete else None,
            'report_url': publication.get('report_url') if complete else None,
            'risk_score': score, 'risk_level': risk.get('level', 'unknown'),
            'risk_score_scope': 'bound formal bundle evidence-signal score, not a static candidate score',
            'ai_overall_risk': stage3.get('overall_risk') if complete else 'unknown',
            'supporting_documents_used': len((bundle.get('policy') or {}).get('supporting_documents') or []) if complete else None,
            'reasons': [] if complete else reasons}


def select(entry, roots, kind):
    attempts, excluded, seen = [], [], set()
    for root in roots:
        root = Path(root).resolve()
        folders = [root / 'samples' / entry['sample_id'], root]
        for folder in folders:
            path = folder / ('result.json' if kind == 'static' else 'verification.json')
            if not path.exists() and kind == 'formal' and folder != root:
                path = root / 'results' / (entry['sample_id'] + '.json')
            if path in seen or not path.is_file():
                continue
            seen.add(path)
            value = read(path)
            if not bound(value, entry):
                excluded.append({'path': str(path), 'reason': 'APK/package binding differs or unreadable'})
                continue
            outcome = (inspect_static(folder, value) if kind == 'static' else
                       inspect_capture(folder, value) if kind == 'capture' else inspect_formal(folder, value, entry))
            attempts.append({**outcome, 'source': str(path), '_time': modified(value, path)})
    attempts.sort(key=lambda item: (item['passed'], item['_time']), reverse=True)
    for item in attempts:
        item.pop('_time', None)
    selected = dict(attempts[0]) if attempts else {'passed': False, 'state': 'not_run', 'source': None,
                                                 'reasons': ['no same-APK retained ' + kind + ' attempt']}
    return {**selected, 'attempts': attempts, 'excluded_sources': excluded}


def build(manifest, static_roots, capture_roots, formal_roots, policy_store):
    rows = []
    for entry in ready_entries(Path(manifest)):
        static = select(entry, static_roots, 'static')
        capture = select(entry, capture_roots, 'capture')
        formal = select(entry, formal_roots, 'formal')
        policy = load_policy(policy_store, package=entry['package'], version_code=entry.get('version_code'),
                             apk_sha256=entry['sha256'])
        rows.append({'sample_id': entry['sample_id'], 'name': entry['name'], 'package': entry['package'],
            'apk_sha256': entry['sha256'], 'version_code': entry.get('version_code'),
            'static': static, 'capture': capture, 'formal': formal,
            'local_policy': {'available': policy.get('available') is True, 'status': policy.get('status'),
                'supporting_documents': len(policy.get('supporting_documents') or []), 'gaps': policy.get('gaps')},
            'risk_score': formal.get('risk_score') if formal['passed'] else None,
            'risk_level': formal.get('risk_level', 'unknown') if formal['passed'] else 'unknown'})
    return {'schema_version': 1, 'index_generated': True, 'passed': bool(rows) and all(r['formal']['passed'] for r in rows),
        'generated_at': datetime.now(timezone(timedelta(hours=8))).isoformat(),
        'scope': 'read-only retained evidence index; static candidates and formal risk are separate; unknown is not zero',
        'manifest': str(Path(manifest).resolve()), 'network_calls': 0, 'device_execution': False,
        'counts': {'apps': len(rows), 'whole_dex': sum(r['static']['passed'] for r in rows),
            'capture_passed': sum(r['capture']['passed'] for r in rows),
            'formal_published': sum(r['formal']['passed'] for r in rows),
            'policy_available': sum(r['local_policy']['available'] for r in rows),
            'risk_unknown': sum(r['risk_score'] is None for r in rows)}, 'samples': rows}


def cell(value):
    return str(value if value is not None else 'unknown').replace('|', '\\|').replace('\n', ' ')


def markdown(summary):
    lines = ['# 国内 APK 核心交付索引', '', '生成时间：' + summary['generated_at'], '',
        '只读取同一 APK 的既有证据，每个阶段完整采用单一来源。优先保留成功，重试失败不覆盖成功；所有尝试及排除原因见 verification.json。',
        '静态候选不等于风险结论；没有已发布正式报告者综合风险 unknown。分数来自通过正式运行的绑定证据包，不是安全认证或模型准确率。', '',
        '| 应用 | 全 DEX | 静态候选 | 安装/运行采集 | 读取数 | 本地政策/补充数 | 正式 AI | 风险信号分 | 报告 | 失败/缺口 |',
        '| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |']
    for row in summary['samples']:
        static, capture, formal, policy = (row[k] for k in ('static', 'capture', 'formal', 'local_policy'))
        reasons = [kind + ': ' + '; '.join(row[kind]['reasons']) for kind in ('static', 'capture', 'formal') if row[kind]['reasons']]
        if not policy['available']:
            reasons.append('policy: ' + str(policy['status']))
        if capture.get('reads') == 0:
            reasons.append('有限场景未观察到敏感读取，不等于无收集')
        values = [row['name'], str(static.get('dex_count')) if static['passed'] else '未完整',
            static.get('candidate_count'), '原包=' + cell(capture.get('installed_original_apk')) +
            '；进程存活=' + cell(capture.get('original_pid_alive')) + '；采集=' +
            ('通过' if capture['passed'] else capture['state']), capture.get('reads'),
            str(policy['status']) + '/' + str(policy['supporting_documents']),
            '通过；附录输入' + str(formal.get('supporting_documents_used')) if formal['passed'] else formal['state'],
            row['risk_score'], '[PDF](' + formal['report_path'].replace('\\', '/') + ')' if formal.get('report_path') else '—',
            '; '.join(reasons) or '证据范围仍限于已执行场景']
        lines.append('| ' + ' | '.join(cell(value) for value in values) + ' |')
    lines += ['', '计数：`' + json.dumps(summary['counts'], ensure_ascii=False) + '`', '',
              '本地政策栏是当前资料库状态；正式 AI 的“附录输入”来自该轮证据包，二者不混称。未生效政策不能替代现行政策。',
              '每个报告、采集、静态扫描的精确路径，以及失败模型阶段/门控原因，均保存在 verification.json。']
    return '\n'.join(lines) + '\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path, default=ROOT / 'output/domestic-apk-corpus-20261018/manifest.json')
    parser.add_argument('--static-root', type=Path, action='append')
    parser.add_argument('--capture-root', type=Path, action='append', required=True)
    parser.add_argument('--formal-root', type=Path, action='append', required=True)
    parser.add_argument('--policy-store', type=Path, default=DEFAULT_STORE)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    out = args.out.resolve()
    if out.exists() or not out.is_relative_to(ROOT / 'output'):
        parser.error('use a new project output directory; historical artifacts are never overwritten')
    summary = build(args.manifest, args.static_root or STATIC, args.capture_root, args.formal_root, args.policy_store)
    out.mkdir(parents=True)
    (out / 'verification.json').write_text(json.dumps(summary, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    (out / 'README.md').write_text(markdown(summary), encoding='utf-8')
    print(json.dumps({'out': str(out), 'counts': summary['counts'], 'all_core_passed': summary['passed']}, ensure_ascii=False))


if __name__ == '__main__':
    main()
