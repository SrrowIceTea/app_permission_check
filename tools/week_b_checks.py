"""B 周 D4/D5 边界核验：从实际产物判定，不把「没跑」写成「通过」。

只读已产生的产物与回归日志；不跑设备、不重采、不改判定。
历史封存副本不能充当设备正控或新会话证据。
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'tools'))

import real_sample_result as rsr  # noqa: E402
from vehicle.bench import claim_scope as scope  # noqa: E402

MAO = ROOT / 'output/week-mao-20261110'
FROZEN = ROOT / 'output/claim-verdicts-20261110/verdicts.json'


def read(path):
    path = Path(path)
    return json.loads(path.read_text(encoding='utf-8')) if path.is_file() else None


def check(check_id, description, verdict, evidence):
    return {'id': check_id, 'check': description, 'verdict': verdict, 'evidence': evidence}


def report_cells(path):
    path = Path(path)
    if not path.is_file():
        return {}
    out = {}
    for line in path.read_text(encoding='utf-8').splitlines():
        if line.startswith('| W') and line.count('|') >= 9:
            cells = [c.strip() for c in line.split('|')[1:-1]]
            if len(cells) == 8:
                out[cells[0]] = cells
    return out


def boundary_checks(out):
    checks = []
    legacy, current = read(FROZEN), read(MAO / 'selfcheck.json')
    if legacy and current:
        keys = ('scored', 'asserted_ratio', 'wrong_assertion_ratio', 'unobserved_ratio')
        same = (legacy.get('counts') == current.get('counts')
                and all(legacy.get(k) == current.get(k) for k in keys))
        statuses = {r['item']: r.get('status') for r in legacy.get('items', [])}
        changed = [r['item'] for r in current.get('items', [])
                   if statuses.get(r['item']) != r.get('status')]
        checks.append(check('B01', '冻结 6 项状态 / counts / 三个比率不因投影修复改变',
                            'pass' if same and not changed else 'fail',
                            {'counts_equal': legacy.get('counts') == current.get('counts'),
                             'ratios': {k: current.get(k) for k in keys},
                             'status_changes': changed}))
    else:
        checks.append(check('B01', '冻结计分对照', 'not_run', '缺 verdicts.json 或 selfcheck.json'))

    after = report_cells(out / 'd2-report-after.md')
    if current and after:
        rows = {r['item']: r for r in current.get('items', [])}
        mismatches = []
        for item, cells in after.items():
            row = rows.get(item) or {}
            expected = (rsr.DASH if row.get('status') == 'unscored'
                        else str(scope.evidence_cell(row, rsr.DASH)))
            if cells[5] != expected:
                mismatches.append({'item': item, 'shown': cells[5], 'expected': expected})
        checks.append(check('B02', '报告「业务证据（本命题）」列与计分同源、不取整轮值',
                            'pass' if not mismatches else 'fail',
                            {'rows': len(after), 'mismatches': mismatches,
                             'cross_proposition_counterexample': 'tools/test_report_projection.py::test_c2'}))
    else:
        checks.append(check('B02', '报告证据列对照', 'not_run', '缺报告或 selfcheck.json'))

    unscored = after.get('W05')
    synthetic_gap = rsr.limitations({'items': [
        {'item': 'X', 'status': 'unscored', 'unscored_reason': 'reviewers_disagreed'}]})
    ok = (bool(unscored) and '未计分·' in unscored[4]
          and any('评审意见未一致' in n for n in synthetic_gap)
          and not any('X 无采集产物' in n for n in synthetic_gap))
    checks.append(check('B03', 'unscored 显示结构性原因，且不给评审未一致编造「无采集产物」',
                        'pass' if ok else 'fail',
                        {'w05_cell': unscored[4] if unscored else None,
                         'synthetic_gap': synthetic_gap}))

    index = read(out / 'replay-index.json') or {}
    records = index.get('captures') or []
    experiment_ok = all(
        r.get('emits_rule_findings') is False
        and r.get('registered_location_egress_rule') is None
        and (r.get('layer_accounting') or {}).get('candidates', {}).get('pairs') == 0
        and not (r.get('layers') or {}).get('association', {}).get('origin_proven')
        for r in records if r.get('result_path'))
    checks.append(check('B04', '历史重放不产 findings、不启用定位外发规则、不写来源因果',
                        'pass' if records and experiment_ok else ('fail' if records else 'not_run'),
                        {'records': len(records),
                         'attempts': [(r['id'], r.get('attempt_status')) for r in records]}))
    readonly = all((r.get('staging') or {}).get('source_readonly_verified')
                   and (r.get('staging') or {}).get('staged_unchanged_after_replay')
                   for r in records if r.get('staging'))
    checks.append(check('B05', '只读副本：原目录与 staging 的 sha256 前后一致',
                        'pass' if records and readonly else ('fail' if records else 'not_run'),
                        {'readonly_verified': readonly, 'captures': len(records)}))
    classified = all((r.get('layer_accounting') or {}).get('all_reasons_classified')
                     for r in records if r.get('layer_accounting'))
    checks.append(check('B06', '所有拒绝原因均归类；未分类原因不被静默丢弃',
                        'pass' if records and classified else ('fail' if records else 'not_run'),
                        {'all_classified': classified}))

    before, post = (read(out / 'd1-synthetic/result.json'),
                    read(out / 'd4-synthetic/result.json'))
    if before and post:
        b = {c['name']: (c['result']['pair_count'], c['result']['ambiguous_flows'])
             for c in before['cases']}
        a = {c['name']: (c['result']['pair_count'], c['result']['ambiguous_flows'])
             for c in post['cases']}
        checks.append(check('B07', '六类正负控前后配对数/歧义流数不变',
                            'pass' if b == a else 'fail', {'before': b, 'after': a}))
    else:
        checks.append(check('B07', '六类正负控对照', 'not_run', '缺 d1/d4 synthetic 产物'))

    baseline = read(out / 'baseline.json') or {}
    rules = (baseline.get('rules') or {}).get('by_android_version') or {}
    ge = any(v.get('VSC-GE-location_registered') for v in rules.values())
    checks.append(check('B08', '四个 Android 版本均未默认登记 VSC-GE-location',
                        'pass' if rules and not ge else ('fail' if rules else 'not_run'),
                        {'versions': list(rules), 'any_registered': ge}))

    guard = subprocess.run([sys.executable, 'tools/test_inventory_guard.py'], cwd=ROOT,
                           capture_output=True, text=True, encoding='utf-8', errors='replace')
    checks.append(check('B09', '测试清单守卫（新测试均已登记）',
                        'pass' if guard.returncode == 0 else 'fail',
                        {'returncode': guard.returncode, 'stdout': (guard.stdout or '').strip()}))

    regressions = {}
    for name in ('verify-root', 'verify-mobile', 'verify-branch'):
        data = read(out / name / 'verification.json')
        if data is None:
            regressions[name] = {'verdict': 'not_run'}
            continue
        rows = data if isinstance(data, list) else data.get('checks') or []
        regressions[name] = {'entries': len(rows),
                             'nonzero': [r.get('name') for r in rows if r.get('exit_code')],
                             'verdict': 'pass' if rows and all(
                                 r.get('exit_code') == 0 for r in rows) else 'fail'}
    ran = [v for v in regressions.values() if v['verdict'] != 'not_run']
    checks.append(check('B10', '最终基线三套回归无新增失败',
                        ('pass' if ran and all(v['verdict'] == 'pass' for v in ran)
                         else 'fail') if ran else 'not_run', regressions))
    return checks, regressions
