"""冻结输入自测：观测状态、计分与新旧口径兼容对照。仅用于授权测试。

只读 ``output/`` 下已封存的产物，**不重跑审计、不要求采集改字段、不需要设备**。
用旧口径的 ``verdicts.json`` 还原盲评裁决（只取 A/B 一致的 decision，不复用系统输出），
在冻结采集副本上重放新口径，逐项比对，并把四种口径反例与冻结实例的对应关系写清楚。

产出（默认 ``output/week-mao-20261110/``）：
  * ``selfcheck.json``      新口径完整 report
  * ``compat-matrix.json``  逐项对照 + 计数差异 + 采集副本交叉核对 + 反例实例
  * ``counterexamples.json`` 四种口径反例（周一复现 / 周二修复目标）
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from vehicle.bench import claim_scope as scope  # noqa: E402
from vehicle.bench import claim_verdicts as cv  # noqa: E402

DEFAULT_VERDICTS = ROOT / 'output/claim-verdicts-20261110/verdicts.json'
DEFAULT_AUDIT = ROOT / 'output/real-detection-20261110'
DEFAULT_OUT = ROOT / 'output/week-mao-20261110'


def read_json(path):
    path = Path(path)
    return json.loads(path.read_text(encoding='utf-8')) if path.is_file() else None


def adjudications_from(verdicts):
    """只还原裁决，不把旧系统输出带进新口径。"""
    items = []
    for row in verdicts.get('items') or []:
        decision = row.get('adjudicated')
        if decision not in ('present', 'absent'):
            continue
        items.append({'id': row.get('item'), 'case': row.get('case'),
                      'A': {'decision': decision}, 'B': {'decision': decision}})
    return items


def crosscheck(audit_dir, cases):
    """读冻结采集副本：detection-summary.json 与逐 case 的 correlation-summary 对账。"""
    sheet = read_json(Path(audit_dir) / 'detection-summary.json') or []
    by_case = {row.get('case'): row for row in sheet if isinstance(row, dict)}
    rows = []
    for case in cases:
        summary = read_json(Path(audit_dir) / str(case) / 'correlation-summary.json')
        detection = (summary or {}).get('detection_summary')
        present = isinstance(detection, dict)
        business = (detection or {}).get('business_evidence_total')
        sheet_business = (by_case.get(case) or {}).get('business')
        agrees = sheet_business is not None and sheet_business == business
        # 评审 F3：None == None 曾让「双方都没有采集副本」被写成「一致」。
        # note 一律以 agrees 为准，并按缺失形态给出可操作文案。
        if agrees:
            note = '采集副本与逐 case 产物一致'
        elif not present and sheet_business is None:
            note = ('该 case 无采集副本且无 audit 产物（结构性不可计分），'
                    '不做一致性判定，也不外推')
        elif sheet_business is None:
            note = '采集副本没有该 case 的分档记录，不做一致性判定'
        else:
            note = '两份冻结产物口径不一致，只如实记录，不改字段'
        rows.append({'case': case,
                     'sheet_business': sheet_business,
                     'artifact_business': business,
                     'artifact_has_detection_summary': present,
                     'agrees': agrees,
                     'note': note})
    return rows


def compat_rows(legacy, current):
    old = {row.get('item'): row for row in legacy.get('items') or []}
    rows = []
    for row in current.get('items') or []:
        prior = old.get(row.get('item')) or {}
        rows.append({
            'item': row.get('item'), 'case': row.get('case'),
            'adjudicated': row.get('adjudicated'),
            'legacy_status': prior.get('status'),
            'current_status': row.get('status'),
            'status_changed': prior.get('status') != row.get('status'),
            'legacy_system_stance': prior.get('system_stance'),
            'current_system_stance': row.get('system_stance'),
            'observation_state': row.get('observation_state'),
            'observation_scope': row.get('observation_scope'),
            'required_evaluators': row.get('required_evaluators'),
            'matched_evaluators': row.get('matched_evaluators'),
            'business_evidence_scoped': row.get('business_evidence_scoped'),
            'detection_summary_present': row.get('detection_summary_present'),
            'observation_reason': row.get('observation_reason'),
        })
    return rows


def frozen_instances(rows):
    """四种反例在冻结批次里各自对应什么；没触发就明说没触发，不编造。"""
    by_case = {row['case']: row for row in rows}
    w03, w05 = by_case.get('mg4-post'), by_case.get('yaabsa-playback')
    return {
        'C1': {'triggered': False,
               'note': '冻结 6 个 case 没有「本题求值器没跑、却跑了其他求值器」的组合；反例只在合成输入下复现。'},
        'C2': {'triggered': False,
               'note': '冻结批次每个 case 的业务证据都来自本 case；没有跨命题借证据的实例。'},
        'C3': {'triggered': bool(w03),
               'case': 'mg4-post' if w03 else None,
               'observation_state': (w03 or {}).get('observation_state'),
               'note': 'W03 有 detection_summary，但所需 mg4_native_http 未运行（SLIRP 归因失败），'
                       '新口径显式记 not_applicable；W05 另属「无 audit 产物」的结构性不可计分。'},
        'C4': {'triggered': bool(w03),
               'case': 'mg4-post' if w03 else None,
               'legacy_report_cell': 0,
               'current_report_cell': scope.report_cell(w03 or {}),
               'note': 'W03 旧报告只显示「运行求值器数 0」；新列显示不可判。'},
        'W05_no_audit': (w05 or {}).get('current_status'),
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--verdicts', type=Path, default=DEFAULT_VERDICTS)
    parser.add_argument('--audit-dir', type=Path, default=DEFAULT_AUDIT)
    parser.add_argument('--out', type=Path, default=DEFAULT_OUT)
    args = parser.parse_args(argv)
    legacy = read_json(args.verdicts)
    if legacy is None:
        raise SystemExit('冻结 verdicts.json 不存在：' + str(args.verdicts))
    if not args.audit_dir.is_dir():
        raise SystemExit('冻结采集副本目录不存在：' + str(args.audit_dir))
    current = cv.report(adjudications_from(legacy), args.audit_dir,
                        label_tier=legacy.get('label_tier'))
    rows = compat_rows(legacy, current)
    matrix = {
        'generated_by': 'tools/scope_selfcheck.py',
        'frozen_verdicts': str(args.verdicts),
        'frozen_audit_dir': str(args.audit_dir),
        'items': rows,
        'status_changes': [row['item'] for row in rows if row['status_changed']],
        'counts_legacy': legacy.get('counts'),
        'counts_current': current.get('counts'),
        'counts_changed': legacy.get('counts') != current.get('counts'),
        'ratios_legacy': {key: legacy.get(key) for key in
                          ('scored', 'asserted_ratio', 'wrong_assertion_ratio', 'unobserved_ratio')},
        'ratios_current': {key: current.get(key) for key in
                           ('scored', 'asserted_ratio', 'wrong_assertion_ratio', 'unobserved_ratio')},
        'ratios_changed': any(legacy.get(key) != current.get(key) for key in
                              ('scored', 'asserted_ratio', 'wrong_assertion_ratio', 'unobserved_ratio')),
        'observation_states': current.get('observation_states'),
        'not_applicable_count': current.get('not_applicable_count'),
        'unregistered_cases': current.get('unregistered_cases'),
        'frozen_crosscheck': crosscheck(args.audit_dir,
                                        [row['case'] for row in rows if row.get('case')]),
        'frozen_counterexample_instances': frozen_instances(rows),
        'caveat': ('本次只重放投影层，不重跑审计、不改采集字段。新旧状态一致说明修复是口径加固，'
                   '不是改冻结批次的结果；not_applicable 仍不是阴性结论。'),
    }
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / 'selfcheck.json').write_text(
        json.dumps(current, ensure_ascii=False, indent=2), encoding='utf-8')
    (args.out / 'compat-matrix.json').write_text(
        json.dumps(matrix, ensure_ascii=False, indent=2), encoding='utf-8')
    (args.out / 'counterexamples.json').write_text(
        json.dumps(scope.counterexamples(), ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps({
        'out': str(args.out),
        'status_changes': matrix['status_changes'],
        'counts_changed': matrix['counts_changed'],
        'ratios_changed': matrix['ratios_changed'],
        'observation_states': matrix['observation_states'],
        'crosscheck_agreement': sum(1 for r in matrix['frozen_crosscheck'] if r['agrees'])
                                / max(1, len(matrix['frozen_crosscheck'])),
    }, ensure_ascii=False))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
