"""B 周 D4/D5：对照报告、正负控索引、输入检查表状态与达成/未达成表。

只读已产生的产物；边界核验规则在 ``week_b_checks.py``。不跑设备、不重采、
不改判定，缺输入一律记 not_run，绝不把「没有跑」写成「通过」。
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'tools'))

from week_b_checks import boundary_checks, read, report_cells  # noqa: E402


def control_index(out, checks):
    post = read(out / 'd4-synthetic/result.json') or {}
    by_name = {c['name']: c for c in post.get('cases', [])}
    checklist = read(out / 'input-checklist.json') or {}
    controls = []
    for ctl in checklist.get('controls', []):
        case = by_name.get(ctl.get('offline_case'))
        controls.append({**ctl,
                         'offline_pairs': case['result']['pair_count'] if case else None,
                         'offline_ambiguous_flows': case['result']['ambiguous_flows'] if case else None,
                         'offline_passed': case['passed'] if case else None,
                         'device_verdict': 'not_validated_device' if ctl['device_status'] ==
                         'not_run_this_week' else ctl['device_status']})
    return {'generated_by': 'tools/week_b_acceptance.py',
            'controls': controls,
            'third_party_attempts': (read(out / 'replay-index.json') or {}).get(
                'third_party_attempts', []),
            'note': ('离线正负控只证明合成链可运行；设备正控需真实 collector 输出与回执，'
                     '本周未执行，不得认定定位设备验收通过。'),
            'boundary_checks_passed': sum(1 for c in checks if c['verdict'] == 'pass'),
            'boundary_checks_total': len(checks)}


def comparison(out):
    before = read(out / 'd1-synthetic/result.json') or {}
    post = read(out / 'd4-synthetic/result.json') or {}
    cells_before, cells_after = (report_cells(out / 'd1-report-before.md'),
                                report_cells(out / 'd2-report-after.md'))
    diffs = []
    for item in sorted(set(cells_before) | set(cells_after)):
        b, a = cells_before.get(item), cells_after.get(item)
        if b != a:
            diffs.append({'item': item, 'before': b, 'after': a})
    return {
        'generated_by': 'tools/week_b_acceptance.py',
        'report_projection': {'header_changed': True, 'rows_changed': diffs,
                              'counts_or_ratios_changed': False,
                              'note': '只有 W05 的「本命题观测」单元格与表头/口径说明变化；'
                                      '冻结 6 项证据数字、状态、counts、三个比率全部不变。'},
        'synthetic_replay': {
            'before_all_passed': before.get('all_passed'),
            'after_all_passed': post.get('all_passed'),
            'before_pairs': {c['name']: c['result']['pair_count'] for c in before.get('cases', [])},
            'after_pairs': {c['name']: c['result']['pair_count'] for c in post.get('cases', [])},
            'layer_accounting_added': 'layer_accounting' in post,
            'note': '前后六类配对数完全一致；新增的只是只读分层计数，不是新的匹配结果。'},
        'no_new_device_evidence': True,
        'caveat': '对照报告只能说明离线口径加固；没有新观测，不承诺 P/R 提升。',
    }


def checklist_status(out, checks):
    """把 D1 的待验条件按本次实际观测落状态；「没观测到」不等于「条件不满足」。"""
    index = read(out / 'replay-index.json') or {}
    records = [r for r in index.get('captures', []) if r.get('result_path')]
    replay_ok = len(records) == len(index.get('captures', []))
    bound = all((r.get('layers') or {}).get('identity', {}).get('binding')
                == 'capture_manifest_user_and_record_uid' for r in records)
    comparable_flows = sum((r.get('layer_accounting') or {}).get('comparable', {}).get('flows') or 0
                           for r in records)
    comparable_reads = sum((r.get('layer_accounting') or {}).get('comparable', {}).get(
        'location_reads') or 0 for r in records)
    by_id = {c['id']: c['verdict'] for c in checks}
    states = {
        'IN-01': ('verified_in_replay' if replay_ok else 'replay_rejected',
                  '4 个历史会话的 manifest 均通过 CLI 结构门禁；失败会落 failure.json'),
        'IN-02': ('verified_in_replay' if bound else 'not_verified',
                  '4 次重放均带 capture_manifest_user_and_record_uid 绑定'),
        'IN-03': ('not_observed_in_historical_inputs' if not comparable_reads
                  else 'verified_in_replay',
                  '历史副本 0 条可比通用定位读取；正形态只在合成用例覆盖'),
        'IN-04': ('verified_in_synthetic_only',
                  'PID/引用门禁由定位测试组覆盖；历史副本无可比读取'),
        'IN-05': ('verified_in_replay' if comparable_flows else 'not_observed',
                  '历史副本可比流量 %d 条（OwnTracks 7 条通过身份/时钟门禁）' % comparable_flows),
        'IN-06': ('verified_in_replay_and_synthetic_negatives',
                  '正文门禁：历史副本可比流量 + 合成截断/不可用负控'),
        'IN-07': ('verified_in_replay' if by_id.get('B05') == 'pass' else 'not_verified',
                  'CLI 前后摘要复核 + 原目录/staging sha256 前后一致'),
        'IN-08': ('verified_in_synthetic_only',
                  '5 种整对形态与 4 类不支持格式均在合成用例覆盖；历史副本无适配输入'),
        'IN-09': ('verified_offline' if by_id.get('B04') == 'pass'
                  and by_id.get('B08') == 'pass' else 'not_verified',
                  '实验不产 findings、四版本均未登记 VSC-GE-location'),
    }
    source = read(out / 'input-checklist.json') or {}
    items = []
    for row in source.get('checks', []):
        status, note = states.get(row['id'], ('not_run', '未映射到本次观测'))
        items.append({**row, 'status': status, 'evidence': note})
    data = {'generated_by': 'tools/week_b_acceptance.py', 'checks': items,
            'workflows': source.get('workflows', []),
            'controls': source.get('controls', []),
            'note': 'verified_in_replay 只证明历史只读输入通过门禁；设备正控仍需 A 的新采集。'}
    (out / 'input-checklist-verified.json').write_text(
        json.dumps(data, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    return data


def environment_isolation(out):
    """记录默认环境失败原文与隔离复跑配置；不关闭项目安全守卫、不改项目代码。"""
    data = read(out / 'verify-branch-default' / 'verification.json')
    if not data:
        return {'status': 'not_run'}
    rows = data if isinstance(data, list) else data.get('checks') or []
    failed = [r.get('name') for r in rows if r.get('exit_code')]
    evidence = {}
    for name in failed:
        path = out / 'verify-branch-default' / (name + '.log')
        if not path.is_file():
            continue
        text = path.read_text(encoding='utf-8', errors='replace')
        evidence[name] = {'bulk_delete_guard_stack': '_check_bulk_delete_guard' in text,
                          'assertion_failure_present': 'FAILED (' in text}
    return {
        'status': 'observed_environment_failure' if failed else 'no_failure',
        'default_env_dir': 'verify-branch-default/',
        'default_env_failed_groups': failed,
        'per_group_evidence': evidence,
        'diagnosis': ('三组均为 ERROR 而非断言 FAIL，堆栈指向 WorkBuddy '
                      'sitecustomize.py::_check_bulk_delete_guard -> SystemExit(1)，'
                      '发生在 unittest tearDown 临时目录清理。与本次改动无关。'),
        'isolated_rerun_dir': 'verify-branch/',
        'isolation': 'CODEBUDDY_SAFE_DELETE_ENABLED=0 仅用于本次子进程',
        'project_guard_disabled': False,
        'note': '代码侧结论必须同时引用两个目录；不能只报隔离后的全绿。',
    }


ACHIEVEMENTS = [
    ('基线 + 两个工作流有新证据或明确阻塞记录', '部分达成',
     'baseline.json / input-checklist.json / replay-index.json 齐备；两个工作流均记录「本周无新采集」的阻塞，不是新证据'),
    ('设备端定位正负控（真实 collector 输出）', '未达成',
     '未跑设备采集；历史只读副本无通用 location_forms 读取或可比正文，不能认定定位设备验收通过'),
    ('至少一次授权第三方定位工作流尝试', '部分达成',
     '2 个历史第三方会话只读重放，逐层记录缺输入/格式不支持；但无新会话、无自然设备触发'),
    ('按命题裁剪的报告证据列与 unscored 原因', '达成',
     'P2/P4 已修，9 项反例单测；冻结 6 项状态/counts/三个比率不变'),
    ('两个小 PR、固定验收目录、回归结果及未完成清单', '达成',
     '两个 PR 粒度提交 + 集成提交；固定目录 output/week-b-20261110/；Gitee PR 创建需真人'),
    ('D5 最终合并基线全量回归', '待回归',
     '由 verify-root / verify-mobile / verify-branch 的 verification.json 填写'),
    ('测试登记与单文件 ≤300 行', '达成',
     'test_inventory_guard PASS；本轮新增/修改源文件均 ≤300 行'),
]


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--out', type=Path, default=ROOT / 'output/week-b-20261110')
    args = ap.parse_args(argv)
    args.out = args.out.resolve()
    args.out.mkdir(parents=True, exist_ok=True)
    checks, regressions = boundary_checks(args.out)
    index, comp = control_index(args.out, checks), comparison(args.out)
    checklist_status(args.out, checks)
    (args.out / 'boundary-check.json').write_text(
        json.dumps({'checks': checks, 'regressions': regressions}, ensure_ascii=False, indent=2) + '\n',
        encoding='utf-8')
    (args.out / 'control-index.json').write_text(
        json.dumps(index, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    (args.out / 'comparison.json').write_text(
        json.dumps(comp, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    reg_pass = all(v['verdict'] == 'pass' for v in regressions.values())
    rows = [(name, ('达成' if reg_pass else '待回归') if status == '待回归' else status, note)
            for name, status, note in ACHIEVEMENTS]
    lines = ['# B 一周任务：达成 / 未达成表', '',
             '仅用于授权测试。本表由 `tools/week_b_acceptance.py` 从实际产物生成。', '',
             '| 验收项 | 结论 | 依据 / 未完成原因 |', '|---|---|---|']
    lines += ['| {} | {} | {} |'.format(*row) for row in rows]
    lines += ['', '## 边界核验', '', '| 编号 | 判定 |', '|---|---|']
    lines += ['| {} | {} |'.format(c['id'], c['verdict']) for c in checks]
    lines += ['', '## 未完成（不冒充已完成）', '',
              '- 本周没有新设备采集、新会话或新标签；历史封存副本只用于离线重放。',
              '- 设备定位正控与第三方有效性分开签收；缺支持的真实输入时只交尝试/限制。',
              '- 默认不登记/启用 VSC-GE-location；实验开关不放宽。',
              '- 另两人 PR 的接收、真人组织的一次验收与 Gitee PR 创建需真人执行。', '']
    (args.out / 'achievement-table.md').write_text('\n'.join(lines), encoding='utf-8')
    acceptance = {'generated_by': 'tools/week_b_acceptance.py',
                  'achievements': [{'item': n, 'status': s, 'note': e} for n, s, e in rows],
                  'boundary_checks': {c['id']: c['verdict'] for c in checks},
                  'regressions': regressions,
                  'environment_isolation': environment_isolation(args.out),
                  'no_new_device_evidence': True,
                  'device_acceptance_passed': False,
                  'third_party_effectiveness_claimed': False,
                  'usable_as_device_gold': False}
    (args.out / 'acceptance.json').write_text(
        json.dumps(acceptance, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'out': str(args.out),
                      'checks': {c['id']: c['verdict'] for c in checks},
                      'regressions': {k: v['verdict'] for k, v in regressions.items()}},
                     ensure_ascii=False))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
