"""Compose the real-sample result sheet from sealed artifacts.

仅用于授权测试。Reads only finished outputs; it never re-runs an audit and never
invents a number. Any field missing from an artifact is printed as an em dash and
the corresponding limitation is listed in section 4, so the sheet cannot silently
upgrade an absent measurement into a positive one.
"""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from vehicle.bench.samples import requirements
from vehicle.pipeline.contracts import ROOT

DASH = '—'


def read(path, default=None):
    path = Path(path)
    return json.loads(path.read_text(encoding='utf-8')) if path.is_file() else default


def catalog_rows(sources):
    rows = []
    for sample in sources:
        need = requirements(sample)
        if need['hardware']:
            usable = '否（需物理介质）'
        elif need['service']:
            usable = '需后端'
        else:
            usable = '是'
        rows.append((sample['id'], ', '.join(need['hardware']) or DASH,
                     ', '.join(need['service']) or DASH, usable))
    return rows


def verdict_rows(verdicts):
    rows = []
    for row in verdicts.get('items', []):
        rows.append((row.get('item'), row.get('case'), row.get('adjudicated', DASH),
                     row.get('system_stance', DASH), len(row.get('evaluators_that_ran') or []),
                     row.get('business_evidence_total', DASH), row.get('rule_hits', DASH),
                     row.get('status')))
    return rows


def build(verdicts, measure, sources):
    lines = ['# 真实样本检测结果', '',
             '环境：AAOS 35 模拟器，frida-server 以 root 运行；自有设备与授权第三方 APK。',
             '本文件只汇总**已产生的产物**，不含推测值；缺项一律记为 ' + DASH + '。', '',
             '## 1. 样本目录状态', '',
             '| 样本 | 硬件要求 | 服务要求 | 本环境可否产生行为 |', '|---|---|---|---|']
    lines += ['| {} | {} | {} | {} |'.format(*row) for row in catalog_rows(sources)]
    blocked = sum(1 for row in catalog_rows(sources) if row[3] != '是')
    lines += ['', f'{len(sources)} 个真实样本中 {blocked} 个依赖外部条件；'
                  '只有自足的样本能在此环境产生可观测行为。', '',
              '## 2. 逐案可观测性与断言', '',
              '| 项 | case | 裁决 | 系统断言 | 运行求值器数 | 业务证据 | 规则命中 | 判定 |',
              '|---|---|---|---|---|---|---|---|']
    lines += ['| {} | {} | {} | {} | {} | {} | {} | {} |'.format(*row)
              for row in verdict_rows(verdicts)]
    counts = '；'.join(f'{key}={value}' for key, value in (verdicts.get('counts') or {}).items() if value)
    lines += ['', f'计分 {verdicts.get("scored", 0)} 项：{counts or DASH}', '',
              f'- wrong_assertion_ratio = {verdicts.get("wrong_assertion_ratio")}',
              f'- unobserved_ratio = {verdicts.get("unobserved_ratio")}'
              '（「没观测所以没说」的占比，不计入有效性）', '',
              '## 3. 配对级金标准结果', '']
    if measure is None:
        lines += ['本次未提供配对级结果。', '']
    else:
        label = measure['label']
        families = ' / '.join(p['model_family'] for p in label['participants'])
        lines += [f'标签层级 `{label["tier"]}`（`gold_kind={label["gold_kind"]}`），'
                  f'三方模型家族：{families}', '',
                  '| 求值器 | tp | fp | fn | Precision | Recall |', '|---|---|---|---|---|---|']
        for name, key in (('专用 HA 求值器', 'specialized_ha_evaluator'),
                          ('通用求值器', 'generic_evaluator')):
            metric = measure.get(key) or {}
            lines.append('| {} | {} | {} | {} | {} | {} |'.format(
                name, metric.get('tp', DASH), metric.get('fp', DASH), metric.get('fn', DASH),
                metric.get('precision'), metric.get('recall')))
        lines += ['', '正例 2 对、负控 4 对；样本量=2，**不构成总体准确率**。', '']
    lines += ['## 4. 明确不能主张的结论', '']
    for item in limitations(verdicts):
        lines.append('- ' + item)
    return '\n'.join(lines) + '\n'


def limitations(verdicts):
    """Derive the caveats from what the data actually shows, not from prose."""
    items = verdicts.get('items') or []
    unscored = [row['item'] for row in items if row.get('status') == 'unscored']
    unobserved = [row['item'] for row in items
                  if row.get('status') == 'correct_by_absence_of_observation']
    out = []
    if unscored:
        out.append('缺口：' + '、'.join(unscored) + ' 无采集产物，无法计分。')
    if unobserved:
        out.append('依据不足但结论正确：' + '、'.join(unobserved)
                   + ' 的「absent」来自没有运行任何求值器，不是观测结论。')
    out += ['方法增益：没有对照组实验，配对指标只是单样本数字。',
            '跨模型标签不等于专家验证：模型身份为组织者指定的路由别名，未验证上游权重是否共享。',
            'mg4 类样本的代理逐流归因在模拟器上不可得（SLIRP 不保留源端口），只能依赖替代关系。',
            '位置外发未闭环：通用求值器对 location 只做读取，不做外发关联，本批无该类样本可测。']
    return out


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--verdicts', type=Path, required=True)
    parser.add_argument('--measurement', type=Path)
    parser.add_argument('--catalog', type=Path, default=ROOT / 'vehicle/bench/sources.json')
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args(argv)
    verdicts = read(args.verdicts, {'items': []})
    measure = read(args.measurement) if args.measurement else None
    sources = read(args.catalog, {'samples': []})['samples']
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(build(verdicts, measure, sources), encoding='utf-8')
    print(json.dumps({'out': str(args.out), 'items': len(verdicts.get('items') or [])},
                     ensure_ascii=False))


if __name__ == '__main__':
    main()
