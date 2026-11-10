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

from vehicle.bench import claim_scope as scope
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
    # 投影列一律由 claim_scope 提供，不与计分各算一套（C2/C4 反例）：
    # 第 5 列 observation_state/unscored_reason，第 6 列 business_evidence_scoped。
    # 旧产物缺字段时显示 dash，不按整轮值推算、不默认 0。函数签名与 8 列结构不变。
    rows = []
    for row in verdicts.get('items', []):
        rows.append((row.get('item'), row.get('case'), row.get('adjudicated', DASH),
                     row.get('system_stance', DASH), scope.report_cell(row),
                     scope.evidence_cell(row, DASH), row.get('rule_hits', DASH),
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
              '| 项 | case | 裁决 | 系统断言 | 本命题观测 | 业务证据（本命题） | 规则命中 | 判定 |',
              '|---|---|---|---|---|---|---|---|']
    lines += ['| {} | {} | {} | {} | {} | {} | {} | {} |'.format(*row)
              for row in verdict_rows(verdicts)]
    lines += ['', '「本命题观测」取自 `observation_state`：已观测（本命题）/ 已观测·本轮无命中 / '
              '不可判（未运行/缺统计）；unscored 行显示具体的结构性原因。不可判不是阴性结论，'
              '不等于未发生或无风险；旧产物无该字段时显示「无观测状态」，不按数量推算。',
              '「业务证据（本命题）」只投影 `business_evidence_scoped`，与 `system_stance`、'
              '七态计分同源；整轮 `business_evidence_total` 不进入本表，避免借其他命题的证据'
              '形成肯定结论。旧产物缺该字段时显示 ' + DASH + '，不退化成整轮值、不默认 0。'
              '不可判行的 0 只表示没有本命题证据记录，**不是**健康零命中，须同看「本命题观测」列。']
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
    # B 周 D2：unscored 有两种结构性原因，旧文案一律写「无采集产物」会给
    # reviewers_disagreed 编造原因。按 unscored_reason 分组，同源生成。
    unscored_by_reason = {}
    for row in items:
        if row.get('status') == 'unscored':
            key = row.get('unscored_reason') or 'unknown'
            unscored_by_reason.setdefault(key, []).append(str(row.get('item')))
    unobserved = [row['item'] for row in items if row.get('status') in
                  ('correct_by_absence_of_observation', 'missed_without_observation')]
    # 评审 F2：旧文案按 status 断言「没有运行任何求值器」，对 not_applicable
    # 的行会编造原因（正是 C3 反例点名的旧缺陷）。改由 observation_state 同源生成。
    not_applicable = [row['item'] for row in items
                      if row.get('observation_state') == 'not_applicable']
    out = []
    if unscored_by_reason:
        parts = ['、'.join(names) + ' ' + scope.UNSCORED_LIMITATIONS.get(
            reason, '原因未记录，不推断为没有行为或没有采集')
            for reason, names in sorted(unscored_by_reason.items())]
        out.append('缺口：' + '；'.join(parts) + '。')
    out.append('业务证据列按命题裁剪：其他命题的整轮证据不参与本题断言；'
               '本命题 0 条证据记录也不等于未发生。')
    if not_applicable:
        out.append('本轮不可判定：' + '、'.join(not_applicable)
                   + ' 缺少本命题所需求值器的观测或统计结构，逐条原因见「本命题观测」列；'
                     '不可判不是阴性结论，不等于未发生、无风险或合规。')
    if unobserved:
        out.append('依据不足但结论碰巧正确：' + '、'.join(unobserved)
                   + ' 没有本命题的观测证据，不得计入有效性；'
                     '不据此推断「求值器没运行」或「应用没有行为」。')
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
