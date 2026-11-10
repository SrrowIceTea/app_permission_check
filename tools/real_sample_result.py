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
    # Observation and business counts both use the proposition's own projection.
    # Older artifacts without scoped counts remain unknown, never borrow totals.
    rows = []
    for row in verdicts.get('items', []):
        rows.append((row.get('item'), row.get('case'), row.get('adjudicated', DASH),
                     row.get('system_stance', DASH), scope.report_cell(row),
                     (row['business_evidence_scoped']
                      if type(row.get('business_evidence_scoped')) is int
                      and row['business_evidence_scoped'] >= 0 else DASH), row.get('rule_hits', DASH),
                     row.get('status')))
    return rows


def location_section(result):
    lines = ['## 有限定位实验（独立于规则和业务证据）', '']
    if result is None:
        return lines + ['未提供本轮定位交接验收；不推断设备或第三方验证通过。', '']
    from vehicle.privacy.location_acceptance import render
    lines += ['实验候选不会计入上表整轮规则命中、本命题业务证据或配对级P/R。', '',
              render(result).replace('# B侧定位交接验收', '### 交接验收', 1)
                            .replace('## 限制', '### 限制')
                            .replace('## 人工交接复核检查表', '### 人工交接复核检查表'), '']
    return lines


def build(verdicts, measure, sources, location=None):
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
              '| 项 | case | 裁决 | 系统断言 | 本命题观测 | 本命题业务证据 | 整轮规则命中 | 判定 |',
              '|---|---|---|---|---|---|---|---|']
    lines += ['| {} | {} | {} | {} | {} | {} | {} | {} |'.format(*row)
              for row in verdict_rows(verdicts)]
    lines += ['', '「本命题观测」取自 `observation_state`：已观测（本命题）/ 已观测·本轮无命中 / '
              '不可判（未运行/缺统计）。不可判不是阴性结论，不等于未发生或无风险；'
              '旧产物无该字段时显示「无观测状态」，不按数量推算。'
              '业务证据仅取 business_evidence_scoped；旧产物缺少命题明细时留空，不借整轮合计。']
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
    lines += ['', *location_section(location)]
    return '\n'.join(lines) + '\n'


def limitations(verdicts):
    """Derive the caveats from what the data actually shows, not from prose."""
    items = verdicts.get('items') or []
    unscored = [row for row in items if row.get('status') == 'unscored']
    unobserved = [row['item'] for row in items if row.get('status') in
                  ('correct_by_absence_of_observation', 'missed_without_observation')]
    # 评审 F2：旧文案按 status 断言「没有运行任何求值器」，对 not_applicable
    # 的行会编造原因（正是 C3 反例点名的旧缺陷）。改由 observation_state 同源生成。
    not_applicable = [row['item'] for row in items
                      if row.get('observation_state') == 'not_applicable']
    out = []
    if unscored:
        out.extend('不可计分：' + str(row.get('item', DASH)) + '，'
                   + scope.unscored_text(row) + '。' for row in unscored)
    if not_applicable:
        out.append('本轮不可判定：' + '、'.join(not_applicable)
                   + ' 缺少本命题所需求值器的观测或统计结构，逐条原因见「本命题观测」列；'
                     '不可判不是阴性结论，不等于未发生、无风险或合规。')
    if unobserved:
        out.append('本命题缺少观测依据：' + '、'.join(unobserved)
                   + ' 没有本命题的观测证据，不得计入有效性；'
                     '不据此推断「求值器没运行」或「应用没有行为」。')
    out += ['方法增益：没有对照组实验，配对指标只是单样本数字。',
            '跨模型标签不等于专家验证：模型身份为组织者指定的路由别名，未验证上游权重是否共享。',
            'mg4 类样本须核对本轮归因来源；旧轮SLIRP源端口缺失不证明本轮其他归因路径不可用。',
            '定位内容关联保持独立实验；设备受控验证与第三方尝试分别报告，不升级默认外发规则。']
    return out


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--verdicts', type=Path, required=True)
    parser.add_argument('--measurement', type=Path)
    parser.add_argument('--location-acceptance', type=Path, help='本轮独立定位交接验收JSON')
    parser.add_argument('--catalog', type=Path, default=ROOT / 'vehicle/bench/sources.json')
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args(argv)
    verdicts = read(args.verdicts, {'items': []})
    measure = read(args.measurement) if args.measurement else None
    location = read(args.location_acceptance) if args.location_acceptance else None
    if args.location_acceptance and (not isinstance(location, dict)
                                     or location.get('experimental_only') is not True):
        parser.error('Location acceptance must be an existing experimental-only result')
    sources = read(args.catalog, {'samples': []})['samples']
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(build(verdicts, measure, sources, location), encoding='utf-8')
    print(json.dumps({'out': str(args.out), 'items': len(verdicts.get('items') or [])},
                     ensure_ascii=False))


if __name__ == '__main__':
    main()
