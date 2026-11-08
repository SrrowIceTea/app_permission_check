"""Freeze/compare/sign new workflow evidence separately from pair scoring. 授权测试专用。"""
import argparse
import json
from pathlib import Path

from vehicle.bench.blind_round import reviewer
from vehicle.bench.expanded_sources import material
from vehicle.bench.review_policy import comparison_mode, validate_agents
from vehicle.pipeline.contracts import ROOT, digest, read_json, write_json

QUESTIONS = (
    ('M01', 'mg4-native', '目标应用本次完整 POST 写入、代理请求与独立服务回执能否按身份和正文摘要绑定？'),
    ('M02', 'mg4-native', '单独 shell actor 的同端点请求能否归为 MG4 应用请求？'),
    ('M03', 'mg4-native', '材料中是否存在可核验的成功敏感 API 读取事件，而不仅是请求发送？'),
    ('M04', 'mg4-native', '按提供的现行计分契约，这个案例是否已满足通用读取—外发配对计分资格？'),
    ('N01', 'owntracks-network', '前台和后台阶段是否均有本轮新位置读取、身份绑定的完整请求与独立回执？'),
    ('N02', 'owntracks-network', '离线阶段取得的位置，能否在恢复连接后按值、正文摘要和独立回执对齐？'),
    ('N03', 'owntracks-network', 'HTTP 503 能否证明位置正文未离开应用、未到达接收端？'),
    ('N04', 'owntracks-network', '503 请求本身是否获得了成功的 2xx 响应？'),
    ('N05', 'owntracks-network', '按现行规则求值与基准契约，这些业务配对是否可直接增加正式通用配对计分样本？'),
    ('P01', 'owntracks-permissions', '授权与恢复两阶段是否均有新位置读取、归属请求和独立回执的闭环？'),
    ('P02', 'owntracks-permissions', '在 denied 阶段给定的有界观察窗口内，是否存在本轮测试值的新读取或对应外发回执？'),
    ('P03', 'owntracks-permissions', '材料是否足以证明撤权后所有历史位置永远不再外发，或确已观察到 API 抛出权限拒绝异常？'),
    ('P04', 'owntracks-permissions', '没有对应读取和流事件的 denied 阶段，是否可直接构造正式 pair_schema=2 的负配对？'),
)
POLICY = '''# 本轮复核口径

仅用于授权测试。只读本目录 evidence.json、plan.json、policy.md；不读取旧报告、旧答卷、
组织者资格调查、工具预测或其他评审目录。共享目录的访问限制是程序性约束，不是权限隔离。
present=命题获得支持；absent=给定材料否定命题；insufficient=证据不足。逐题给出来源/事件与理由。
设备 ts/device_start_ms 与宿主 host_received_ts、动作 ts、接收端 ts 属不同时间基准，不直接相减。
body_sha256/坐标摘要用于值一致性，不自行证明唯一来源或法律违规。HTTP失败不等于没有发送。

当前产品计分契约：vehicle/bench/review_packet.py 的 PAIR_CASE=ha_battery；
suite.py 仅该 case.kind 进入正式配对指标分支。OwnTracks 专用求值器的返回语义明确为
workflow_only；有 read_then_egress 字段不自行扩大正式求值范围。MG4 请求发送不是敏感API读取。
pair_schema=2 要求真实存在的来源+正整数事件引用，不能为“未发生”编造事件。动态阶段/同一APK变体
不增加独立App数。业务复核完成不等于有可计分参考正例。证据不足保持未计分，不用多数票补证。

review.json 填实际 reviewer、agent_id、context_mode=fresh、独立UUID和带时区 reviewed_at。
只向组织者交回自己的答卷，不打开另一份答卷。A/B结果交齐后由第三个新上下文C独立核对。
'''


def prepare(out):
    out = Path(out).resolve()
    cases, refs = material()
    out.mkdir(parents=True, exist_ok=False)
    private = out / 'organizer-only'
    private.mkdir()
    evidence = {'schema_version': 1, 'cases': cases,
                'projection': 'raw identity/events/body hashes/receipts; no old predictions or answers'}
    write_json(private / 'evidence.json', evidence)
    items = [{'id': k, 'case': c, 'prompt': p} for k, c, p in QUESTIONS]
    plan = {'schema_version': 1, 'round_id': out.name, 'review_mode': 'subagent',
            'scope': 'new_workflow_eligibility_review', 'source_sha256': refs, 'items': items,
            'evidence_sha256': digest(private / 'evidence.json')}
    write_json(private / 'plan.json', plan)
    for slot in ('A', 'B'):
        folder = out / ('reviewer-' + slot)
        folder.mkdir()
        for name in ('evidence.json', 'plan.json'):
            (folder / name).write_bytes((private / name).read_bytes())
        (folder / 'policy.md').write_text(POLICY, encoding='utf-8')
        write_json(folder / 'review.json', {'schema_version': 1, 'slot': slot,
            'plan_sha256': digest(private / 'plan.json'), 'evidence_sha256': plan['evidence_sha256'],
            'reviewer': None, 'reviewer_kind': 'subagent', 'reviewed_at': None, 'agent_id': None,
            'context_mode': 'fresh', 'review_session_id': None,
            'decisions': [{'id': row['id'], 'decision': None, 'reason': None} for row in items]})
    return plan


def frozen(out):
    private = Path(out) / 'organizer-only'
    plan = read_json(private / 'plan.json')
    if digest(private / 'evidence.json') != plan['evidence_sha256']:
        raise ValueError('frozen evidence changed')
    for relative, expected in plan['source_sha256'].items():
        if digest(ROOT / relative) != expected:
            raise ValueError('source changed: ' + relative)
    for slot in ('A', 'B'):
        if (Path(out) / ('reviewer-' + slot) / 'policy.md').read_text(encoding='utf-8') != POLICY:
            raise ValueError('frozen reviewer policy changed')
    return private, plan


def compare(out):
    out = Path(out)
    private, plan = frozen(out)
    expected = {i['id'] for i in plan['items']}
    a, av = reviewer(out / 'reviewer-A/review.json', 'A', plan['evidence_sha256'],
                     digest(private / 'plan.json'), expected)
    b, bv = reviewer(out / 'reviewer-B/review.json', 'B', plan['evidence_sha256'],
                     digest(private / 'plan.json'), expected)
    comparison_mode(plan, (a, b))
    report = {'schema_version': 1, 'review_mode': 'subagent',
        'plan_sha256': digest(private / 'plan.json'), 'evidence_sha256': plan['evidence_sha256'],
        'review_sha256': {s: digest(out / f'reviewer-{s}/review.json') for s in ('A', 'B')},
        'disagreements': [{'id': k, 'A': av[k], 'B': bv[k]} for k in sorted(expected)
                          if av[k]['decision'] != bv[k]['decision']],
        'insufficient_items': sorted(k for k in expected if 'insufficient' in
                                    (av[k]['decision'], bv[k]['decision']))}
    write_json(out / 'comparison.json', report)
    template = {**report, 'slot': 'C', 'reviewer': None, 'reviewer_kind': 'subagent', 'agent_id': None,
        'context_mode': 'fresh', 'review_session_id': None, 'reviewed_at': None, 'confirmed': False,
        'decisions': [{'id': i['id'], 'decision': None, 'reason': None} for i in plan['items']],
        'cases': [{'id': c['id'], 'workflow_status': None, 'eligibility': None,
                   'eligibility_reasons': None} for c in read_json(private / 'evidence.json')['cases']]}
    write_json(out / 'signoff-request.json', template)
    return report


def finalize(out):
    out = Path(out)
    private, plan = frozen(out)
    report = compare(out)
    c, votes = reviewer(out / 'signoff-subagent.json', 'C', plan['evidence_sha256'],
                        digest(private / 'plan.json'), {i['id'] for i in plan['items']})
    a, b = (read_json(out / f'reviewer-{s}/review.json') for s in ('A', 'B'))
    validate_agents((a, b, c))
    if c.get('confirmed') is not True or c.get('review_sha256') != report['review_sha256']:
        raise ValueError('C must bind both actual answers and explicitly confirm')
    cases = read_json(private / 'evidence.json')['cases']
    decisions = {r['id']: r for r in c.get('cases', [])}
    if len(c.get('cases', [])) != len(cases) or set(decisions) != {r['id'] for r in cases}:
        raise ValueError('C must review all cases')
    published = []
    for case in cases:
        row = decisions[case['id']]
        if row.get('eligibility') not in ('workflow_only', 'insufficient'):
            raise ValueError('current scoring contract does not admit these pair cases')
        if row.get('workflow_status') not in ('supported', 'insufficient'):
            raise ValueError('explicit workflow status required')
        if not isinstance(row.get('eligibility_reasons'), list) or not row['eligibility_reasons'] or not all(isinstance(x, str) and x.strip()
                                                       for x in row['eligibility_reasons']):
            raise ValueError('eligibility reasons required')
        published.append({'id': case['id'], 'family': case['family'], 'package': case['package'],
            'session_ids': [r['identity']['session'] for r in case['captures']],
            'workflow_status': row['workflow_status'], 'eligibility': row['eligibility'],
            'eligibility_reasons': row['eligibility_reasons'], 'reference_pairs': None,
            'review_status': 'signed', 'findings': [votes[i['id']]['reason'] for i in plan['items']
                                                  if i['case'] == case['id']]})
    public = {'schema_version': 1, 'round_id': plan['round_id'], 'review_mode': 'subagent',
        'signoff_status': 'signed', 'cases': published,
        'counts': {'scope': 'this_new_round', 'workflow_apps': len({c['family'] for c in cases}),
                   'independent_apps': 0, 'required_independent_apps': 10,
                   'reference_pairs': 0, 'required_reference_pairs': 100},
        'limits': ['本轮复核业务链与计分资格；未新增正式通用配对计分样本。',
                   '历史 HA 已签结果另列，不混入本轮参考范围。',
                   '同模型可能共享错误；subagent 参考不是真人真值。',
                   '历史采集重放不是新的设备实测，不输出法律违规结论。'],
        'bindings': {'plan_sha256': report['plan_sha256'], 'evidence_sha256': report['evidence_sha256'],
                     'review_a_sha256': report['review_sha256']['A'], 'review_b_sha256': report['review_sha256']['B'],
                     'signoff_sha256': digest(out / 'signoff-subagent.json')}}
    write_json(out / 'public-review.json', public)
    write_json(out / 'reference-metrics.json', {'status': 'not_measured', 'origin': 'subagent_review',
        'subagent_signoff': 'signed', 'human_signoff': 'not_applicable', 'precision': None,
        'recall': None, 'new_eligible_apps': 0, 'new_reference_positive_pairs': 0})
    return public


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('prepare', 'compare', 'finalize'))
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    result = {'prepare': prepare, 'compare': compare, 'finalize': finalize}[args.action](args.out)
    print(json.dumps({'out': str(args.out), 'scope': result.get('scope', result.get('review_mode'))}))


if __name__ == '__main__':
    main()
