"""B-side integrated acceptance, no device mutation. 仅用于授权测试。"""
import argparse
import json
import subprocess
from collections import Counter
from pathlib import Path

from vehicle.pipeline.contracts import ROOT, digest, write_json
from vehicle.privacy import location_handoff as handoff

CHECKLIST = [
    '新会话：commit、APK/规则/实际bundle、设备/API/user/PID和TLS开关有记录',
    'capture中reads/flows/verification/collector-health及摘要齐全，实际bundle归档',
    '正控：真实通用PRIVACY_READ/location_forms，完整请求和同轮接收回执',
    '负控：异值、单坐标不形成整对匹配；重复来源保留歧义',
    '第三方：自然工作流，不改App返回值或格式，明确触达/格式/输入缺口',
    '动作和回执绑定session及capture清单摘要；旧签核不迁移',
    '设备正控与第三方尝试分别展示，不混合规则、实验和业务计数',
]


def summarize(plan, rows):
    sessions = Counter(r.get('session_id') for r in rows if r.get('session_id'))
    for row in rows:
        if row.get('session_id') and sessions[row['session_id']] > 1:
            row.update(status='blocked', condition_met=False, reason_code='session_reused_across_cases')
    kinds = {kind: [r for r in rows if r['kind'] == kind] for kind in handoff.KINDS}
    controls = all(kinds[k] and all(r['condition_met'] for r in kinds[k]) for k in handoff.KINDS[:-1])
    attempted = bool(kinds['third_party']) and all(r.get('action_record_validated')
                                                  and r['condition_met'] for r in kinds['third_party'])
    synthetic = plan.get('input_kind') == 'synthetic'
    complete = bool(controls and attempted)
    return {'schema_version': 1, 'input_kind': plan.get('input_kind'), 'experimental_only': True,
        'status': 'synthetic_only' if complete and synthetic else 'completed' if complete else 'incomplete',
        'device_controls_verified': bool(controls and not synthetic),
        'third_party_attempt_recorded': bool(attempted and not synthetic),
        'third_party_supported_matches': sum(r.get('pair_count', 0) for r in kinds['third_party'])
                                         if not synthetic and attempted else None,
        'missing_case_kinds': [k for k in handoff.KINDS if not kinds[k]], 'cases': rows,
        'counts_by_status': dict(Counter(r['status'] for r in rows)),
        'checklist': CHECKLIST,
        'limits': ['声明的设备来源和动作属于交接记录，不等于独立人工金标准。',
                   '实验匹配不进入规则findings，不证明唯一因果或违规。',
                   '第三方没有支持的输入时可完成尝试记录，不能宣称通用检出通过。',
                   '合成验证不能代替设备定位正负控，不报告总体P/R。']}


def render(result):
    lines = ['# B侧定位交接验收', '', '状态：' + result['status'],
        '输入来源：' + str(result['input_kind']),
        '设备正负控已核验：' + str(result['device_controls_verified']),
        '第三方工作流尝试已记录：' + str(result['third_party_attempt_recorded']),
        '尚缺场景：' + ('、'.join(result['missing_case_kinds']) or '无'), '',
        '| case | 类型 | 状态 | 可比读取 | 可比请求 | 身份/窗口可比组合 | 实验候选 | 歧义流 | 原因 |',
        '|---|---|---|---|---|---|---|---|---|']
    for row in result['cases']:
        inputs = row.get('inputs') or {}
        values = [row['id'], row['kind'], row['status'], inputs.get('comparable_reads', '—'),
                  inputs.get('comparable_flows', '—'), inputs.get('compatible_comparisons', '—'),
                  row.get('pair_count', '—'),
                  row.get('ambiguous_flows', '—'), row.get('reason_code', '—')]
        lines.append('| ' + ' | '.join(str(v).replace('|', '\\|').replace('\n', ' ') for v in values) + ' |')
    lines += ['', '## 限制', *['- ' + text for text in result['limits']], '', '## 人工交接复核检查表',
              *['- [ ] ' + text for text in result['checklist']]]
    return '\n'.join(lines) + '\n'


def run(plan_path, output):
    plan_sha = digest(Path(plan_path))
    plan, base = handoff.load_plan(plan_path)
    output = Path(output).resolve()
    for entry in plan['cases']:
        if output.is_relative_to(handoff.resolve(base, entry.get('capture'))):
            raise handoff.UnsafeOutputError('acceptance_output_inside_source_capture')
    output.mkdir(parents=True, exist_ok=False)
    rows = []
    for entry in plan['cases']:
        rows.append(handoff.inspect_case(entry, base, output / entry['id']))
    result = summarize(plan, rows)
    if digest(Path(plan_path)) != plan_sha:
        result.update(status='handoff_changed', device_controls_verified=False,
                      third_party_attempt_recorded=False, third_party_supported_matches=None)
        for row in rows:
            row.update(status='blocked', condition_met=False, reason_code='handoff_changed')
        result['counts_by_status'] = dict(Counter(r['status'] for r in rows))
    for row in rows:
        write_json(output / row['id'] / 'acceptance.json', row)
    result['handoff_sha256'] = plan_sha
    result['declared_baseline'] = plan.get('baseline_commit')
    git = subprocess.run(['git', 'rev-parse', 'HEAD'], cwd=ROOT, capture_output=True, text=True)
    result['implementation_commit'] = git.stdout.strip() if git.returncode == 0 else None
    result['implementation_sha256'] = {p.name: digest(p) for p in (Path(__file__), Path(handoff.__file__))}
    write_json(output / 'acceptance.json', result)
    (output / 'REPORT.md').write_text(render(result), encoding='utf-8')
    return result


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--handoff', type=Path, required=True)
    ap.add_argument('--out', type=Path, required=True)
    args = ap.parse_args(argv)
    if args.out.exists():
        ap.error('Use a new output directory')
    try:
        result = run(args.handoff, args.out)
    except (OSError, ValueError, TypeError, KeyError) as exc:
        if isinstance(exc, (FileExistsError, handoff.UnsafeOutputError)):
            ap.error('Output already exists or is inside source capture; evidence was not changed')
        args.out.mkdir(parents=True, exist_ok=True)
        write_json(args.out / 'failure.json', {'status': 'acceptance_failed', 'type': type(exc).__name__,
                                              'reason': str(exc)})
        return 2
    print(json.dumps({'out': str(args.out), 'status': result['status']}, ensure_ascii=False))
    return 0 if result['status'] in ('completed', 'synthetic_only') else 2


if __name__ == '__main__':
    raise SystemExit(main())
