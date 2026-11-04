"""Paired Hook-overhead statistics and a readable report. 仅用于授权测试。

Only process CPU time and host wall time on an owned fixture are measured.
There is no independent label set here, so this module never reports accuracy.
"""
import math
import statistics


def p95(values):
    return sorted(values)[math.ceil(.95 * len(values)) - 1] if values else None


def cpu_ms(stat_text):
    """utime+stime from /proc/<pid>/stat; Android USER_HZ is 100."""
    fields = stat_text.rsplit(')', 1)[1].split()
    return (int(fields[11]) + int(fields[12])) * 10


def summarize(runs):
    paired = {}
    failed = []
    failed_pairs = set()
    for run in runs:
        if run.get('passed') is not True or 'error' in run or 'cpu_ms' not in run or 'wall_ms' not in run:
            # A crashed arm is not zero overhead: report it separately and skip the pair.
            failed.append({'pair': run.get('pair'), 'arm': run.get('arm'),
                           'error': run.get('error') or ('run_not_passed' if run.get('passed') is not True
                                                        else 'missing cpu_ms/wall_ms'),
                           'hook_errors': run.get('hook_errors'), 'cleanup': run.get('cleanup')})
            failed_pairs.add(run.get('pair'))
            continue
        paired.setdefault(run['pair'], {})[run['arm']] = run
    rows, skipped = [], set(failed_pairs)
    for index in sorted(paired):
        arms = paired[index]
        if index in failed_pairs or set(arms) != {'with_hook', 'without_hook'}:
            skipped.add(index)
            continue
        base, hooked = arms['without_hook'], arms['with_hook']
        rows.append({'pair': index, 'first_arm': base['arm'] if base['order'] == 1 else hooked['arm'],
            'cpu_without_ms': base['cpu_ms'], 'cpu_with_ms': hooked['cpu_ms'],
            'cpu_delta_ms': hooked['cpu_ms'] - base['cpu_ms'],
            'wall_without_ms': base['wall_ms'], 'wall_with_ms': hooked['wall_ms'],
            'wall_delta_ms': round(hooked['wall_ms'] - base['wall_ms'], 1),
            'actions_without': base['actions'], 'actions_with': hooked['actions'],
            'hook_read_events': hooked.get('hook_read_events'),
            'primary_read_events': hooked.get('primary_read_events'),
            'nested_suppressed': hooked.get('nested_suppressed'),
            'read_events_accounted': hooked.get('read_events_accounted'),
            'hook_egress_events': hooked.get('hook_egress_events')})
    deltas = [r['cpu_delta_ms'] for r in rows]
    walls = [r['wall_delta_ms'] for r in rows]
    base_cpu = [r['cpu_without_ms'] for r in rows]
    median_delta = statistics.median(deltas) if deltas else None
    if median_delta is None:
        interpretation = '没有可用的配对数据。'
    elif median_delta <= 0:
        interpretation = ('中位增量 ≤ 0：本轮出现负增量，说明夹具的 CPU 噪声大于 Hook 开销；'
            '不能据此宣称 Hook 无开销，也不能把负值当成加速。')
    else:
        interpretation = '中位增量为正，仅代表该夹具该工作负载下的稳态执行成本。'
    summary = {'paired_runs': len(rows), 'skipped_pairs': sorted(skipped), 'failed_runs': failed,
        'pairs': rows,
        'cpu_delta_ms': {'min': min(deltas) if deltas else None,
            'median': median_delta,
            'mean': round(statistics.fmean(deltas), 1) if deltas else None,
            'p95': p95(deltas),
            'max': max(deltas) if deltas else None},
        'cpu_relative_percent': (round(statistics.median(deltas) /
            statistics.median(base_cpu) * 100, 1) if deltas and statistics.median(base_cpu) else None),
        'interpretation': interpretation,
        'wall_delta_ms': {'min': min(walls) if walls else None,
            'median': round(statistics.median(walls), 1) if walls else None,
            'mean': round(statistics.fmean(walls), 1) if walls else None,
            'p95': p95(walls),
            'max': max(walls) if walls else None},
        'accuracy': {'status': 'not_measured',
            'reason': '没有独立人工标注；CPU/墙钟开销不能冒充检测准确率。'},
        'caveats': ['仅自有 AAOS 夹具与 plain 工作负载；不能外推到第三方 App。',
            'CPU 只取应用进程，不含 frida-server 与主机 ADB/轮询开销。',
            '只测 Hook 稳态执行；attach/detach 成本不在测量窗口内。',
            '墙钟包含 adb shell 轮询与代理转发，抖动大于 CPU 指标。']}
    return summary


def render_markdown(report, environment, pairs, actions):
    lines = ['# Hook 开销配对测量（自有 AAOS 夹具）', '',
        '仅用于授权测试。有/无 Hook 交替执行同一工作负载，按配对比较。', '',
        '## 环境', '']
    lines += ['- %s: %s' % (key, value) for key, value in environment.items()]
    lines += ['', '## 工作负载', '',
        '- 模式: `plain`（读取 8 个 VHAL 属性并 POST 到 `/collect`）',
        '- 每轮动作数: %d；配对数: %d；两臂交替先后顺序' % (actions, pairs), '',
        '## 结果', '',
        '| 配对 | 先执行 | 无 Hook CPU ms | 有 Hook CPU ms | CPU 增量 ms | 墙钟增量 ms | VHAL 事件 | 主读取 | 嵌套合并 | 外发事件 |',
        '| ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |']
    for row in report['pairs']:
        lines.append('| %d | %s | %s | %s | %s | %s | %s | %s | %s | %s |' % (row['pair'], row['first_arm'],
            row['cpu_without_ms'], row['cpu_with_ms'], row['cpu_delta_ms'], row['wall_delta_ms'],
            row['hook_read_events'], row['primary_read_events'], row['nested_suppressed'], row['hook_egress_events']))
    cpu = report['cpu_delta_ms']
    wall = report['wall_delta_ms']
    lines += ['', '## 汇总', '',
        '- 应用进程 CPU 增量中位 %s ms / P95 %s ms / 范围 %s–%s ms' % (
            cpu['median'], cpu['p95'], cpu['min'], cpu['max']),
        '- 相对无 Hook 基线: %s%%' % report['cpu_relative_percent'],
        '- 主机墙钟增量中位 %s ms / P95 %s ms / 范围 %s–%s ms' % (
            wall['median'], wall['p95'], wall['min'], wall['max']),
        '- 解读: %s' % report['interpretation'],
        '- 检测准确率: **未测量**（%s）' % report['accuracy']['reason'], '',
        '## 限制', '']
    lines += ['- ' + item for item in report['caveats']]
    if report['failed_runs']:
        lines += ['', '## 失败的轮次', '',
            '以下轮次没有产生配对数据，按失败记录，未计入开销：', '']
        lines += ['- 配对 %s / %s: `%s`' % (row['pair'], row['arm'], row['error'])
            for row in report['failed_runs']]
    lines += ['', '原始逐轮数据见 `runs.jsonl`；机器可读汇总见 `overhead.json`。']
    return '\n'.join(lines) + '\n'
