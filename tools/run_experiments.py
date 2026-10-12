"""离线实验入口：产出可写进报告/论文的量化结论，不需要设备。

与 `run_regressions.py` 的分工：那边判"有没有坏"（全绿才算过），
这边**不做通过/失败判定**，只产出数字。把两者混在一起会让"实验跑出来的结论
不符合预期"被误当成测试失败而删掉——这正是实验最该保留的东西。

每轮写到独立的 `output/experiment-<时间戳>/`，并把 latest 指针指过去。
"""
import json
import subprocess
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# (名字, 工作目录, 命令, 产出文件名)
EXPERIMENTS = [
    ('attribution', 'phase4',
     [sys.executable, 'experiment_attribution.py', '--out', '{out}/attribution.json'],
     'attribution.json'),
    ('correlation', 'phase5',
     [sys.executable, 'experiment_correlation.py', '--out', '{out}/correlation.json'],
     'correlation.json'),
]


def main() -> int:
    out = ROOT / 'output' / ('experiment-' + datetime.now().strftime('%Y%m%d-%H%M%S'))
    out.mkdir(parents=True)
    (ROOT / 'output/latest-experiment.txt').write_text(str(out), encoding='utf-8')
    index = []
    for name, cwd, command, produced in EXPERIMENTS:
        args = [a.format(out=out) for a in command]
        result = subprocess.run(args, cwd=ROOT / cwd, capture_output=True,
                                encoding='utf-8', errors='replace', timeout=600)
        (out / (name + '.log')).write_text(result.stdout + result.stderr, encoding='utf-8')
        index.append(dict(name=name, exit_code=result.returncode,
                          output=produced if (out / produced).exists() else None))
        print(f'{name}: exit={result.returncode} -> {produced}', flush=True)
    (out / 'index.json').write_text(json.dumps(index, indent=2, ensure_ascii=False) + '\n',
                                    encoding='utf-8')
    print(str(out), flush=True)
    # 实验脚本的非零退出码表示"解析预测与实现不符"（见 experiment_attribution 的交叉核对），
    # 那是真问题，要往外传。
    return int(any(item['exit_code'] != 0 for item in index))


if __name__ == '__main__':
    raise SystemExit(main())
