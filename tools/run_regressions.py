"""离线回归入口；记录退出码与完整日志，任何失败均返回非零。"""
import json
import subprocess
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CHECKS = [
    ('completion', '.', [sys.executable, '-m', 'unittest', 'test_completion']),
    ('rules-contract', 'core', [sys.executable, '-m', 'unittest', 'test_rules_contract']),
    ('codeloc', 'core/evidence', [sys.executable, '-m', 'unittest', 'test_codeloc',
                           'test_event_lookup']),
    ('correlate', 'phase5', [sys.executable, '-m', 'unittest', 'test_experiment']),
    # 归因/载荷/失败流落盘/报文扫描是平台无关的，已抽到 core/collector/；
    # 车载 VHAL 指纹表留在 phase4。
    ('collector', 'core/collector', [sys.executable, '-m', 'unittest', 'test_body',
                                     'test_attribution', 'test_unanswered',
                                     'test_experiment']),
    ('tagging-vehicle', 'phase4', [sys.executable, '-m', 'unittest', 'test_tagging']),
    ('dashboard', 'phase6', [sys.executable, '-m', 'unittest', 'test_dashboard']),
    ('runtime', 'phase3', ['node', 'test_runtime.mjs']),
    ('parity', 'phase1', [sys.executable, 'android/tools/verify_schema_parity.py']),
    # core/static 的用例全部离线（不需要 jadx、不需要设备、不需要 APK）。
    # 需要真的反编译的验证在 tools/workbench_acceptance.py，那里慢，不进回归。
    ('workbench', 'core/static', [sys.executable, '-m', 'unittest',
                             'test_static_rules', 'test_crosscheck', 'test_jobs']),
]


def main():
    out = ROOT / 'output' / ('regression-' + datetime.now().strftime('%Y%m%d-%H%M%S'))
    out.mkdir(parents=True)
    (ROOT / 'output/latest-regression.txt').write_text(str(out), encoding='utf-8')
    results = []
    for name, cwd, command in CHECKS:
        process = subprocess.run(command, cwd=ROOT / cwd, capture_output=True,
                                 encoding='utf-8', errors='replace', timeout=120)
        (out / (name + '.log')).write_text(process.stdout + process.stderr, encoding='utf-8')
        results.append(dict(name=name, exit_code=process.returncode))
        print(name, process.returncode, flush=True)
    (out / 'verification.json').write_text(json.dumps(results, indent=2), encoding='utf-8')
    return int(any(r['exit_code'] != 0 for r in results))


if __name__ == '__main__':
    raise SystemExit(main())
