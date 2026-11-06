"""离线回归入口；记录退出码与完整日志，任何失败均返回非零。"""
import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from core.regression_output import create_output, publish_latest
CHECKS = [
    ('completion', '.', [sys.executable, '-m', 'unittest', 'test_completion']),
    ('rules-contract', 'core', [sys.executable, '-m', 'unittest', 'test_rules_contract']),
    # event_store 的存储不变量此前错位在仓库根的 test_completion.py 里（§8.2 B-5）——
    # 拆到被测模块旁边，并单独成组，改 core 的人跑得到。
    ('event-store', 'core', [sys.executable, '-m', 'unittest', 'test_event_store']),
    ('codeloc', 'core/evidence', [sys.executable, '-m', 'unittest', 'test_codeloc',
                           'test_event_lookup']),
    ('correlate', 'vehicle/analyze', [sys.executable, '-m', 'unittest', 'test_experiment']),
    ('vehicle-evidence', '.', [sys.executable, '-m', 'unittest',
                              'vehicle.analyze.test_vehicle_evidence', 'vehicle.analyze.test_context',
                              'core.collector.test_vehicle_lifecycle']),
    ('vehicle-pipeline', '.', [sys.executable, '-m', 'unittest',
        'vehicle.pipeline.test_preflight', 'vehicle.pipeline.test_audit',
        'core.test_regression_output',
        'vehicle.pipeline.test_bundle',
        'vehicle.pipeline.test_scenarios', 'vehicle.coverage.test_coverage',
        'vehicle.policy.test_assessment', 'vehicle.bench.test_metrics', 'vehicle.bench.test_suite',
        'vehicle.bench.test_blind_round', 'vehicle.bench.test_subagent_signoff', 'vehicle.bench.test_handoff',
        'vehicle.bench.test_overhead',
        'core.frida_host.test_message_stream', 'core.frida_host.test_shutdown',
        'vehicle.bench.test_window_calibration',
        'core.collector.test_scope', 'core.collector.test_response_capture', 'core.collector.test_health',
        'core.collector.test_parse',
        'vehicle.pipeline.test_environment', 'vehicle.pipeline.test_acceptance',
        'vehicle.pipeline.test_diagnostics', 'vehicle.privacy.test_evaluation', 'vehicle.privacy.test_versions',
        'vehicle.pipeline.test_capture_lifecycle',
        'vehicle.pipeline.test_capture_proxy',
        'vehicle.privacy.test_observation', 'vehicle.privacy.test_ha_evaluation',
        'vehicle.lab.test_evidence_repairs', 'vehicle.lab.test_owntracks_run',
        'vehicle.lab.test_owntracks_permissions', 'vehicle.lab.test_mg4_write',
        'vehicle.rules.android.tools.test_recovery_acceptance',
        'vehicle.privacy.test_ha_socket_evidence']),
    # 归因/载荷/失败流落盘/报文扫描是平台无关的，已抽到 core/collector/；
    # 车载 VHAL 指纹表留在 vehicle/traffic。
    ('collector', 'core/collector', [sys.executable, '-m', 'unittest', 'test_body',
                                     'test_attribution', 'test_unanswered',
                                     'test_redaction',
                                     'test_system_probe',
                                     'test_experiment', 'test_montecarlo',
                                     'test_uid_sampler', 'test_targets', 'test_native_write']),
    ('tagging-vehicle', 'vehicle/traffic', [sys.executable, '-m', 'unittest', 'test_tagging']),
    ('dashboard', 'vehicle/dashboard', [sys.executable, '-m', 'unittest', 'test_dashboard']),
    ('runtime', 'vehicle/hooks', ['node', 'test_runtime.mjs']),
    ('privacy-runtime', 'vehicle/hooks', ['node', 'test_privacy.mjs']),
    ('parity', 'vehicle/rules', [sys.executable, 'android/tools/verify_schema_parity.py']),
    # core/static 的用例全部离线（不需要 jadx、不需要设备、不需要 APK）。
    # 需要真的反编译的验证在 tools/workbench_acceptance.py，那里慢，不进回归。
    ('workbench', 'core/static', [sys.executable, '-m', 'unittest',
                             'test_static_rules', 'test_crosscheck', 'test_jobs',
                             'test_analysis']),
    # 验收脚本点名的钩子 bundle 必须解析得到。改名/抽取时"引用没跟着改"会
    # **离线全绿、真跑才炸**（2026-10-12 实测：device_acceptance 漏改两个路径）。
    # 这条不需要设备，纯粹查"脚本点名 -> 文件在不在"。
    ('hook-bundles', 'tools', [sys.executable, '-m', 'unittest', 'test_hook_bundles']),
    # bundle 占位符替换（A1 分档新增 watch-limit / no-stack）必须保持长度头自洽——
    # 替换错了不会报错，只会让设备拒绝加载，症状与"钩子没挂上"一样。纯离线。
    ('frida-bundle-config', 'core/frida_host',
     [sys.executable, '-m', 'unittest', 'test_bundle_config']),
]

# 工程-7（2026-10-16 定语义）：`--mobile` 时在 16 组之后追加移动侧 29 项检查。
# 语义定为：**移动侧失败 = 根回归失败（非零退出）**——"根回归绿了但移动端已经烂了"
# 的静默状态正是文档状态列不可信教训的来源；不想让移动侧影响结论时，
# 直接跑本入口（不带 --mobile）或单独跑 mobile/tools/run_mobile_checks.py 即可。
# 移动侧整批依赖 requirements.txt（reportlab/Pillow/mitmproxy/…），解释器缺包时会
# 冒出假红——见 AGENTS.md「先确认解释器再判红」，故给它单独的宽松超时。
MOBILE_GROUP = ('mobile-checks', 'mobile/tools', [sys.executable, 'run_mobile_checks.py'])
MOBILE_TIMEOUT = 600
PREPARE_TIMEOUT = 1000


def run_check(out, name, cwd, command, timeout):
    with (out / (name + '.log')).open('w', encoding='utf-8') as log:
        try:
            process = subprocess.run(command, cwd=ROOT / cwd, stdout=log, stderr=subprocess.STDOUT,
                                     timeout=timeout, env={**os.environ, 'PYTHONIOENCODING': 'utf-8'})
            return dict(name=name, exit_code=process.returncode)
        except subprocess.TimeoutExpired:
            log.write(f'\n{name} 超时（{timeout} 秒）。\n')
            return dict(name=name, exit_code=124, status='timeout')


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--mobile', action='store_true',
                    help='追加跑移动侧 29 项检查（mobile/tools/run_mobile_checks.py），'
                         '失败计入根回归失败（语义见 MOBILE_GROUP 注释）')
    ap.add_argument('--prepare', action='store_true', help='先按锁文件准备 Hook 产物，用于干净检出')
    ap.add_argument('--out', type=Path, help='本次回归日志目录，必须是新目录')
    args = ap.parse_args()
    out = create_output(ROOT, 'regression', args.out)
    publish_latest(ROOT / 'output/latest-regression.txt', out)
    name, cwd, command = MOBILE_GROUP
    mobile_group = (name, cwd, [*command, '--out', str(out / 'mobile')])
    checks = [*CHECKS, mobile_group] if args.mobile else list(CHECKS)
    if args.prepare:
        checks.insert(0, ('prepare', '.', [sys.executable, '-m', 'vehicle', 'prepare',
                                           '--install-deps', '--out', str(out / 'prepare')]))
    timeouts = {'prepare': PREPARE_TIMEOUT, 'mobile-checks': MOBILE_TIMEOUT}
    results = []
    for name, cwd, command in checks:
        result = run_check(out, name, cwd, command, timeouts.get(name, 120))
        results.append(result)
        print(name, result['exit_code'], flush=True)
        if name == 'prepare' and result['exit_code']:
            break
    (out / 'verification.json').write_text(json.dumps(results, indent=2), encoding='utf-8')
    return int(any(r['exit_code'] != 0 for r in results))


if __name__ == '__main__':
    raise SystemExit(main())
