"""Phase 7 工作台的端到端验收：**真的反编译一个 APK**，并核对结果。

仅用于授权测试（自有设备与自有 APK）。用项目自己的夹具 APK，不碰第三方 APK。

为什么单独一个脚本、不进 `run_regressions.py`：这里要跑 jadx，一次约 20-30 秒
（3.6MB 夹具），而回归套件必须保持秒级、且不依赖 jadx 装没装。

    python tools/workbench_acceptance.py [--apk <自有APK>] [--session <采集会话目录>]

判据里有几条是**专门钉静默失败**的：
  * 属性名必须在 `classes3.dex` 里被找到——只扫第一个 dex 会得到 0 命中却毫无报错
  * 权限数必须与动态路径的 `requested-permissions.txt` 一致——两条路同源
  * 静态结论不得出现 `observed` 及以上等级
  * 部分反编译失败必须被记成缺口，而不是静默当成"类不存在"
"""
from __future__ import annotations

import argparse
import json
import sys
import tempfile
import time
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'phase7'))

import analysis      # noqa: E402
import apkmeta       # noqa: E402
import crosscheck    # noqa: E402
import dexfacts      # noqa: E402
import toolchain     # noqa: E402

DEFAULT_APK = ROOT / 'phase2/target-app/app/build/outputs/apk/debug/app-debug.apk'
EXPECTED_PROPERTY = 'GEAR_SELECTION'


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apk', type=Path, default=DEFAULT_APK)
    parser.add_argument('--session', type=Path, help='采集会话目录（用它的清单证明是同一个 APK）')
    parser.add_argument('--findings', type=Path, help='动态侧 findings.jsonl（在交付目录里）')
    parser.add_argument('--skip-decompile', action='store_true', help='只验静态链路，快得多')
    args = parser.parse_args()

    out = ROOT / 'output' / ('workbench-' + datetime.now().strftime('%Y%m%d-%H%M%S'))
    out.mkdir(parents=True)
    (ROOT / 'output/latest-workbench.txt').write_text(str(out), encoding='utf-8')
    checks: dict = {}
    details: dict = {}

    apk = args.apk.resolve()
    if not apk.exists():
        raise SystemExit(f'没有这个 APK：{apk}')

    started = time.time()
    digest, why = crosscheck.resolve_findings(args.session, args.findings)
    static = analysis.scan_static(apk, ROOT / 'phase1/rules_library/rules.db', '15', out)
    details['static_seconds'] = round(time.time() - started, 1)

    # 1) 权限：静态取到的必须与动态路径记录的**同一批**
    permissions = static.get('apk', {}).get('permissions', [])
    checks['permissions_extracted'] = len(permissions) > 0
    dynamic_perms_file = (args.session / 'requested-permissions.txt') if args.session else None
    if dynamic_perms_file and dynamic_perms_file.exists():
        dynamic = [l.strip() for l in dynamic_perms_file.read_text(encoding='utf-8').splitlines()
                   if l.strip()]
        checks['permissions_match_dynamic_path'] = sorted(dynamic) == sorted(permissions)
        details['permissions'] = {'static': sorted(permissions), 'dynamic': sorted(dynamic)}
    else:
        details['permissions'] = {'static': sorted(permissions),
                                  'dynamic': '未提供会话目录，跳过比对'}

    # 2) 多 dex：属性名必须在**非第一个** dex 里也被找到（夹具在 classes3.dex）
    with tempfile.TemporaryDirectory() as tmp:
        facts = dexfacts.scan(apk, toolchain.android_build_tool('dexdump'), Path(tmp))
    checks['multidex_scanned'] = len(facts.get('_per_dex', {})) >= 2
    checks['property_name_found'] = EXPECTED_PROPERTY in facts['strings']
    details['dex_files'] = sorted(facts.get('_per_dex', {}))
    details['dex_gaps'] = facts.get('gaps', [])

    # 3) 等级上限：静态结论绝不能到 observed 及以上
    levels = {f['conclusion_level'] for f in static.get('findings', [])}
    checks['static_capped_at_candidate'] = levels <= {'candidate'}

    # 4) 交叉核对（给了动态侧才做）
    if digest or args.session:
        result = analysis.crosscheck_with_session(out, crosscheck.sha256_of(apk), apk,
                                                  args.session, args.findings)
        details['crosscheck'] = {k: result.get(k) for k in ('comparable', 'counts', 'reason')}
        if result.get('comparable'):
            checks['crosscheck_comparable'] = True
            checks['crosscheck_identity_proven'] = result['identity']['same_apk'] is True

    # 5) 反编译（慢）
    if not args.skip_decompile:
        started = time.time()
        dec = analysis.decompile(apk, out, threads=4)
        details['decompile'] = {k: dec[k] for k in ('returncode', 'errors', 'classes_written',
                                                    'files')}
        details['decompile_seconds'] = round(time.time() - started, 1)
        details['decompile_gap'] = dec.get('gap')
        checks['decompile_produced_sources'] = dec['classes_written'] > 0
        # 部分失败必须是**缺口**，不能静默
        checks['partial_failure_is_a_gap'] = (dec['errors'] == 0) or bool(dec.get('gap'))

    result = dict(apk=str(apk), session=str(args.session) if args.session else None,
                  checks=checks, passed=all(checks.values()),
                  toolchain={k: v for k, v in toolchain.describe().items()
                             if not k.endswith('_error')}, details=details)
    (out / 'verification.json').write_text(json.dumps(result, ensure_ascii=False, indent=2),
                                           encoding='utf-8')
    print(json.dumps(result, ensure_ascii=False, indent=2))
    print('Evidence: ' + str(out), file=sys.stderr)
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
