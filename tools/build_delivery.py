"""仅用于授权测试：从通过的真实设备会话生成最终报告、核对和看板。"""
import hashlib
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# adb 定位：VSCAN_ADB 覆盖 > PATH 上的 adb > 本机 SDK 默认位置（理由同 device_acceptance.py）。
ADB = (os.environ.get('VSCAN_ADB') or shutil.which('adb')
       or 'D:/Anroid/SDK/platform-tools/adb.exe')
if not Path(ADB).exists():
    raise SystemExit(f'找不到 adb：{ADB}（设 VSCAN_ADB，或把 platform-tools 加进 PATH）')
# SDK 根由 adb 位置反推（.../platform-tools/adb.exe）。旧版本把 'E:/Android/android-sdk'
# 写进子进程环境，而且是**覆盖**而非兜底，换机器后 dexlines.py 等子进程全部拿到错路径。
SDK_ROOT = Path(ADB).resolve().parents[1]


def check_manifest(source: Path) -> dict:
    """核对采集时的会话清单。

    原有的检查（拉下来的 APK == 本地构建）只证明"现在装机的 == 现在构建的"，
    **证明不了它就是产生这批日志的那个版本**。清单记的是采集当时的哈希，
    两者一比对才能回答"这份报告针对哪个 APK、哪套规则、哪段钩子代码"。

    对旧 session（没有清单）用**具名报错**说明缺什么，而不是让它悄悄跳过。
    """
    manifest_path = source / 'session-manifest.json'
    if not manifest_path.exists():
        raise ValueError(
            f'{source} 没有 session-manifest.json（该会话由加固前的 device_acceptance 采集）。'
            '无法证明报告对应的 APK/规则/bundle 版本；请在当前版本重跑设备验收。')
    manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
    expected = manifest.get('installed_apk_sha256')
    if not expected:
        raise ValueError(f"会话清单里没有装机 APK 哈希（采集时就没算成："
                         f"{manifest.get('installed_apk_hash_error')}），无法证明版本一致性")
    return manifest


def main():
    source = Path((ROOT / 'output/latest-device.txt').read_text(encoding='utf-8'))
    verification = json.loads((source / 'verification.json').read_text(encoding='utf-8'))
    if not verification['passed']:
        raise ValueError('最近设备会话未通过，不能生成通过报告')
    manifest = check_manifest(source)
    out = ROOT / 'output' / ('delivery-' + datetime.now().strftime('%Y%m%d-%H%M%S'))
    out.mkdir(parents=True)
    env = dict(os.environ, PYTHONUTF8='1', ANDROID_SDK_ROOT=str(SDK_ROOT))

    def command(args, name, accepted=(0,)):
        result = subprocess.run(list(map(str, args)), cwd=ROOT, env=env, capture_output=True,
                                encoding='utf-8', errors='replace', timeout=180)
        (out / (name + '.log')).write_text(result.stdout + result.stderr, encoding='utf-8')
        if result.returncode not in accepted:
            raise RuntimeError(f'{name}: exit={result.returncode}, see {out / (name + ".log")}')
        return result.stdout

    dump = command([ADB, '-s', 'emulator-5554', 'shell', 'dumpsys', 'package', 'com.vscanner.targetapp'], 'package')
    collecting = False; permissions = []
    for line in dump.splitlines():
        if 'requested permissions:' in line:
            collecting = True
        elif collecting:
            value = line.strip()
            if value.endswith('permissions:') or not value:
                break
            if value.startswith('android.'):
                permissions.append(value)
    if not permissions:
        raise ValueError('未读取到清单权限，禁止用空权限继续')
    (out / 'requested-permissions.txt').write_text('\n'.join(permissions) + '\n', encoding='utf-8')
    installed = command([ADB, '-s', 'emulator-5554', 'shell', 'pm', 'path', 'com.vscanner.targetapp'], 'apk-path').strip()
    apk_path = installed.splitlines()[0].removeprefix('package:')
    command([ADB, '-s', 'emulator-5554', 'pull', apk_path, out / 'installed.apk'], 'pull-apk')
    built = ROOT / 'phase2/target-app/app/build/outputs/apk/debug/app-debug.apk'
    digest = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
    if digest(built) != digest(out / 'installed.apk'):
        raise ValueError('装机APK与通过验收的Debug构建不一致')
    # 与**采集当时**的哈希比对。上面那条只证明"现在装机的 == 现在构建的"，
    # 若 APK 在采集之后、出报告之前被换过（重装、调试、自更新），它照样通过。
    pulled = digest(out / 'installed.apk')
    if manifest['installed_apk_sha256'] != pulled:
        raise ValueError(f"装机APK与会话清单不一致：采集时 {manifest['installed_apk_sha256']}，"
                         f"现在 {pulled}。这批日志不是这个 APK 产生的，拒绝出报告。")
    rules = ROOT / 'phase1/rules_library/rules.db'
    command([sys.executable, ROOT / 'phase5/correlate.py', '--rules', rules,
        '--reads', source / 'reads.jsonl', '--egress', source / 'egress.jsonl', '--flows', source / 'flows.jsonl',
        '--permissions', out / 'requested-permissions.txt', '--session', verification['session'],
        '--out', out / 'findings.jsonl', '--summary', out / 'summary.json'], 'correlate')
    command([sys.executable, ROOT / 'core/evidence/dexlines.py', '--apk', out / 'installed.apk',
        '--verify', out / 'findings.jsonl', '--cache', out / 'dex-index.json', '--out', out / 'dex-verification.json'], 'dex', (0, 1))
    dex = json.loads((out / 'dex-verification.json').read_text(encoding='utf-8'))
    if not dex.get('dex_index_available') or set(dex['by_status']) - {'VERIFIED', 'INCOMPLETE'}:
        raise ValueError('存在源码行号不匹配或DEX不可用，禁止继续报告流水线')
    # `set({}) - {...}` 是空集！零条核对会**通过**上面那行。而"一条都没核对"
    # 与"全部核对通过"在报告里长得一模一样（都是没有徽章），必须单独拦。
    if not dex.get('checks_total'):
        raise ValueError(f"本轮没有任何代码位置可核对（checks_total={dex.get('checks_total')}）——"
                         "这通常意味着事件编号歧义或钩子没采到栈，不是「全部通过」")
    # native回调没有运行时行号时保留INCOMPLETE和定位缺口；不伪造全量通过徽章。
    command([sys.executable, ROOT / 'phase5/ownership.py', '--flows', source / 'flows.jsonl',
        '--cache', ROOT / 'output/completion/rdap-cache', '--out', out / 'ownership.json'], 'ownership')
    command([sys.executable, ROOT / 'phase5/report.py', '--rules', rules, '--findings', out / 'findings.jsonl',
        '--summary', out / 'summary.json', '--flows', source / 'flows.jsonl', '--ownership', out / 'ownership.json',
        '--out', out / 'audit-report.pdf'], 'report')
    command([sys.executable, ROOT / 'phase6/dashboard.py', '--rules', rules, '--findings', out / 'findings.jsonl',
        '--summary', out / 'summary.json', '--verify', out / 'dex-verification.json', '--out', out / 'dashboard.html'], 'dashboard')
    # 无响应请求：不进 findings（它们不构成外发证据），但**必须在交付里如实记数**——
    # "发出去了但没收到响应"与"没有外发"是两件事，只躺在 session 目录里等于没人知道。
    unanswered_path = source / 'flows-unanswered.jsonl'
    unanswered = (unanswered_path.read_text(encoding='utf-8').splitlines()
                  if unanswered_path.exists() else [])
    if unanswered:
        print(f'注意：本次采集有 {len(unanswered)} 条请求未收到响应，详见 {unanswered_path}', flush=True)
    provenance = dict(source_session=str(source), device_verification=verification,
        installed_apk_sha256=digest(out / 'installed.apk'), rules_sha256=digest(rules),
        source_hashes={name: digest(source / name) for name in ('reads.jsonl', 'egress.jsonl', 'flows.jsonl')},
        # 采集时的版本清单：报告针对哪个 APK / 哪套规则 / 哪段钩子代码
        session_manifest=manifest,
        unanswered_requests=len(unanswered))
    (out / 'provenance.json').write_text(json.dumps(provenance, indent=2, ensure_ascii=False), encoding='utf-8')
    (ROOT / 'output/latest-delivery.txt').write_text(str(out), encoding='utf-8')
    print(str(out), flush=True)


if __name__ == '__main__':
    main()
