"""车载 live 采集 + AI 复核端到端自检（仅授权测试：自有设备与自有 APK）。

演示/回归都能用：服务已在跑、设备已由 prepare-vehicle-device.ps1 备好即可。
    python tools/vehicle_demo_e2e.py --base http://127.0.0.1:8773 --serial emulator-5554

做四件事：
  1. 读 /api/config，确认 platform=vehicle 且 ai_configured=true
  2. 用 uiautomator 找到靶子三个按钮的坐标，预先给可授予的车载权限（避免运行时弹窗挡住点击）
  3. 以原始字节 POST 上传 APK，mode=live 提交任务
  4. 轮询任务，进入 capture 阶段后按「索权 → 读 VHAL → 外泄 HTTP」点一遍，直到任务结束
最后打印结论数量、AI 复核状态与产物路径；任一步失败以非零码退出。
"""
import argparse
import json
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path

BUTTONS = [('读取 VHAL', '读取 VHAL'), ('外泄 HTTP', '外泄 JSON（HTTP')]
# 「索权演示」不点：它会拉起运行时权限框，实测把应用拖死（original_process_alive=false），
# 随后 frida detach 卡住、reads worker 被强杀 → 整轮 capture_unhealthy。
# 权限类结论（VSC-P001~P006）来自清单静态分析，不需要点这个按钮。
# 可授予的 normal 权限；signature|privileged 的（CAR_IDENTIFICATION/MILEAGE/ENGINE_DETAILED）
# 授不了也不该授，靶子会如实记 DENIED —— 那正是要展示的分档。
GRANTS = ['android.car.permission.CAR_SPEED', 'android.car.permission.CAR_ENERGY',
          'android.car.permission.CAR_POWERTRAIN']


def adb(serial, *args, binary=False):
    result = subprocess.run(['adb', '-s', serial, *map(str, args)], capture_output=True, timeout=120)
    if result.returncode:
        raise RuntimeError(f'adb {args} 失败：{result.stderr.decode("utf-8", "replace")[:200]}')
    return result.stdout if binary else result.stdout.decode('utf-8', 'replace')


def request(url, data=None, headers=None, timeout=60):
    req = urllib.request.Request(url, data=data, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()


def buttons(serial):
    """从 uiautomator dump 取三个按钮的中心点；找不到就报清楚是哪一步。"""
    adb(serial, 'shell', 'rm', '-f', '/sdcard/ui.xml')
    adb(serial, 'shell', 'uiautomator', 'dump', '/sdcard/ui.xml')
    raw = adb(serial, 'shell', 'cat', '/sdcard/ui.xml')
    start = raw.find('<?xml')
    root = ET.fromstring(raw[start:] if start >= 0 else raw)
    found = {}
    for node in root.iter('node'):
        text = node.get('text') or ''
        bounds = node.get('bounds') or ''
        match = re.match(r'\[(\d+),(\d+)\]\[(\d+),(\d+)\]', bounds)
        if not match or not text:
            continue
        x1, y1, x2, y2 = map(int, match.groups())
        for label, needle in BUTTONS:
            if label in found or needle not in text:
                continue
            found[label] = ((x1 + x2) // 2, (y1 + y2) // 2)
    missing = [label for label, _ in BUTTONS if label not in found]
    if missing:
        raise RuntimeError(f'界面上找不到按钮：{missing}（先用 prepare-vehicle-device.ps1 拉起应用）')
    return found


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--base', default='http://127.0.0.1:8773')
    parser.add_argument('--serial', default='emulator-5554')
    parser.add_argument('--apk', default='vehicle/targets/target-app/app/build/outputs/apk/debug/app-debug.apk')
    parser.add_argument('--package', default='com.vscanner.targetapp')
    parser.add_argument('--user', default='10')
    parser.add_argument('--seconds', default='40')
    parser.add_argument('--timeout', type=int, default=600)
    args = parser.parse_args()

    status, body = request(f'{args.base}/api/config')
    config = json.loads(body)
    print(f"[config] {status} platform={config.get('platform')} ai_configured={config.get('ai_configured')}")
    if config.get('platform') != 'vehicle':
        sys.exit('不是车载工作台，停止。')
    if not config.get('ai_configured'):
        sys.exit('服务未启用 AI（缺 --ai-config）。先用 start-all.ps1 -Only vehicle 启动。')

    # 先给可授予的权限，避免运行时弹窗挡点击；授不了的是预期结果。
    for permission in GRANTS:
        try:
            adb(args.serial, 'shell', 'pm', 'grant', '--user', args.user, args.package, permission)
        except RuntimeError as error:
            print(f'[grant] {permission} 未授予（预期之内）：{str(error)[:80]}')

    points = buttons(args.serial)
    print('[ui] ' + '  '.join(f'{label}={xy}' for label, xy in points.items()))

    apk = Path(args.apk).read_bytes()
    query = (f'authorized=true&mode=live&serial={args.serial}&user={args.user}'
             f'&seconds={args.seconds}&version=15&scope=all&ai_review=true&name={Path(args.apk).name}')
    status, body = request(f'{args.base}/api/pipeline?{query}', data=apk,
                           headers={'Content-Type': 'application/vnd.android.package-archive'})
    if status != 202:
        sys.exit(f'提交失败 {status}：{body[:400].decode("utf-8", "replace")}')
    job = json.loads(body)['id']
    print(f'[submit] {job} 已受理')

    deadline = time.time() + args.timeout
    tapped, capture_seen = 0, False
    while time.time() < deadline:
        status, body = request(f'{args.base}/api/pipeline/{job}')
        snapshot = json.loads(body)
        state = snapshot.get('state')
        stages = {row.get('stage'): row.get('status') for row in snapshot.get('stage_timings') or []}
        if stages.get('capture') == 'running' and tapped == 0:
            # 两个约束：
            # ① 先等 hook 完成 ARMED（约 2–3 s），否则前两次点击落在挂载之前，一条 VHAL_READ 都采不到；
            # ② 只在窗口前段点一轮，外泄请求不要压在收尾时刻，否则 detach 会被在途请求拖住。
            time.sleep(7)
            capture_seen = True
            for label, _ in BUTTONS:
                adb(args.serial, 'shell', 'input', 'tap', *points[label])
                print(f'[tap] {label} @ {points[label]}')
                time.sleep(4)
            tapped += 1
        if state in ('done', 'failed', 'static_only'):
            break
        time.sleep(2)

    status, body = request(f'{args.base}/api/pipeline/{job}')
    snapshot = json.loads(body)
    print('-' * 60)
    print(f"state={snapshot.get('state')} findings={snapshot.get('findings_total')} "
          f"bands={snapshot.get('findings_by_conclusion_level')}")
    result = snapshot.get('result') or {}
    print(f"ai={json.dumps(result.get('ai'), ensure_ascii=False)}")
    print(f"capture_seen={capture_seen} tap_rounds={tapped} elapsed_ms={snapshot.get('stage_timings_elapsed_ms')}")
    print('-' * 60)
    for row in snapshot.get('stage_timings') or []:
        print(f"  {str(row.get('stage')):10} {str(row.get('status')):8} {row.get('duration_ms')} ms")
    if snapshot.get('state') != 'done':
        print(json.dumps(result, ensure_ascii=False)[:600])
        sys.exit(1)
    print(f'任务目录：output/vehicle-web/{job}')


if __name__ == '__main__':
    main()
