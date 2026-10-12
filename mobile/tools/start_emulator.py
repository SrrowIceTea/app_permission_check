#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""以**强制抓包**模式启动模拟器：流量绕不过代理 + 系统级信任代理 CA。

仅用于授权测试（自有设备 / 已授权的公开第三方样本）。

为什么需要它（三件事必须一起做才有用）：

  1. `-http-proxy http://10.0.2.2:8888`
     在 SLIRP 层把 TCP 连接交给代理。**应用无法绕过**——实测 NewPipe 用
     loopj/AsyncHttpClient，完全不理 `settings put global http_proxy`，
     而这一层对它有效。这是"flows.jsonl 为空"的根因。
  2. `-writable-system`
     否则 `adb remount` 报 "Device must be bootloader unlocked"，系统 CA 装不进去。
  3. 装系统 CA
     流量被导到代理后，HTTPS 仍会因证书校验失败而断。系统级 CA 让**所有**应用
     信任代理证书，不必逐 App 上 TLS 绕过钩子（钩子只对愿意用它的进程生效）。

**重启模拟器会打断同机上其他正在跑的采集**（例如别人正在跑的 native hook 实验），
所以本脚本不会自动重启——它检查现状、给出该执行的命令、并在你确认后启动。

用法：
    python start_emulator.py --avd VScan_Phone              # 启动并装 CA
    python start_emulator.py --avd VScan_Phone --dry-run    # 只看会执行什么
    python start_emulator.py --status                       # 只看当前抓包能力
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(ROOT / "mobile" / "traffic"))
import transparent as tp  # noqa: E402

EMULATOR = "D:/Anroid/SDK/emulator/emulator.exe"
ADB = tp.ADB
BASE_ARGS = ["-no-boot-anim", "-gpu", "auto"]


def adb(*args: str, timeout: int = 60) -> subprocess.CompletedProcess:
    return subprocess.run([ADB, *args], capture_output=True, text=True,
                          encoding="utf-8", errors="replace", timeout=timeout)


def running_emulators() -> list[str]:
    out = adb("devices", timeout=30).stdout
    return [ln.split("\t")[0] for ln in out.splitlines()
            if ln.startswith("emulator-") and "device" in ln]


def wait_boot(timeout_s: int = 300) -> bool:
    end = time.time() + timeout_s
    while time.time() < end:
        if adb("shell", "getprop", "sys.boot_completed", timeout=20).stdout.strip() == "1":
            return True
        time.sleep(5)
    return False


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--avd", default="VScan_Phone")
    ap.add_argument("--port", type=int, default=tp.MITM_PORT)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--status", action="store_true")
    ap.add_argument("--keep-global-proxy", action="store_true",
                    help="不清理设备上的 http_proxy 设置（默认清理：有了强制代理它就是多余的，"
                         "留着反而可能双重代理）")
    args = ap.parse_args()

    if args.status:
        print(json.dumps(tp.capture_verdict(), ensure_ascii=False, indent=2))
        return 0

    capture_args = tp.emulator_capture_args(port=args.port)
    cmd = [EMULATOR, "-avd", args.avd, *BASE_ARGS, *capture_args]

    live = running_emulators()
    print(json.dumps({
        "avd": args.avd,
        "会执行的命令": " ".join(cmd),
        "当前在跑的模拟器": live,
        "注意": ("重启模拟器会打断同机上其他正在跑的采集（如 native hook 实验）；"
                 "若别人在用，先停手" if live else "当前没有模拟器在跑，可以直接起"),
    }, ensure_ascii=False, indent=2))
    if args.dry_run:
        return 0

    if live and sys.stdin.isatty():
        answer = input(f"\n有 {len(live)} 个模拟器在跑，确认重启/再起一个？[y/N] ").strip().lower()
        if answer != "y":
            print("已取消。")
            return 1
    elif live:
        print("[refuse] 有模拟器在跑且非交互模式：请先手动确认（-p 需要人确认重启），"
              "避免打断别人的采集。", file=sys.stderr)
        return 2

    print("[start] 启动模拟器…")
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            stdin=subprocess.DEVNULL)
    if not wait_boot():
        print("[fail] 模拟器未在超时内启动完成", file=sys.stderr)
        return 3

    # 系统 CA：装进 /system 的信任库，所有应用都信任代理证书
    print("[ca] 安装系统 CA…")
    ca = tp.install_system_ca()
    print(json.dumps(ca, ensure_ascii=False, indent=2)[:600])
    if not ca.get("installed"):
        print("[warn] 系统 CA 未装上：HTTPS 仍会断。看 ca.error 的说明。", file=sys.stderr)

    if not args.keep_global_proxy:
        cur = tp.adb("shell", "settings", "get", "global", "http_proxy", timeout=30).stdout.strip()
        if cur not in ("null", "", ":0"):
            tp.adb("shell", "settings", "put", "global", "http_proxy", ":0", timeout=30)
            print(f"[proxy] 已清理设备全局代理（原值 {cur!r}）——强制代理已覆盖它")

    print(json.dumps({
        "status": "ready",
        "emulator_pid": proc.pid,
        "抓包": "SLIRP 层强制走代理，应用绕不过",
        "CA": "已装系统信任库" if ca.get("installed") else "未装（HTTPS 会断）",
        "下一步": "直接跑 mobile/tools/batch_thirdparty.py；mitmproxy 仍是常规代理模式，无需改参数",
    }, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
