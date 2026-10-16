#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""夹具阳性对照自检（A3）——批前必跑：先证明"采集链路活着"，再开始出批。

仅用于授权测试（已获授权的样本与设备）。

为什么必须有：批次 1 出批时 5 个样本 44 条结论 100% 是静态 over_permission、
运行时零产出——A1（挂全套钩子把应用打死）没有任何判据拦得住，全靠人翻文件。
**"采不到"与"应用没收集"在结果文件里长得一模一样**，本自检把这二者分开：
装夹具 → 挂钩（privacy+consent）→ 点 1 个按钮（btnDeviceId）→ 断言 reads.jsonl
出现 ≥1 条 PRIVACY_READ。失败 = 采集链路故障（而非被测应用清白），拒绝出批。

失败时 reason/hint 写进 <out>/result.json；hint 指向 A1 分档定位
（`VSCAN_WATCH_LIMIT=<n>` 分档跑，见 DEV_FIX_REPORT §5.1）。A1 未修期间批次侧
允许显式 `--skip` 跳过——跳过事实会写进批次摘要，不许静默。

环境变量会经 start_hook 透传给 run.py，所以
`VSCAN_WATCH_LIMIT=8 python fixture_selftest.py --out ...` 可直接做分档自检。

跑法（一般由 batch_thirdparty.py 调用，也可单跑）：
    python mobile/tools/fixture_selftest.py --out output/_selftest

退出码：0=通过或显式跳过（passed 分别为 true/null）；1=自检失败（拒绝出批）。
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(HERE))
import thirdparty_env as env  # noqa: E402

MOBILE = ROOT / "mobile"
PY = sys.executable
PKG = "com.vscanner.privacydemo"
APK = MOBILE / "fixture-app" / "app" / "build" / "outputs" / "apk" / "debug" / "app-debug.apk"
BUTTON = "btnDeviceId"
FRIDA_LOCAL = ROOT / "output" / "_frida" / "frida-server"
# 正控断言之外的账目：这些不算"阳性证据"，但失败时打出来便于归因
NOT_EVIDENCE = ("START", "ARMED", "NOT_TARGET")


def read_events(path: Path) -> list[dict]:
    """读 JSONL；坏行跳过（与 device_run_thirdparty 的读取口径一致）。"""
    out: list[dict] = []
    if not path.exists():
        return out
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            pass
    return out


def pid_alive(pid: str) -> bool:
    """问"原来那个 pid 还在吗"——pidof 会返回同名新进程，不能用（见 core/frida_host/run.py）。"""
    fired = env.adb("shell", f"if test -d /proc/{pid}; then echo y; else echo n; fi")
    return fired.stdout.strip() == "y"


def clear_dialogs(log: Path) -> str:
    """触发前按 BACK 清掉遮挡界面的系统弹窗：系统弹窗是异步弹出的，会挡住后面的
    控件（device_run.py 实测过"前一个按钮过了、后三个全找不到控件"）。"""
    env.adb("shell", "uiautomator", "dump", "/data/local/tmp/vscan_selftest.xml", timeout=45)
    text = env.adb("shell", "cat", "/data/local/tmp/vscan_selftest.xml", timeout=45).stdout
    log.write_text(text[-3000:], encoding="utf-8")
    if "permissioncontroller" in text or "允许" in text or "Allow" in text:
        env.adb("shell", "input", "keyevent", "4", timeout=30)
        time.sleep(1.2)
        return "cleared"
    return "none"


def trigger(log: Path, user: int | None) -> int:
    cmd = [PY, str(HERE / "trigger.py"), "--package", PKG, "--button", BUTTON]
    if user is not None:
        cmd += ["--user", str(user)]
    return env.run(cmd, log, timeout=240)


def run(out: Path, seconds: int, user: int | None) -> dict:
    session = out / "session"
    session.mkdir(parents=True, exist_ok=True)
    checks: list[dict] = []

    def check(name: str, ok: bool, note: str = "") -> None:
        entry = {"name": name, "ok": bool(ok)}
        if note:
            entry["note"] = note
        checks.append(entry)

    def fail(reason: str, hint: str, events: list[dict] | None = None,
             alive: bool | None = None, death: dict | None = None) -> dict:
        result = {"passed": False, "reason": reason, "hint": hint, "checks": checks,
                  "event_kinds": sorted({e.get("ev") for e in (events or [])}),
                  "out": str(out)}
        # 触发之后的失败要带上"存活/死亡"事实：A1 分档扫描（a1_tier_scan.py）
        # 靠 `alive_at_end` 判定这一格崩没崩。**不给这个键 = 环境没跑起来**
        # （APK 缺失、设备没启动、frida-server 不可用…），那种格子是无效测量，
        # 不能算成"应用存活"，否则会把"没测到"记成"没崩"。
        if alive is not None:
            result["alive_at_end"] = alive
            result["app_death"] = death
        return result

    if not APK.exists():
        return fail("夹具 APK 不存在，自检无法开跑",
                    f"先在 mobile/fixture-app 跑 ./gradlew :app:assembleDebug；期待 {APK}")
    if not env.wait_boot():
        return fail("设备未在超时内启动完成", "adb devices 看一眼；模拟器启动见 mobile/README.md")

    ok, state = env.ensure_frida_server(out / "frida-check.log", FRIDA_LOCAL)
    check("frida_server", ok, f"state={state}")
    if not ok:
        return fail("frida-server 不可用（没有它钩子无法 attach）",
                    "见 frida-check.log；frida-server 版本需与宿主 frida 一致")

    install = env.adb("install", "-r", "-g", str(APK), timeout=300)
    (out / "install.log").write_text(install.stdout + install.stderr, encoding="utf-8")
    ok = "Success" in install.stdout
    check("install", ok)
    if not ok:
        return fail("夹具安装失败", "见 install.log；确认设备架构与 APK 匹配（-g 已自动授权）")

    env.adb("shell", "logcat", "-c", timeout=30)
    start = ["shell", "am", "start"]
    if user is not None:
        start += ["--user", str(user)]
    start += ["-W", "-n", f"{PKG}/.MainActivity"]
    env.adb(*start, timeout=120)
    # 钩子是 attach 模式（run.py 用 pidof 找进程）：必须先等到 pid 再挂钩。
    pid = env.wait_for_app(PKG)
    check("app_started", bool(pid), f"pid={pid}")
    if not pid:
        return fail("夹具未在 60s 内启动（pidof 无输出）",
                    "冷启动竞争或装到了别的用户（--user）；与\"装机失败\"看 install.log 区分")

    # **单 agent 合并 bundle**（2026-10-16 A1 修复）：四个模块（privacy/consent/
    # egress_tp/ssl_pinning_tp）在同一个 JS 上下文里装配——frida-java-bridge 不支持
    # "多脚本各自替换方法"（实测双脚本 ~50% 触发 ART 的 GetOatQuickMethodHeader
    # FATAL 主线程 abort，单脚本 5/5 稳定）。事件全部落 reads.jsonl。
    hooks = [
        env.start_hook(MOBILE / "hooks" / "dist" / "hook_all.bundle.js", session,
                       "reads.jsonl", out / "hook-all.log", seconds, PKG),
    ]
    # **等"挂妥"再点击**（2026-10-16）：原来是固定 sleep(8)，设备忙时（刚重启/
    # 首次 attach/frida-server 冷启）可能钩子还没 arm 完就点了按钮——那一轮会
    # 产出"点击成功、应用也执行了读取，但零事件"的假阴性（jiton-49-r1 实遇）。
    # 改为轮询 hook 日志的挂妥标记（脚本侧 "armed N/N" + 驱动侧 "collecting for"），
    # 最多等 90s；等不到 → 失败退出，而不是继续跑出误导性的"零事件"格子。
    armed_ok = False
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        try:
            txt = (out / "hook-all.log").read_text(encoding="utf-8", errors="replace")
        except OSError:
            txt = ""
        if "armed" in txt and "collecting for" in txt:
            armed_ok = True
            break
        time.sleep(0.5)
    check("hooks_armed_in_time", armed_ok, "hook-all.log 已出现 armed + collecting 标记")
    if not armed_ok:
        return fail("钩子 90s 内未确认挂妥，放弃本轮（防假零事件）",
                    "看 hook-all.log：attach 卡住 / 脚本加载报错 / frida-server 未起")
    dialog = clear_dialogs(out / "dialog.xml")
    check("dialog_cleared", dialog == "cleared", f"state={dialog}")
    rc = trigger(out / "trigger.log", user)
    check("trigger", rc == 0, f"rc={rc}")
    time.sleep(5)   # 等事件回传落盘

    # **窗口证据必须在拆钩之前采集**（2026-10-16）：拆钩（无论优雅 detach 还是强杀）
    # 会在应用进程里触发一次工具侧 abort（Thread-N 的 DeleteGlobalRef
    # "without being attached"，CheckJNI 上必 abort，双脚本场景必现）——那是拆钩噪声，
    # 不是应用在采集窗口内的行为。检查若放拆钩之后，就成了"测我们自己的拆钩动作"，
    # 还会随拆钩快慢忽真忽假（实测同一配置出现过 True/False 两种读数）。
    events = read_events(session / "reads.jsonl")
    readers = [e for e in events if e.get("ev") == "PRIVACY_READ"]
    alive = pid_alive(pid)
    check("alive_at_end", alive, f"pid={pid}")
    death = env.app_death_reason(PKG)
    (out / "app-death.json").write_text(json.dumps(death, ensure_ascii=False, indent=2),
                                        encoding="utf-8")

    for handle in hooks:
        env.stop_hook(handle, out / "hooks-stop.log")

    if not readers and not alive:
        return fail("零真实事件 + 夹具进程已死——这就是 A1 的采集链路故障症状",
                    "分档定位崩点：VSCAN_WATCH_LIMIT=<n>（1→8→16→32→58）逐档跑本自检，"
                    "见 DEV_FIX_REPORT §5.1；app-death.json 与 logcat 是旁证", events,
                    alive, death)
    if not readers and rc != 0:
        return fail("按钮没点到（trigger 失败），未产出任何 PRIVACY_READ",
                    "看 trigger.log 与 dialog.xml：界面被弹窗挡住或夹具版本变了（resource-id）",
                    events, alive, death)
    if not readers:
        return fail("钩子挂上了（进程存活）但 reads.jsonl 零 PRIVACY_READ",
                    "看 hook-privacy.log 与 reads.jsonl 的 START/ARMED 行："
                    "映射层空转（UNMAPPED_ARG）或按钮没触发读取；分档见 DEV_FIX_REPORT §5.1",
                    events, alive, death)

    check("runtime_events_captured", True, f"{len(readers)} 条 PRIVACY_READ")
    return {"passed": True, "reason": "", "hint": "", "checks": checks,
            "privacy_reads": len(readers),
            "event_kinds": sorted({e.get("ev") for e in events}),
            "alive_at_end": alive, "app_death": death, "out": str(out)}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", required=True, help="自检产物目录（result.json 的所在）")
    ap.add_argument("--seconds", type=int, default=90, help="钩子会话时长")
    ap.add_argument("--user", type=int, default=None)
    ap.add_argument("--skip", action="store_true",
                    help="显式跳过自检（A1 未修期间）：写 passed=null 的结果并退出 0；"
                         "批次侧只允许显式跳过，跳过事实必须留在批次摘要里")
    args = ap.parse_args()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    if args.skip:
        result: dict = {"passed": None, "skipped": "explicit --skip-fixture-selftest",
                        "hint": "跳过 = 本轮批次无法区分\"采不到\"与\"没收集\"，"
                                "结论可信度下降；A1 修复后请去掉 --skip 重跑"}
    else:
        guard = env.device_guard()
        result = ({"passed": False, "reason": "设备守卫失败：" + guard, "hint": guard,
                   "checks": []}
                  if guard else run(out, args.seconds, args.user))
    (out / "result.json").write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n",
                                     encoding="utf-8")
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result.get("passed") is not False else 1


if __name__ == "__main__":
    raise SystemExit(main())
