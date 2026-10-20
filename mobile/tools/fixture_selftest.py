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
import coverage_window as cov  # noqa: E402  段账目/覆盖率（与单样本运行器同一口径）
from core.io_utils import load_jsonl_counting  # noqa: E402  JSONL 唯一实现（只按 LF 分行）

MOBILE = ROOT / "mobile"
PY = sys.executable
PKG = "com.vscanner.privacydemo"
APK = MOBILE / "fixture-app" / "app" / "build" / "outputs" / "apk" / "debug" / "app-debug.apk"
BUTTON = "btnDeviceId"
FRIDA_LOCAL = ROOT / "output" / "_frida" / "frida-server"
# 正控断言之外的账目：这些不算"阳性证据"，但失败时打出来便于归因
NOT_EVIDENCE = ("START", "ARMED", "NOT_TARGET")


def read_events(path: Path) -> list[dict]:
    """读 JSONL；坏行跳过（与 device_run_thirdparty 的读取口径一致）。

    分行必须走 core.io_utils：`str.splitlines()` 会在 JSON 字符串里的
    U+0085/U+2028 处切断记录，把"有事件"读成"没事件"——而本自检的结论正是
    "零事件 = 采集链路故障"，误判方向恰好是最危险的那一边。
    """
    rows, skipped = load_jsonl_counting(path)
    if skipped:
        # 不能吞掉：本自检的判据是"零事件 = 采集链路故障"，而坏行会让事件数变成下界。
        # 方向上它只会让自检更保守（更容易拒绝出批），但"静默少几条"正是 io_utils
        # 明令禁止的形态——这里至少留痕。
        print(f"[selftest] ⚠ {path.name} 有 {skipped} 行无法解析（事件数为下界）",
              file=sys.stderr)
    return rows


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
             alive: bool | None = None, death: dict | None = None,
             coverage: dict | None = None) -> dict:
        result = {"passed": False, "status": "failed", "reason": reason, "hint": hint,
                  "checks": checks,
                  "event_kinds": sorted({e.get("ev") for e in (events or [])}),
                  "out": str(out)}
        # 触发之后的失败要带上"存活/死亡"事实：A1 分档扫描（a1_tier_scan.py）
        # 靠 `alive_at_end` 判定这一格崩没崩。**不给这个键 = 环境没跑起来**
        # （APK 缺失、设备没启动、frida-server 不可用…），那种格子是无效测量，
        # 不能算成"应用存活"，否则会把"没测到"记成"没崩"。
        if alive is not None:
            result["alive_at_end"] = alive
            result["app_death"] = death
        # 失败也要带窗口账本（2026-10-19 复核）：以前 coverage 只在成功/degraded
        # 分支里出现，`a1-args-2`、`a1-purejs-1` 明明写了 coverage.json，
        # result.json 却没有——批次汇总于是看不到"这条失败是因为窗口被截断"。
        if coverage is not None:
            result["coverage"] = coverage
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
    # 自检的"窗口"从挂钩发起算起（钩子会话时长 = seconds）
    t_hook = time.time()
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
    alive_at = time.time()
    alive = pid_alive(pid)
    death = env.app_death_reason(PKG, pid=pid, since_ms=int(t_hook * 1000),
                                 dump_dir=out)
    (out / "app-death.json").write_text(json.dumps(death, ensure_ascii=False, indent=2),
                                        encoding="utf-8")
    # **判活与取证对不上时以硬证据为准**（2026-10-19 复核）：被信号打死的进程在父进程
    # 回收前 /proc/<pid> 还在（僵尸），只判目录存在会读出 alive=True；而同一轮的
    # app-death.json 里躺着本 pid 的 SIGSEGV。旧写法两边都留着，报告于是同时写着
    # "存活"和"崩了"（a1-args-1 就是这么来的）。
    if death.get("signal") and alive is not False:
        death["hooked_pid"] = pid
        death["note"] = (f"/proc/{pid} 仍可访问，但已取到本 pid 的 "
                         f"{death['signal']} 记录：按死亡计")
        alive = False
        (out / "app-death.json").write_text(
            json.dumps(death, ensure_ascii=False, indent=2), encoding="utf-8")
    check("alive_at_end", alive, f"pid={pid}")
    # 窗口账本：死亡段的"有效观测"用墓碑 uptime / 崩溃行时间戳，拿不到就记 None。
    coverage = cov.summarize(
        [cov.segment_entry(0, t_hook, alive_at, alive, death, events=len(readers))],
        seconds)
    (out / "coverage.json").write_text(
        json.dumps(coverage, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    for handle in hooks:
        env.stop_hook(handle, out / "hooks-stop.log")

    if not readers and not alive:
        # 死因按本次证据说（2026-10-19 复核）：这句话原来写死成"这就是 A1 的采集链路
        # 故障症状"，可 `a1-purejs-1` 那次是 RenderThread 的 EGL_NOT_INITIALIZED
        # （模拟器 GPU），被同一句话归到了 A1 头上。
        sig = death.get("signal") or "信号未知"
        thr = death.get("thread") or "线程未知"
        return fail(f"零真实事件 + 夹具进程已死：{sig} @ {thr}（A1 残留形态是否一致见 app-death.json）",
                    "分档定位崩点：VSCAN_WATCH_LIMIT=<n>（1→8→16→32→58）逐档跑本自检，"
                    "见 DEV_FIX_REPORT §5.1；app-death.json 与 logcat 是旁证", events,
                    alive, death, coverage)
    if not readers and rc != 0:
        return fail("按钮没点到（trigger 失败），未产出任何 PRIVACY_READ",
                    "看 trigger.log 与 dialog.xml：界面被弹窗挡住或夹具版本变了（resource-id）",
                    events, alive, death, coverage)
    if not readers:
        return fail("钩子挂上了（进程存活）但 reads.jsonl 零 PRIVACY_READ",
                    "看 hook-privacy.log 与 reads.jsonl 的 START/ARMED 行："
                    "映射层空转（UNMAPPED_ARG）或按钮没触发读取；分档见 DEV_FIX_REPORT §5.1",
                    events, alive, death, coverage)

    check("runtime_events_captured", True, f"{len(readers)} 条 PRIVACY_READ")
    base = {"checks": checks, "privacy_reads": len(readers),
            "event_kinds": sorted({e.get("ev") for e in events}),
            "alive_at_end": alive, "app_death": death, "coverage": coverage,
            "out": str(out)}
    if not alive:
        # **有事件但进程被打死**：阳性对照（钩子能采）成立，A1 原验收判据
        # （"≥1 真实事件 且 进程存活"，DEV_FIX_REPORT §8.1）不成立。
        # 以前这里返回 passed=True，等于让"进程死了"悄悄通过；现在明确降级：
        # passed=False + status=degraded，批次默认放行但整批标注
        # `selftest_degraded` + `coverage_caveats`；要拒绝出批用 `--strict-selftest`
        # （2026-10-19 复核：旧 hint 里写的 `--allow-degraded-selftest` 根本不存在，
        # 照着提示敲会直接被 argparse 打回）。
        return {**base, "passed": False, "status": "degraded",
                "reason": "有真实事件，但夹具进程在窗口内死亡（A1 残留：插桩下 "
                          f"{death.get('signal') or 'SIGSEGV'}@{death.get('thread') or '未知线程'}）",
                "hint": (f"有效观测 {coverage['observed_s']}s/{seconds}s。"
                         "本轮采集链路本身是通的（事件已出），但『窗口完整性』不成立："
                         "批次默认放行并标注 selftest_degraded，要拒绝出批请用 "
                         "--strict-selftest；本批所有阴性结论只能限定在 observed_s 内"),
                "degraded": True}
    return {**base, "passed": True, "status": "passed", "reason": "", "hint": ""}


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
        result: dict = {"passed": None, "status": "skipped",
                        "skipped": "explicit --skip-fixture-selftest",
                        "hint": "跳过 = 本轮批次无法区分\"采不到\"与\"没收集\"，"
                                "结论可信度下降；A1 修复后请去掉 --skip 重跑"}
    else:
        guard = env.device_guard()
        result = ({"passed": False, "status": "failed", "reason": "设备守卫失败：" + guard,
                   "hint": guard, "checks": []}
                  if guard else run(out, args.seconds, args.user))
    (out / "result.json").write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n",
                                     encoding="utf-8")
    print(json.dumps(result, ensure_ascii=False, indent=2))
    # 退出码：0 = 通过或降级（由批次侧按显式开关决定是否放行）；
    # 1 = 失败（链路不通，拒绝出批）。降级不能退 0 以外的值，否则批次侧
    # 还没读到 result.json 就先被 subprocess 返回值误导。
    return 0 if result.get("passed") is not False or result.get("degraded") else 1


if __name__ == "__main__":
    raise SystemExit(main())
