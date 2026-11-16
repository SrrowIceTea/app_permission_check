#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""device_run_thirdparty 阶段②：launch（从 device_run_thirdparty.py 拆出，零行为改动）。
spawn / attach 启动与挂钩，含 spawn 失败回退 attach 与早退判据（返回 1 时整个运行短路）。
"""
from __future__ import annotations

import json
import re
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(HERE))
import thirdparty_env as env      # noqa: E402
sys.path.insert(0, str(ROOT))

MOBILE = ROOT / "mobile"
HOOK_MARGIN_SPAWN_S = 55
HOOK_MARGIN_ATTACH_S = 15


def _wait_for_spawn(proc, log: Path, timeout_s: float = 40) -> tuple[str | None, str]:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = proc.poll()
        if status is not None:
            return None, f"Frida 启动进程已退出（退出码 {status}，见 {log.name}）"
        ready = re.search(r"^FRIDA_SPAWN_READY (\d+) (\d+) (\d+)$",
                          log.read_text(encoding="utf-8", errors="replace"), re.MULTILINE)
        if ready:
            return ready[1], f"user={ready[2]} uid={ready[3]}"
        time.sleep(0.25)
    return None, f"未在 {timeout_s:g}s 内确认 Frida 已恢复目标 PID（见 {log.name}）"


def _stage_launch(ctx) -> int:
    """launch：spawn/attach 启动应用并挂 Frida 钩子（单 agent 合并 bundle），
    spawn 失败回退 attach。早退（应用起不来）时返回 1，整个运行短路。
    """
    args = ctx.args
    out = ctx.out
    session = ctx.session
    checks = ctx.checks
    emit = ctx.emit
    check = ctx.check
    main_activity = ctx.main_activity
    resolved_activity = ctx.resolved_activity
    ctx.startup_mode = "attach"

    # 冷启动竞争：attach 模式先 am start、等到 pid 再挂钩子；
    # spawn 模式反过来——钩子进程 spawn 应用（在第一条指令前挂上），应用由 resume 启动。
    # spawn 的根因（2026-10-19 实测定性）：attach 太晚，应用启动那一刻的联网/egress
    # 全落在钩子覆盖外，flows 归因恒 unresolved（24/24），egress 事件 0 条。
    if args.spawn_hook:
        pid = None  # spawn 模式下由 hook 进程启动，这里只做占位，不等 am start
        emit("launch", "running", f"spawn 模式：应用由 Frida spawn 启动（{main_activity}）")
    else:
        emit("launch", "running", f"启动应用 {main_activity}")
        env.adb("shell", "am", "start", "-W", "-n",
                f"{args.package}/{main_activity}", timeout=150)
        pid = env.wait_for_app(args.package)
        check("app_started", 0 if pid else 1,
              note=(f"pid={pid}" if pid else "应用未在超时内出现（冷启动竞争或启动崩溃）")
                   + f"；activity={main_activity}"
                   + ("" if resolved_activity else "（回退值：设备解析为空）"))
        emit("launch", "done" if pid else "failed", f"pid={pid}" if pid else "应用未启动")
        if not pid:
            env.kill_tree(ctx.collector, out / "kill-conn.log")   # 早退也不能留孤儿
            if ctx.pcap_rec is not None:                      # 抓包进程同样不能留在设备上
                ctx.pcap_rec.stop(out / "capture.pcap", out / "pcap-stop.log")
            (out / "verification.json").write_text(json.dumps(
                {"passed": False, "checks": checks, "failed": ["app_started"],
                 "package": args.package}, ensure_ascii=False, indent=2), encoding="utf-8")
            print(json.dumps({"status": "failed", "reason": "app_started"}, ensure_ascii=False))
            ctx.pid = None
            ctx.hooks = []
            return 1

    # （代理已在 am start 之前就绪并设置，见阶段① "启动 mitmproxy" 一段。）

    if args.no_hooks:
        # 对照实验：同一 App、同一流程，只少"挂钩子"这一项。用于判定应用死亡
        # （SIGABRT/SIGSEGV）是否由插桩引起——挂钩与不挂钩各跑一轮比对。
        hooks = []
        emit("hooks", "skipped", "对照实验：--no-hooks，本轮不挂任何钩子")
        check("hooks_armed", 0, optional=True,
              note="对照实验：--no-hooks，本轮不挂任何钩子（其余流程不变）")
    else:
        # **单 agent 合并 bundle**（2026-10-16 A1 修复）：privacy/consent/egress_tp/
        # ssl_pinning_tp 四模块在同一个 JS 上下文里装配。原"5 个脚本各起一个 run.py"
        # 的实现被 frida-java-bridge 的已知限制击穿——"多脚本各自替换方法"不受支持
        # （bridge 源码注释原文 "we don't support replacing methods from multiple
        # scripts"；实测双脚本 ~50% 触发 ART 的 GetOatQuickMethodHeader FATAL
        # 【主线程 abort】，单脚本 5/5 稳定）。vehicle 版 hook_egress/ssl_pinning_bypass
        # 一并退役：观测面被 tp 版覆盖（tp 是"同源加强版"，见各自文件头），且 vehicle
        # 版 TLS 含"已实证会炸 ART 的 HttpsURLConnection 主机名钩子"（tls_bypasses_tp.js
        # 头部有记录）。事件全落 reads.jsonl，收尾阶段由 split_events.py 按 src 分流回
        # consent/egress/tls 独立文件（下游 correlate/evidence_bundle 零改动）。
        emit("hooks", "running", "挂载 Frida 钩子（单 agent 合并 bundle：隐私/同意/出站/TLS）")
        # 钩子会话必须比**观测窗口**活得更久（2026-10-20 修）：余量口径见文件头的
        # HOOK_MARGIN_*。这里传 args.seconds 会让窗口末尾 15~55 秒没有钩子覆盖。
        hook_extra_s = HOOK_MARGIN_SPAWN_S if args.spawn_hook else HOOK_MARGIN_ATTACH_S
        hooks = [
            env.start_hook(MOBILE / "hooks" / "dist" / "hook_all.bundle.js", session,
                           "reads.jsonl", out / "hook-all.log",
                           args.seconds + hook_extra_s, args.package,
                           spawn=args.spawn_hook,
                           # 逐样本的 TLS 校验收宽开关（默认关，见 --tls-bypass）
                           tls_bypass=getattr(args, "tls_bypass", False)),
        ]
        if args.spawn_hook:
            # spawn 模式下应用由 run.py 的 device.spawn + resume 启动。等待应用 pid
            # 出现（spawn 是异步的，run.py 里 spawn→attach→load→resume 需要几秒），
            # 并确认进程没在窗口内崩溃重启——否则 UI 驱动对着一个已死的进程空点。
            spawn_pid, spawn_note = _wait_for_spawn(hooks[0], out / "hook-all.log")
            # spawn 注入对部分应用会导致 SIGSEGV（实测 openmensa：RenderThread
            # 在 spawn 后 3s 崩溃，frida 早期注入 + 部分 native 渲染线程初始化冲突）。
            # 检测到 spawn 的 pid 很快消失时，回退到 attach：停掉 spawn 钩子，用
            # am start 冷启动应用（此时应用已脱离 frida 早期注入，能正常跑），
            # 再 attach 重挂——牺牲启动瞬间的流量，换稳定性（2026-10-19）。
            spawn_died = False
            attach_pid = None      # 回退 attach 的 pid；未走回退时保持 None
            if spawn_pid:
                time.sleep(6)   # 给 spawn 的应用一个崩溃观察窗
                alive = env.adb("shell",
                                f"if test -d /proc/{spawn_pid}; then echo y; else echo n; fi",
                                timeout=30).stdout.strip() == "y"
                spawn_died = not alive or hooks[0].poll() is not None
            # **两种 spawn 失败都要回退 attach**（2026-10-20 修）：
            #   ① 起来了又崩（上面这 6 秒观察窗能抓到）；
            #   ② 压根没起来 —— `device.spawn` 超时/报错时 run.py 直接退出，
            #      应用根本没被启动。`core/frida_host/run.py:resolve_pid` 的历史注释
            #      明确记着"Frida spawn 在本模拟器上会超时"。
            # 原实现只处理 ①：②会走 `check(app_started)=1` 然后直接早退，
            # 每遇到一次就白扔一个样本（40s 等待 + 早退），而 attach 本来能跑。
            if spawn_died or not spawn_pid:
                ctx.startup_mode = "attach_fallback"
                why = f"spawn pid={spawn_pid} 或钩子进程已退出" if spawn_pid else spawn_note
                emit("launch", "running", f"{why}，回退 attach 启动")
                for h in hooks:
                    env.stop_hook(h, out / "hook-all.log")
                for path in session.glob("reads.*"):
                    # The driver owns these until stop_hook returns. Preserve a failed
                    # spawn's events separately before the attach attempt opens its stream.
                    path.rename(out / f"spawn-attempt-{path.name}")
                env.adb("shell", "am", "force-stop", "--user", "current", args.package, timeout=30)
                env.adb("shell", "am", "start", "-W", "-n",
                        f"{args.package}/{main_activity}", timeout=150)
                attach_pid = env.wait_for_app(args.package, timeout_s=40)
                check("app_started", 0 if attach_pid else 1,
                      note=(f"回退 attach pid={attach_pid}（原因：{why}）" if attach_pid else
                            f"spawn 失败且回退 attach 也未启动（原因：{why}）")
                           + f"；activity={main_activity}")
                if attach_pid:
                    pid = attach_pid
                    # 日志换个文件名：`start_hook` 以 "w" 打开日志，用同一个
                    # hook-all.log 会把**spawn 会话的失败原因**（超时/崩溃栈）整段截掉，
                    # 而那正是"为什么会回退"的唯一书面证据。
                    hooks = [
                        env.start_hook(MOBILE / "hooks" / "dist" / "hook_all.bundle.js",
                                       session, "reads.jsonl",
                                       out / "hook-all-fallback.log",
                                       # 回退 attach 同样要留余量：它之后还有
                                       # wait_for_app + sleep(9) 才开观测窗口，
                                       # 原来传 args.seconds 等于末尾 9s 以上无钩子。
                                       args.seconds + HOOK_MARGIN_ATTACH_S,
                                       args.package, spawn=False,
                                       tls_bypass=getattr(args, "tls_bypass", False)),
                    ]
                    emit("launch", "done", f"回退 attach pid={attach_pid}")
                else:
                    emit("launch", "failed", "spawn 失败且回退 attach 失败")
            else:
                pid = spawn_pid
                ctx.startup_mode = "spawn"
                check("app_started", 0,
                      note=f"spawn pid={spawn_pid} {spawn_note}；activity={main_activity}")
                emit("launch", "done", f"spawn pid={spawn_pid}")
            # 早退判据改成「窗口内到底有没有活着的被测进程」（2026-10-20 修）：
            # 原判据 `not spawn_pid and not spawn_died` 漏掉了
            # "spawn 起来了又崩、回退 attach 也没起来"这一种 —— 此时 spawn_pid 有值、
            # spawn_died=True、attach_pid 为空，条件为 False 而**不早退**，于是
            # 没有 app、没有钩子（上面已 stop），却照样跑满 100 秒窗口，
            # 最后 rc=0 被编排层记成 status="ok"，白白浪费一个样本的时间预算。
            if not ((spawn_pid and not spawn_died) or attach_pid):
                for h in hooks:
                    env.stop_hook(h, out / "hook-all.log")
                env.kill_tree(ctx.collector, out / "kill-conn.log")
                if ctx.pcap_rec is not None:
                    ctx.pcap_rec.stop(out / "capture.pcap", out / "pcap-stop.log")
                (out / "verification.json").write_text(json.dumps(
                    {"passed": False, "checks": checks, "failed": ["app_started"],
                     "package": args.package}, ensure_ascii=False, indent=2), encoding="utf-8")
                print(json.dumps({"status": "failed", "reason": "app_started"},
                                 ensure_ascii=False))
                ctx.pid = None
                ctx.hooks = []
                return 1
        time.sleep(9)   # 等钩子挂上：钩子掉线与"应用没动作"长得一样（D309）
        emit("hooks", "done", "钩子已发起挂载（单 agent 合并 bundle）")
    ctx.pid = pid
    ctx.hooks = hooks
    return 0
