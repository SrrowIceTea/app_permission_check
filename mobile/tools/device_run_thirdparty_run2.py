#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""device_run_thirdparty 阶段②：launch（从 device_run_thirdparty.py 拆出，零行为改动）。
spawn / attach 启动与挂钩，含 spawn 失败回退 attach 与早退判据（返回 1 时整个运行短路）。
"""
from __future__ import annotations

import json
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
            env.unblock_quic(out / "quic-unblock.log")        # 同理：不能把 DROP 规则留在设备上
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
                           spawn=args.spawn_hook),
        ]
        if args.spawn_hook:
            # spawn 模式下应用由 run.py 的 device.spawn + resume 启动。等待应用 pid
            # 出现（spawn 是异步的，run.py 里 spawn→attach→load→resume 需要几秒），
            # 并确认进程没在窗口内崩溃重启——否则 UI 驱动对着一个已死的进程空点。
            spawn_pid = env.wait_for_app(args.package, timeout_s=40)
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
                spawn_died = not alive
            # **两种 spawn 失败都要回退 attach**（2026-10-20 修）：
            #   ① 起来了又崩（上面这 6 秒观察窗能抓到）；
            #   ② 压根没起来 —— `device.spawn` 超时/报错时 run.py 直接退出，
            #      应用根本没被启动。`core/frida_host/run.py:resolve_pid` 的历史注释
            #      明确记着"Frida spawn 在本模拟器上会超时"。
            # 原实现只处理 ①：②会走 `check(app_started)=1` 然后直接早退，
            # 每遇到一次就白扔一个样本（40s 等待 + 早退），而 attach 本来能跑。
            if spawn_died or not spawn_pid:
                why = (f"spawn pid={spawn_pid} 已消失（spawn 注入崩溃）" if spawn_pid
                       else "spawn 未拉起应用进程（device.spawn 超时/失败）")
                emit("launch", "running", f"{why}，回退 attach 启动")
                for h in hooks:
                    env.stop_hook(h, out / "hook-all.log")
                env.adb("shell", "am", "start", "-W", "-n",
                        f"{args.package}/{main_activity}", timeout=150)
                attach_pid = env.wait_for_app(args.package, timeout_s=40)
                check("app_started", 0 if attach_pid else 1,
                      note=(f"回退 attach pid={attach_pid}（原因：{why}）" if attach_pid else
                            f"spawn 失败且回退 attach 也未启动（原因：{why}）")
                           + f"；activity={main_activity}")
                if attach_pid:
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
                                       args.package, spawn=False),
                    ]
                    emit("launch", "done", f"回退 attach pid={attach_pid}")
                else:
                    emit("launch", "failed", "spawn 失败且回退 attach 失败")
            else:
                check("app_started", 0 if spawn_pid else 1,
                      note=f"spawn pid={spawn_pid}；activity={main_activity}")
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
                env.unblock_quic(out / "quic-unblock.log")
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
    if pid is None:
        # spawn 模式下 pid 由 Frida 启动的进程决定（上面只做了占位）。分段采集靠
        # /proc/<pid> 判活，没有 pid 就等于整段失明——这里补一次解析，拿不到就
        # 让 coverage 记成"无法判定"（alive=None），绝不写"存活"。
        pid = env.wait_for_app(args.package, timeout_s=20)
    ctx.pid = pid
    ctx.hooks = hooks
    return 0
