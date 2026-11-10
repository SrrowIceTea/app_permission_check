#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""device_run_thirdparty 阶段③：explore（从 device_run_thirdparty.py 拆出，零行为改动）。
分段采集 + 判活 + 死亡重启（teardown / decode 在 *_run4.py）。
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
import thirdparty_ui_flow as flow  # noqa: E402  UI 探索（dump 驱动，不写死坐标）
import coverage_window as cov      # noqa: E402  分段采集的覆盖率账本（A4，2026-10-19）
sys.path.insert(0, str(ROOT))

from device_run_thirdparty_helpers import _count_jsonl  # noqa: E402
MOBILE = ROOT / "mobile"


def _stage_explore(ctx) -> None:
    """UI 交互驱动 + 分段采集（A4）：每段判活，死了就取证、重启、重新挂钩。
    结束后把 segments / coverage / final_alive / final_death / seg_started 放回 ctx，
    供 teardown 的死亡取证与 finalize 的缺口透传使用。
    """
    args = ctx.args
    out = ctx.out
    session = ctx.session
    emit = ctx.emit
    check = ctx.check

    emit("explore", "running", f"UI 交互驱动（最多 {args.max_rounds} 轮）")
    # ---- 分段采集（A4，2026-10-19）----
    # 为什么必须分段：插桩下应用仍会被 SIGSEGV 打死（A1 残留），而死一次的直接后果
    # 不是丢一条事件，是**窗口后半段整段失明**——"没观测到"会被读成"没做"。
    # 这里把窗口切成若干段：每段开始前确认被挂钩 pid 还活着；一旦死了就
    # ① 立刻取证（墓碑 4 分钟就会被 UWB 崩溃循环挤掉）② 重启应用、重新挂钩，
    # 用剩余时间继续采。段账目进 coverage_window，报告据此限定阴性结论的范围。
    window_t0 = time.time()
    budget = float(args.seconds)
    segments: list[dict] = []
    all_actions: list[dict] = []
    rounds_left = args.max_rounds
    restarts_left = 0 if args.no_restart_on_death else args.max_restarts
    seg_index = 0
    seg_started = window_t0
    seg_events_base = _count_jsonl(session / "reads.jsonl")
    seg_closed = False
    # UI 探索状态**必须跨分段调用存活**：本循环按 --segment-chunk（默认 10s）多次
    # 调 flow.explore，而分段只是为了判活。状态放在循环外，explore 才不会每次
    # 从头再点同一批按钮（实测 40 个样本 326 次点击、平均只有 3.0 个不同目标）。
    ui_state = flow.new_state()
    pid = ctx.pid
    hooks = ctx.hooks

    while True:
        remaining = budget - (time.time() - window_t0)
        if remaining <= 0:
            break
        if rounds_left > 0:
            chunk = max(1, int(min(remaining, args.segment_chunk)))
            ui_dir = out / "ui" if seg_index == 0 else out / "ui" / f"seg{seg_index}"
            acts = flow.explore(ui_dir, chunk, rounds_left, args.package,
                                ctx.main_activity, ui_state)
            for a in acts:
                a["segment"] = seg_index
            all_actions.extend(acts)
            # **只数真正跑过的轮次**（2026-10-20 复核纠正）：`explore()` 在"到时间上限"
            # 时会追加一条 action="stop"，它的 `round` 是**下一个**（没跑过的）轮次号，
            # 原口径把它也算一整轮 —— 实测 40-timer-other 每次调用「2 次点击 + 1 条 stop」
            # 记成 3 轮，`--max-rounds 32` 实际只有 ~22 轮可用（三分之一是幽灵轮）。
            rounds_left -= len({a["round"] for a in acts
                                if isinstance(a.get("round"), int)
                                and a.get("action") != "stop"})
        else:
            # UI 轮次用完了但窗口还没到：**窗口要继续开着**（延迟读取/延迟外连都在
            # 后半段发生），并以 5s 粒度判活——否则"轮次跑完就收工"会让死亡发生在
            # 收尾之后、既看不见也来不及重启（2026-10-19 冒烟实测：27s 死亡，
            # 但 6 轮 UI 在 20s 就用完，循环直接退出，成了 1 段）。
            acts = []
            time.sleep(max(1, min(5, remaining)))
        alive = env.pid_alive(pid) if pid else None

        if alive is False and pid:
            death = env.app_death_reason(args.package, pid=pid,
                                          since_ms=int(seg_started * 1000), dump_dir=out)
            death["hooked_pid"] = pid
            death["hooked_pid_alive"] = False
            (out / f"app-death-seg{seg_index}.json").write_text(
                json.dumps(death, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            now = time.time()
            segments.append(cov.segment_entry(
                seg_index, seg_started, now, False, death,
                _count_jsonl(session / "reads.jsonl") - seg_events_base))
            seg_closed = True
            emit("death_probe", "failed",
                 f"段 {seg_index}：pid {pid} 在窗口第 {round(now - window_t0)}s 死亡"
                 f"（{death.get('signal') or '原因未记录'}"
                 f"{'，uptime ' + str(death['uptime_s']) + 's' if death.get('uptime_s') else ''}）")
            remaining = budget - (now - window_t0)
            if restarts_left <= 0 or remaining < args.min_segment_seconds:
                emit("explore", "failed",
                     "死亡后不再重启（重试次数或剩余时间不足）：本窗口有效观测到此为止")
                break
            restarts_left -= 1
            for h in hooks:
                env.stop_hook(h, out / f"hooks-stop-seg{seg_index}.log")
            hooks = []
            emit("explore", "running", f"段 {seg_index} 死亡，重启应用并重新挂钩"
                                       f"（剩余 {round(remaining)}s）")
            env.adb("shell", "am", "start", "-W", "-n",
                    f"{args.package}/{ctx.main_activity}", timeout=150)
            new_pid = env.wait_for_app(args.package, timeout_s=60)
            if not new_pid:
                emit("explore", "failed", "重启后应用未出现，放弃剩余窗口")
                break
            hooks = [
                env.start_hook(MOBILE / "hooks" / "dist" / "hook_all.bundle.js", session,
                               "reads.jsonl", out / f"hook-all-seg{seg_index + 1}.log",
                               # 这里**不加余量**（2026-10-20 复核纠正）：`remaining`
                               # 是在死亡时刻算的，而 start_hook 还要排在
                               # `am start` + `wait_for_app` 之后（Δ 秒）——
                               # 钩子 deadline = 现在 + Δ + remaining = 窗口结束 + Δ，
                               # 本来就已经盖过窗口末尾；再加 15 秒只是让钩子白活 15 秒。
                               # 真需要余量的是**回退 attach** 那一处（见 launch 阶段）。
                               int(remaining),
                               args.package, spawn=False,
                               tls_bypass=getattr(args, "tls_bypass", False)),
            ]
            time.sleep(9)   # 等钩子挂妥（同首段）
            pid = new_pid
            # 重新拉起的应用回到首屏：给它留几步 UI 轮次，否则"重启了但不再操作"
            # 只证明进程活着，证明不了新一段里还能采到东西。
            rounds_left = max(rounds_left, min(args.max_rounds, 3))
            # 新段 = 新的一轮探索：屏幕回到首屏，"点过什么"也要重来（否则首屏的
            # 候选全在 tapped 里，一进来就判穷尽）。全局轮次号保留，供证据命名。
            keep_round = ui_state["round"]
            ui_state = flow.new_state()
            ui_state["round"] = keep_round
            seg_index += 1
            seg_started = time.time()
            seg_events_base = _count_jsonl(session / "reads.jsonl")
            seg_closed = False
            continue

    # ---- 关最后一段 + 终局取证（顺序很关键，2026-10-19 复核修正）----
    # 旧顺序：先 summarize（最后一刻只做了 /proc 判活、death=None）→ 再取证。
    # 实测反例 a1-args-1：判活在崩溃前返回 True，取证在崩溃后才拿到 SIGSEGV，
    # ledger 于是写成「1 段 / 0 次死亡 / observed 63.2s（预算 45s）/ 窗口完整」，
    # 而同一轮的 app-death.json 里躺着 `SIGSEGV @ Jit thread pool, uptime 88s`。
    # 现在：**先取证，再关段**；证据里有点名本 pid 的崩溃行就以死亡计
    # （/proc 残留的僵尸目录也会让 pid_alive 返回 True）。
    final_alive_at = time.time()
    final_alive = env.pid_alive(pid) if pid else None
    final_death = None
    if pid:
        final_death = env.app_death_reason(args.package, pid=pid,
                                           since_ms=int(seg_started * 1000), dump_dir=out)
        final_death["hooked_pid"] = pid
        final_death["hooked_pid_alive"] = final_alive
        if final_death.get("signal") and final_alive is not False:
            final_death["note"] = (f"/proc/{pid} 仍可访问，但已取到本 pid 的 "
                                   f"{final_death['signal']} 记录：按死亡计")
            final_alive = False
        (out / "app-death-final.json").write_text(
            json.dumps(final_death, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    if not seg_closed:
        segments.append(cov.segment_entry(
            seg_index, seg_started, final_alive_at, final_alive, final_death,
            _count_jsonl(session / "reads.jsonl") - seg_events_base))
        seg_closed = True

    (out / "ui-actions.json").write_text(json.dumps(
        {"actions": all_actions, "note": "每次点击的点击前/后 XML 见 ui/ 目录（多段时为 ui/segN/），可回溯"},
        ensure_ascii=False, indent=2), encoding="utf-8")
    taps = [a for a in all_actions if a["action"] == "tap"]
    check("ui_taps_made", 0 if taps else 1, note=f"完成 {len(taps)} 次点击，{len(segments)} 段")
    coverage = cov.summarize(segments, budget, window_t0)
    (out / "coverage.json").write_text(
        json.dumps(coverage, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    check("coverage_not_truncated", 0 if not coverage["truncated"] else 1, optional=True,
          note=coverage["caveat"])
    emit("explore", "done" if not coverage["truncated"] else "failed", coverage["caveat"])

    ctx.pid = pid
    ctx.hooks = hooks
    ctx.segments = segments
    ctx.coverage = coverage
    ctx.final_alive = final_alive
    ctx.final_death = final_death
    ctx.seg_started = seg_started


