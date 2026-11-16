"""Check hook readiness and observation evidence. 仅用于授权测试。"""
from core.io_utils import load_jsonl_counting
import thirdparty_env as env
from device_run_thirdparty_helpers import observation_events


def _event_log(path, check, name):
    events, skipped = load_jsonl_counting(path)
    valid = [event for event in events
             if isinstance(event, dict) and isinstance(event.get("ev"), str) and event["ev"]]
    skipped += len(events) - len(valid)
    if skipped:
        check(f"{name}_jsonl_parse", 1, optional=True,
              note=f"{path.name} 有 {skipped} 行无法作为事件使用（证据不完整）")
    clean = not skipped and not any(event["ev"] in ("SCRIPT_ERROR", "ERROR") for event in valid)
    return valid, clean


def _stage_armed(ctx) -> None:
    """钩子必须自证挂载（M016）：没有 ARMED 就是没挂上，不是"应用没动作"；
    armed 之外必须有**真实事件**（§8.1 A2），零事件必须判失败并写进 gaps。
    """
    args = ctx.args
    session = ctx.session
    check = ctx.check
    # 收尾：把样本强制停掉。**必须放在死亡取证之后**（在跑就杀会让 alive 永远为 false，
    # 那是自己制造假结论）；不停掉的话，样本会带着残留状态活到下一样本的窗口里——
    # 实测：一轮 camera 跑完后它的 MainActivity 一直留在前台，下一轮开跑时机器人
    # 先从别人家的界面上做 overlay 清理。停止样本只影响我们安装的测试副本。
    env.adb("shell", "am", "force-stop", args.package, timeout=60)

    all_events = []
    ctx.read_repeat_count = 0
    hooks_ready = True
    for name, fname in (("privacy", "reads.jsonl"), ("consent", "consent.jsonl")):
        if args.no_hooks:
            # 对照实验：本来就没挂钩子，"没 ARMED"是设计使然，不是失败
            check(f"hook_{name}_armed", 0, optional=True,
                  note="对照实验：--no-hooks，本项按设计不适用")
            continue
        events, clean = _event_log(session / fname, check, f"hook_{name}")
        all_events.extend(events)
        ctx.read_repeat_count += sum(event["repeat_count"] for event in events
                                     if event["ev"] == "PRIVACY_READ_REPEATS"
                                     and type(event.get("repeat_count")) is int and event["repeat_count"] > 0)
        armed = any(e.get("ev") == "ARMED" for e in events)
        hooks_ready = hooks_ready and clean and armed
        script_error = any(e.get("ev") in ("SCRIPT_ERROR", "ERROR") for e in events)
        check(f"hook_{name}_armed", 0 if armed else 1,
              note=None if armed else ("钩子脚本抛错，未挂载" if script_error
                                       else "没有 ARMED 事件：钩子没跑起来"))

    # ---- A2（§8.1）：`armed` 之外必须有**真实事件**，且这是**强制**判据 ----
    # `armed` 只证明钩子挂上了，不证明捕得到：夹具与 5 个第三方样本实测都是
    # "58/58 armed; failed=0" 而 reads.jsonl 只有 START/ARMED 两行。
    # 零事件时这里必须判失败并写进 gaps——不许为了让判据变绿而把它改回 optional（§8.6 第 1 条）。
    real_reads = []
    if args.no_hooks:
        check("runtime_events_captured", 0, optional=True,
              note="对照实验：--no-hooks，本项按设计不适用")
    else:
        # 只认"应用做了什么"的事件（P1-02）。egress 也算观测：一个零读取的浏览器
        # 仍可能有 EGRESS_CONNECT/EGRESS_URL——那是行为，不是装载。
        egress, egress_clean = _event_log(session / "egress.jsonl", check, "egress")
        all_obs = all_events + egress
        real_reads = observation_events(all_obs)
        context_only = len(all_obs) - len(real_reads)
        reviewed = (not real_reads and ctx.no_activity_confirmation and ctx.final_alive is True
                    and hooks_ready and egress_clean and not ctx.coverage["truncated"]
                    and not ctx.coverage["deaths"])
        if reviewed:
            ctx.no_activity_review = ctx.no_activity_confirmation
        check("runtime_events_captured", 0 if real_reads else 1, optional=bool(reviewed),
              note=(f"观测事件 {len(real_reads)} 条（读取/外发/同意）" if real_reads else
                    f"只有装载/拓扑事件（{context_only} 条），没有一条应用行为事件。"
                    "armed ≠ 能捕到（§8.1 A2）——据此**不得**写「该应用未收集」；"
                    "先按 A1 排查插桩是否把应用打死，或本轮 UI 未触碰被监视 API"))
    ctx.real_reads = real_reads

    # ---- 启动期覆盖：attach 模式先 `am start` 再挂钩，应用 onCreate 里的调用赶不上 ----
    # 2026-11-15 Roam 实测：dex 里唯一一条 `requestLocationUpdates` 就在启动期调用，
    # UI 确实显示出速度（36 km/h），钩子却 0 条读取。这不是"应用没读"，是"没赶上"。
    # 判据设成 optional：它不否定本轮结论，但必须在报告里能看见，否则会被读成"未收集"。
    if not args.no_hooks:
        if ctx.startup_mode == "spawn" and hooks_ready:
            check("startup_calls_covered", 0, optional=True,
                  note="首段由 Frida 装载脚本后恢复目标进程。启动期先观测隐私读取，其余钩子延后就绪。")
        else:
            mode = {"spawn": "spawn 未确认钩子就绪", "attach_fallback": "spawn 回退 attach"}
            check("startup_calls_covered", 1, optional=True,
                  note=f"{mode.get(ctx.startup_mode, 'attach')}：应用启动期调用可能未被采集。")
