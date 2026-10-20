"""采集窗口的覆盖率账本：把"分段 + 死亡"换算成**可写进报告的有效观测时长**。

背景（2026-10-19）：插桩下的应用仍会被 SIGSEGV 打死（A1 残留，症状见
`mobile/A1_RESIDUAL_20261019.md`）。打死一次的直接后果不是丢一条事件，而是
**窗口后半段整段失明**——而"失明"与"应用没做该动作"在产物里长得一样。旧实现只把
`app_alive_at_window_end` 记成 optional，报告照样通过，于是"窗口内未观察到 XX"
这句话其实是"死后的时间没看"。本模块负责把这件事变成数字：

    observed_s   真正能观察到行为的时长（= 各段存活时长之和）
    truncated    窗口是否被截断（有过死亡）
    coverage     有效观测 / 预算窗口

约定：
  - 每段（segment）是"一次启动 + 一次挂钩 + 一段 UI 驱动"，死亡后重启会**新开一段**；
  - 死亡时刻优先用墓碑的 `Process uptime: Ns`（进程自己报的），其次用墓碑/崩溃日志的
    时间戳（`death_ts_ms`）减去段起点；**两者都拿不到就记 None（未知），不再拿
    "现在 - 段起点"充数**——那是"我们什么时候发现它死"的上界，不是它活了多久。
    2026-10-19 复核实测：一条没有墓碑的死亡因此被记成 `observed_s=156.5/45`，
    等于把"死了一小时也不知道"写成"全程都看着"。
  - 所有数字都可以是 None（探测失败），调用方必须照实降级，不许把 None 读成 0/False；
  - 各段之和不超过预算：超出的部分记进 `overrun_s`（那是本轮跑超了，不是观测到的行为）。
"""
from __future__ import annotations


def _num(v) -> float | None:
    if v is None or isinstance(v, bool):
        return None
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def segment_entry(index: int, started_at: float | None, ended_at: float | None,
                  alive: bool | None, death: dict | None = None,
                  events: int | None = None, note: str = "") -> dict:
    """一段的账目。`alive` 是 /proc/<pid> 的判活结果（None = 没测到）。

    `observed_s` 的取值顺序：墓碑 `Process uptime` → 墓碑/崩溃日志时间戳与段起点之差
    → None（未知）。**不再用墙钟兜底**（见模块 docstring 的 156.5s/45s 实测）。
    """
    uptime = _num((death or {}).get("uptime_s"))
    elapsed = None
    if started_at is not None and ended_at is not None:
        elapsed = max(0.0, ended_at - started_at)
    observed = elapsed
    basis = "wall_clock"
    if alive is None:
        # 没测到存活 = 这一段不能计入观测时长（否则"没看"会被算成"看了"）
        observed, basis = None, "unknown_alive"
    elif alive is False:
        offset = _death_offset(death, started_at)
        if offset is not None:
            if elapsed is not None and elapsed < offset:
                # uptime 从**进程启动**算，可能比本段还长（进程比钩子先起来，
                # 或墓碑时间戳稍早）。这时只能确定"它死在本段结束之前"，
                # 有效观测就是本段长度——写 basis=uptime 而值等于墙钟，会让
                # 读报告的人以为数字来自进程自报（2026-10-19 实测 38 vs 36.5）。
                observed, basis = elapsed, "wall_clock_clamped"
            else:
                observed = offset
                basis = "uptime" if uptime is not None else "death_ts"
        elif uptime is not None and elapsed is None:
            observed, basis = uptime, "uptime"
        else:
            # 只知道自己死了、不知道什么时候死的：这一段对"观测了多久"没有贡献
            observed, basis = None, "unknown_death"
    return {"index": index, "started_at": started_at, "ended_at": ended_at,
            "elapsed_s": round(elapsed, 1) if elapsed is not None else None,
            "observed_s": round(observed, 1) if observed is not None else None,
            "observed_basis": basis,
            "death_offset_s": (round(_death_offset(death, started_at), 1)
                               if _death_offset(death, started_at) is not None else None),
            "alive_at_end": alive,
            # 存**副本**：调用方随后会往 death 里塞 segments/coverage，而 coverage 的
            # detail 里又有这一段 → 同一个对象互指，json.dumps 报 "Circular reference"。
            "death": dict(death) if death else None, "events": events, "note": note}


def _death_offset(death: dict | None, started_at: float | None) -> float | None:
    """死亡时刻相对段起点的秒数（越界值一律丢弃）。

    - `uptime_s`：进程自报"活了多久"，最可信；
    - `death_ts_ms`：墓碑/崩溃日志的时间戳（UTC epoch ms），换成本机时钟再相减；
    - 负偏移（墓碑比本段还早）说明这条死亡证据不是本段的 → 返回 None，不参与计算。
    """
    if not death:
        return None
    uptime = _num(death.get("uptime_s"))
    if uptime is not None and uptime >= 0:
        return uptime
    ts_ms = _num(death.get("death_ts_ms"))
    if ts_ms is None or started_at is None:
        return None
    offset = ts_ms / 1000.0 - started_at
    if offset < 0:
        return None
    return offset


def summarize(segments: list[dict], budget_s: float | None,
              window_t0: float | None = None) -> dict:
    """把各段账目汇总成 coverage 块（纯函数，可单测）。

    三态硬约束：判活结果 None 的段**不进存活分母**，也不贡献 observed（只记出来），
    避免把"没测到"算成"没崩/没采"。

    `window_t0` 是窗口起点（wall clock）。给了它，"首次死亡约在第几秒"才是**窗口内**的
    偏移；不给就只能用段内偏移——多段时会把"重启后的第 30s"错写成"窗口第 30s"。
    """
    segs = segments or []
    deaths = [s for s in segs if s.get("alive_at_end") is False]
    unknown = [s for s in segs if s.get("alive_at_end") is None]
    known = [s for s in segs if s.get("alive_at_end") is not None]
    observed_vals = [_num(s.get("observed_s")) for s in known]
    observed = (sum(v for v in observed_vals if v is not None)
                if any(v is not None for v in observed_vals) else None)
    events = [s.get("events") for s in segs if s.get("events") is not None]
    first_death_at = None
    if deaths:
        first = deaths[0]
        first_death_at = _death_offset(first.get("death"), first.get("started_at"))
        seg_elapsed = _num(first.get("elapsed_s"))
        if first_death_at is not None and seg_elapsed is not None:
            # uptime 从进程启动算，可能比本段还长——报告里"窗口第几秒"不能超过段长
            first_death_at = min(first_death_at, seg_elapsed)
        if first_death_at is not None and window_t0 is not None:
            seg_start = _num(first.get("started_at"))
            if seg_start is not None:
                first_death_at += max(0.0, seg_start - float(window_t0))
        if first_death_at is None:
            first_death_at = _num(first.get("observed_s"))
    overrun = None
    if observed is not None and budget_s:
        budget_f = float(budget_s)
        if observed > budget_f:
            # 跑超了预算是采集侧的偏差，不能算成"观测到了更多行为"
            overrun = round(observed - budget_f, 1)
            observed = budget_f
    cov = None
    if observed is not None and budget_s:
        cov = round(min(1.0, observed / float(budget_s)), 3)

    unknown_death = [s for s in deaths if s.get("observed_basis") == "unknown_death"]
    if not segs:
        caveat = "未记录分段（旧产物）：无法据产物判断窗口是否被截断"
    elif deaths:
        lost = None
        if observed is not None and budget_s:
            lost = max(0.0, float(budget_s) - observed)
        caveat = (f"窗口被截断：{len(deaths)} 段进程死亡（首次死亡约在 "
                  f"{first_death_at if first_death_at is not None else '未知'}s），"
                  f"有效观测 {observed if observed is not None else '未知'}s"
                  f"/{int(budget_s) if budget_s else '未知'}s"
                  + (f"，约 {round(lost, 1)}s 未观测" if lost is not None else "")
                  + "。阴性结论只能限定在有效观测时长内，不得写成整个窗口")
        if unknown_death:
            caveat += (f"；其中 {len(unknown_death)} 段的死亡时刻无法确认"
                       "（墓碑/崩溃缓冲已被挤掉），该段不计入有效观测，"
                       "不能把「段末」当作「死亡时刻」")
    elif unknown:
        caveat = (f"{len(unknown)} 段无法判定存活（探测失败/超时），"
                  "不能据此声称应用全程存活")
    else:
        caveat = "窗口完整：各段进程均存活至段末"

    return {"segments": len(segs),
            "deaths": len(deaths),
            "unknown_alive": len(unknown),
            "unknown_death_at": len(unknown_death),
            "budget_s": int(budget_s) if budget_s else None,
            "observed_s": round(observed, 1) if observed is not None else None,
            "overrun_s": overrun,
            "coverage_ratio": cov,
            "truncated": bool(deaths),
            "first_death_at_s": (round(first_death_at, 1)
                                 if first_death_at is not None else None),
            "events_total": sum(events) if events else None,
            "caveat": caveat,
            "detail": segs}
