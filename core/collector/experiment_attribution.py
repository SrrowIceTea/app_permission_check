#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""V-Scanner Phase 4 — 归因能力的量化实验（**离线，不需要设备，不需要 mitmproxy**）。

仅用于授权测试（自有设备与自有 APK）/ For authorized testing on owned devices and APKs only.

**为什么需要它**：`MATCH_TOLERANCE_MS=2000`、`AMBIGUITY_MS=500`、宽限 3000ms 这三个数
目前只有**一组夹具校准**（D403 / D408）作为依据。没有人知道它们在什么范围内还成立、
从哪一点开始会把**无辜的 App 写进报告**。报告和论文要回答的恰恰是
"这套归因在什么条件下可信"，所以把时序抽象成可扫描的参数，用**真实的** `TimeAttribution`
跑出混淆矩阵，而不是拿公式推。

**四类结果**（`wrong` 是最要紧的那一类）：

    correct     归属正确且未标歧义
    ambiguous   归属到了正确的包，但标了歧义（下游不会用它升级结论）
    unresolved  一条候选都没有
    wrong       归属到了一个**不是它**的包，且没标歧义 —— 会进报告

**交叉核对**：每种情形同时按规则算出**预测**结果，与实测比对。两者不一致就说明
我们对规则的理解有偏差（或者规则被改过而这里没跟上），实验会把它标出来而不是掩盖。

    python experiment_attribution.py --out ../output/experiment-attribution.json
"""
from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from attribution import AMBIGUITY_MS, MATCH_TOLERANCE_MS, TimeAttribution  # noqa: E402

A = "com.vscanner.targetapp"     # 流真正属于的那个包
B = "com.vscanner.targetapp2"    # 竞争者

# 实测锚点（D403）：A 的事件比它的流早 2ms；B 的事件比它的流晚 65ms。
REAL_LATENESS_A_MS = -2
REAL_LATENESS_B_MS = 65


def classify(result, truth: str) -> str:
    """把一次归因结果归入四类之一。"""
    if not result.resolved:
        return "unresolved"
    if result.ambiguous:
        return "ambiguous"
    return "correct" if result.package == truth else "wrong"


def predict(lateness_a: int, rival_gap: int | None) -> str:
    """按规则解析地算出预期结果，用来与实测交叉核对。

    规则（`attribution.TimeAttribution.resolve`）：候选按 |delta| 排序取最近；
    亚军**只有包名不同**时才构成歧义，且在 `AMBIGUITY_MS` 之内才算。
    """
    deltas = [(abs(lateness_a), A)]
    if rival_gap is not None:
        deltas.append((abs(rival_gap), B))
    ranked = sorted(deltas)
    if ranked[0][0] > MATCH_TOLERANCE_MS:
        return "unresolved"
    winner_delta, winner = ranked[0]
    for delta2, package2 in ranked[1:]:
        if package2 != winner:
            if delta2 - winner_delta <= AMBIGUITY_MS:
                return "ambiguous"
            break
    if winner != A:
        return "wrong"
    return "correct" if len(ranked) == 1 or ranked[1][0] - winner_delta > AMBIGUITY_MS else "ambiguous"


def run_case(true_lateness: int, rival_gap: int | None, flow_ts: int = 1_000_000) -> dict:
    """一个受控场景：流在 `flow_ts` 到达，A 的事件在 `flow_ts+true_lateness`，
    竞争者的事件在 `flow_ts+rival_gap`（None = 没有竞争者）。"""
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "egress_events.jsonl"
        rows = [(flow_ts + true_lateness, A)]
        if rival_gap is not None:
            rows.append((flow_ts + rival_gap, B))
        with path.open("w", encoding="utf-8") as handle:
            for ts, package in rows:
                handle.write(json.dumps({"ev": "EGRESS_CONNECT", "package": package,
                                         "outcome": "ok", "host_received_ts": ts}) + "\n")
        result = TimeAttribution([path]).resolve(flow_ts)
    observed = classify(result, A)
    expected = predict(true_lateness, rival_gap)
    return {"true_lateness_ms": true_lateness, "rival_gap_ms": rival_gap,
            "observed": observed, "predicted": expected, "agrees": observed == expected,
            "winner": result.package, "delta_ms": result.delta_ms,
            "ambiguous": result.ambiguous, "runner_up": result.runner_up}


def sweep_lateness(rival_gap: int | None, limit: int = 4000, step: int = 250) -> list[dict]:
    """真实应用的事件**迟到多久**就不再被认出来（有/无竞争者两种）。"""
    return [run_case(lateness, rival_gap)
            for lateness in range(-limit, limit + 1, step)]


def sweep_rival(true_lateness: int, limit: int = 4000, step: int = 100) -> list[dict]:
    """竞争者的事件离流多近时会**抢走**归属（或把它变成歧义）。"""
    return [run_case(true_lateness, gap) for gap in range(-limit, limit + 1, step)]


def find_wrong_band(cases: list[dict]) -> list[dict]:
    """挑出 wrong 的区间——这是唯一会把无辜 App 写进报告的结果。"""
    return [c for c in cases if c["observed"] == "wrong"]


def grace_experiment(lateness: int, rival_gap: int | None, grace_ms: int,
                     rival_during_grace: int | None = None) -> dict:
    """宽限期到底救回了什么。

    真实时序（D403 实测）：`hook_egress.js` 在 `Socket.connect` 返回**之后**才记录，
    所以应用自己的事件**结构上**晚于它的流。当场定案会把它判给竞争者，
    等宽限期过去再问就能对上。

    **第二次问的是同一个 `ts`，不是"现在"。** `addon._flush` 用的是
    `ATTRIB.resolve(entry["ts"])`——流的原始时间戳。改变的是**盘上的事件集合**，
    不是查询时刻。早先这里写成 `resolve(flow_ts + grace_ms)`，于是等宽限期一过，
    两个事件的 delta 都被推过容差，结论反而从 ambiguous/wrong 变成 unresolved，
    实验看上去像"宽限期会让结果变差"——完全相反的结论。模型错了，不是被测代码错了。

    `rival_during_grace`：竞争者也在这段窗口里落盘。这时宽限期**可能**帮倒忙，
    是 `made_it_worse` 唯一可能为真的情形。
    """
    flow_ts = 1_000_000
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "egress_events.jsonl"
        path.write_text("", encoding="utf-8")
        attrib = TimeAttribution([path])

        def append(package: str, ts: int) -> None:
            with path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps({"ev": "EGRESS_CONNECT", "package": package,
                                         "outcome": "ok", "host_received_ts": ts}) + "\n")

        if rival_gap is not None:   # 竞争者的事件先到（它更早完成 connect）
            append(B, flow_ts + rival_gap)
        # lateness <= 0 表示自己的事件在流到达时**已经在盘上**了；
        # 早先这里只在 lateness > 0 时写，于是"本来就在"被错误地建模成"从来没有"。
        if lateness <= 0:
            append(A, flow_ts + lateness)
        immediate = classify(attrib.resolve(flow_ts), A)
        if lateness > 0:            # 应用自己的事件在宽限期内落盘
            append(A, flow_ts + lateness)
        if rival_during_grace is not None:
            append(B, flow_ts + rival_during_grace)
        after = classify(attrib.resolve(flow_ts), A)   # 同一个 ts 再问一次
    return {"true_lateness_ms": lateness, "rival_gap_ms": rival_gap, "grace_ms": grace_ms,
            "rival_during_grace_ms": rival_during_grace,
            "immediate": immediate, "after_grace": after,
            "change": compare(immediate, after),
            "rescued": immediate != "correct" and after == "correct",
            "made_it_worse": compare(immediate, after) == "worsened"}


# 严重度只看"会不会被当真写进报告"：wrong 是唯一被断言的错误结论，最重；
# ambiguous 与 unresolved 都是"没下结论"，下游不会据此升级结论；correct 为 0。
SEVERITY = {"correct": 0, "ambiguous": 1, "unresolved": 1, "wrong": 2}


def compare(before: str, after: str) -> str:
    """宽限期前后的变化方向。`worsened` 不是 bug，是这套权衡的代价。"""
    delta = SEVERITY[after] - SEVERITY[before]
    return "improved" if delta < 0 else ("worsened" if delta > 0 else "unchanged")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()

    no_rival = sweep_lateness(None)
    with_rival = sweep_lateness(REAL_LATENESS_B_MS)
    rival_near = sweep_rival(REAL_LATENESS_A_MS)
    rival_far = sweep_rival(1500)          # 真实事件接近容差上限时

    def band(cases: list[dict], outcome: str, key: str) -> list:
        """列出某个结果出现在**被扫描的那个量**上的哪些取值。

        必须显式传 key：`run_case` 两种键都写，早先按"有哪个就用哪个"取值，
        于是扫描 rival_gap 时列出来的是**常量** true_lateness——计数对、标签全错，
        这种"看着具体、其实指别的东西"的输出正是本项目最忌讳的。
        """
        return [c[key] for c in cases if c["observed"] == outcome]

    # 无竞争者：宽限期应当把"自己迟到"的情形救成 correct
    grace_alone = [grace_experiment(lateness, None, 3000)
                   for lateness in (500, 1500, 2000, 2500, 4000)]
    # 有竞争者：宽限期把 wrong **降级**成 ambiguous（不再断言，但也不再是 correct）
    grace = [grace_experiment(lateness, REAL_LATENESS_B_MS, 3000)
             for lateness in (0, 65, 500, 1500, 2000, 2500, 4000)]
    # 竞争者也在窗口里落盘：宽限期**可能**帮倒忙的情形，单独列出来
    grace_rival = [grace_experiment(0, None, 3000, rival_during_grace=gap)
                   for gap in (50, 300, 1500)]

    all_cases = no_rival + with_rival + rival_near + rival_far
    disagreements = [c for c in all_cases if not c["agrees"]]

    report = {
        "constants": {"match_tolerance_ms": MATCH_TOLERANCE_MS, "ambiguity_ms": AMBIGUITY_MS,
                      "grace_ms": 3000},
        "anchors": {"real_lateness_a_ms": REAL_LATENESS_A_MS,
                    "real_lateness_b_ms": REAL_LATENESS_B_MS},
        "no_rival": {"swept": "true_lateness_ms",
                     "correct": band(no_rival, "correct", "true_lateness_ms"),
                     "unresolved": band(no_rival, "unresolved", "true_lateness_ms"),
                     "wrong": band(no_rival, "wrong", "true_lateness_ms")},
        "with_rival_at_65ms": {"swept": "true_lateness_ms",
                               "wrong": band(with_rival, "wrong", "true_lateness_ms"),
                               "ambiguous": band(with_rival, "ambiguous", "true_lateness_ms")},
        "rival_sweep_true_lateness_-2": {
            "swept": "rival_gap_ms",
            "wrong": band(rival_near, "wrong", "rival_gap_ms"),
            "ambiguous": band(rival_near, "ambiguous", "rival_gap_ms")},
        "rival_sweep_true_lateness_1500": {
            "swept": "rival_gap_ms",
            "wrong": band(rival_far, "wrong", "rival_gap_ms")},
        "grace_no_rival": grace_alone,
        "grace_with_rival": grace,
        "grace_rival_arrives_during_window": grace_rival,
        "grace_summary": {
            "no_rival_rescued": sum(1 for g in grace_alone if g["rescued"]),
            "no_rival_cases": len(grace_alone),
            "with_rival_de_escalated": sum(1 for g in grace
                                           if g["immediate"] == "wrong" and g["change"] == "improved"),
            "with_rival_cases": len(grace),
            "rival_during_window_worsened": sum(1 for g in grace_rival
                                                if g["change"] == "worsened"),
        },
        "cross_check": {"cases": len(all_cases), "disagreements": len(disagreements),
                        "detail": disagreements[:10]},
        "caveat": "受控时序扫描，不是真机分布；结论是「规则在什么条件下给出什么」，"
                  "不是「某 App 有百分之多少会被误判」。真实误判率取决于事件迟到分布，"
                  "需要长时间真机采集才能得到。",
    }
    text = json.dumps(report, ensure_ascii=False, indent=2)
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(text + "\n", encoding="utf-8")
    print(text)
    return 0 if not disagreements else 1


if __name__ == "__main__":
    raise SystemExit(main())
