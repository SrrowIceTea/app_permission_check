#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""V-Scanner Phase 4 — 归因误判率的 Monte Carlo 采样（**离线，不需要设备**）。

仅用于授权测试（自有设备与自有 APK）/ For authorized testing on owned devices and APKs only.

**为什么需要它**：`experiment_attribution.py` 是**构造时序**的规则语义扫描，回答
"规则在极端取值下给出什么"（wrong 28/33 是构造出来的带，不是真实比率）。本脚本回答
"在**迟到分布**下，误归因率是百分之几"——把 28/33 转成"迟到分布下 X%"。

**迟到分布从哪来**：真机分布要靠 `verify_multi_app.py` 在设备上跑夹具采集（P1 待办）。
本脚本把分布做成**可配置参数**（--mu-a / --sigma-a / --mu-b / --sigma-b / --p-rival），
默认用实测锚点拟合的**假设分布**；设备数据一到，换成实测分布参数重跑即可得到真机数字。
**默认值不是真机数字，是假设分布下的基准**——务必在报告里写清这一点。

**建模的关键**：addon 会在宽限期（GRACE_MS=3000）内反复重试，迟到超过宽限期的事件
在流被定案时**还没落盘**。所以"迟到 <= 宽限期"的事件参与 resolve，"迟到 > 宽限期"的
事件等于没赶上——这正是宽限期与迟到分布联合作用的正确模型。迟到 < 0 表示事件**早于**
流（D403 实测 A 早 2ms）。

    python experiment_attribution_montecarlo.py --cases 20000 --seed 42 \
        --out ../output/attribution-montecarlo.json
"""
from __future__ import annotations

import argparse
import json
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from attribution import TimeAttribution  # noqa: E402

A = "com.vscanner.targetapp"     # 流真正属于的那个包
B = "com.vscanner.targetapp2"    # 竞争者

GRACE_MS = 3000  # 与 addon.GRACE_MS 一致

# 假设分布的默认参数（**不是真机数字**，见模块 docstring）：
#   A 真主事件迟到 ~ N(-2, 400)：均值取 D403 实测的 -2ms；σ 取到能覆盖 D402 实测的
#       575/1128ms 事件迟到（约 1.5~3σ），让"多数紧、少数迟到"这种真实形状进入采样。
#   B 竞争者事件迟到 ~ N(65, 150)：均值取 D403 实测的 +65ms。
DEFAULT_MU_A = -2.0
DEFAULT_SIGMA_A = 400.0
DEFAULT_MU_B = 65.0
DEFAULT_SIGMA_B = 150.0
DEFAULT_P_RIVAL = 0.5


def classify(result, truth: str) -> str:
    """一次归因结果归入四类之一（与 experiment_attribution.classify 同口径）。"""
    if not result.resolved:
        return "unresolved"
    if result.ambiguous:
        return "ambiguous"
    return "correct" if result.package == truth else "wrong"


def run_once(rng: random.Random, mu_a: float, sigma_a: float, mu_b: float, sigma_b: float,
             p_rival: float, flow_ts: int = 1_000_000, conservative: bool = False) -> dict:
    """一次采样：A 的流在 `flow_ts` 到达，A/B 事件各带一个迟到（<0 = 早于流）。

    建模宽限期：迟到 <= GRACE_MS 的事件在定案时已在盘上，迟到 > GRACE_MS 的没赶上
    （addon 已按 unresolved 落盘）。用**真实的** `TimeAttribution` 跑（events 注入，
    绕过文件 IO，resolve 排序/歧义/弃权逻辑不变），不手推公式。
    """
    lateness_a = int(round(rng.gauss(mu_a, sigma_a)))
    rival = rng.random() < p_rival
    lateness_b = int(round(rng.gauss(mu_b, sigma_b))) if rival else None

    events = []
    if lateness_a <= GRACE_MS:
        events.append((flow_ts + lateness_a, A, "egress_hook", None))
    if lateness_b is not None and lateness_b <= GRACE_MS:
        events.append((flow_ts + lateness_b, B, "egress_hook", None))

    result = TimeAttribution(events=events, conservative=conservative).resolve(flow_ts)

    return {"lateness_a_ms": lateness_a, "lateness_b_ms": lateness_b,
            "outcome": classify(result, A),
            "package": result.package, "delta_ms": result.delta_ms,
            "ambiguous": result.ambiguous, "runner_up": result.runner_up}


def tally(cases: list[dict]) -> dict:
    """四类结果的计数与占比。"""
    n = len(cases)
    counts: dict[str, int] = {}
    for c in cases:
        counts[c["outcome"]] = counts.get(c["outcome"], 0) + 1
    return {k: {"count": v, "rate": round(v / n, 5)} for k, v in sorted(counts.items())}


def summarize(values: list[int | None]) -> dict:
    """迟到分布的分位摘要（比直方图更有信息量、更不易写错桶界）。"""
    xs = sorted(v for v in values if v is not None)
    if not xs:
        return {"n": 0}

    def pct(q: float) -> int:
        return xs[min(len(xs) - 1, int(q * (len(xs) - 1)))]

    return {"n": len(xs), "min": xs[0], "max": xs[-1],
            "mean": round(sum(xs) / len(xs), 1),
            "median": pct(0.5), "p10": pct(0.1), "p90": pct(0.9)}


def sweep_true_lateness(rng_seed: int, per_point: int, mu_b: float, sigma_b: float,
                        conservative: bool = False) -> list[dict]:
    """固定竞争者迟到 ~ N(mu_b, sigma_b)、竞争者总在场，扫 A 的平均迟到 mu_a。

    这是校准 MATCH_TOLERANCE_MS / AMBIGUITY_MS / 宽限期的直接依据：wrong 率在哪个
    mu_a 开始上翘，就是"真主迟到多少开始崩"的临界点。
    """
    out = []
    for mu_a in range(-500, 2001, 250):
        rng = random.Random(rng_seed)
        cases = [run_once(rng, float(mu_a), 150.0, mu_b, sigma_b, 1.0,
                          conservative=conservative)
                 for _ in range(per_point)]
        t = tally(cases)
        out.append({"mu_a_ms": mu_a,
                    "wrong_rate": t.get("wrong", {}).get("rate", 0.0),
                    "ambiguous_rate": t.get("ambiguous", {}).get("rate", 0.0),
                    "unresolved_rate": t.get("unresolved", {}).get("rate", 0.0),
                    "correct_rate": t.get("correct", {}).get("rate", 0.0)})
    return out


def run_duo_once(rng: random.Random, spacing_ms: int, conservative: bool,
                 flow_a_ts: int = 1_000_000) -> tuple[str, str]:
    """两条流并发（D407 场景）：A 流与 B 流相距 `spacing_ms`，各自事件带 D407 实测锚点
    迟到（A 晚 24ms、B 晚 15ms，加 σ=20ms 抖动模拟实测散布）。返回 (A 流结果, B 流结果)。

    这是量化保守模式**代价**的维度：默认下两条流各自 correct（不串包），保守下只要
    对方的事件落进自己 2000ms 窗口就弃权 → correct 退化成 ambiguous。
    """
    flow_b_ts = flow_a_ts + spacing_ms
    la = int(round(rng.gauss(24.0, 20.0)))
    lb = int(round(rng.gauss(15.0, 20.0)))
    events = [(flow_a_ts + la, A, "egress_hook", None),
              (flow_b_ts + lb, B, "egress_hook", None)]
    ra = TimeAttribution(events=events, conservative=conservative).resolve(flow_a_ts)
    rb = TimeAttribution(events=events, conservative=conservative).resolve(flow_b_ts)
    return classify(ra, A), classify(rb, B)


def sweep_duo_spacing(rng_seed: int, per_point: int, conservative: bool = False) -> list[dict]:
    """扫两条流间距，看保守模式把"并发且不串包"的 correct 退化多少。

    三条曲线：`both_correct_rate`（两条都正确，D407 交付的验收目标）、
    `any_wrong_rate`（任一串包）、`both_ambiguous_rate`（两条都弃权）。
    """
    out = []
    for spacing in range(0, 3001, 250):
        rng = random.Random(rng_seed)
        outcomes = [run_duo_once(rng, spacing, conservative) for _ in range(per_point)]
        n = len(outcomes)
        out.append({"spacing_ms": spacing,
                    "both_correct_rate": round(
                        sum(1 for a, b in outcomes if a == "correct" and b == "correct") / n, 5),
                    "any_wrong_rate": round(
                        sum(1 for a, b in outcomes if "wrong" in (a, b)) / n, 5),
                    "both_ambiguous_rate": round(
                        sum(1 for a, b in outcomes if a == "ambiguous" and b == "ambiguous") / n, 5)})
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--cases", type=int, default=20000)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--mu-a", type=float, default=DEFAULT_MU_A)
    parser.add_argument("--sigma-a", type=float, default=DEFAULT_SIGMA_A)
    parser.add_argument("--mu-b", type=float, default=DEFAULT_MU_B)
    parser.add_argument("--sigma-b", type=float, default=DEFAULT_SIGMA_B)
    parser.add_argument("--p-rival", type=float, default=DEFAULT_P_RIVAL)
    parser.add_argument("--conservative", action="store_true",
                        help="开启保守弃权（D415）再跑一遍对比")
    parser.add_argument("--sweep-per-point", type=int, default=2000)
    parser.add_argument("--duo-per-point", type=int, default=2000)
    parser.add_argument("--no-sweep", action="store_true", help="跳过 mu_a 扫描（加速/测试）")
    parser.add_argument("--no-duo", action="store_true", help="跳过双流并发扫描（加速/测试）")
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()

    # 默认模式。同一 seed 重放一遍 conservative 模式，让两者在**同一批迟到值**上对比，
    # 否则"保守把 wrong 转成 ambiguous"就无从归因到开关本身。
    rng = random.Random(args.seed)
    cases = [run_once(rng, args.mu_a, args.sigma_a, args.mu_b, args.sigma_b,
                      args.p_rival, conservative=args.conservative)
             for _ in range(args.cases)]
    rng2 = random.Random(args.seed)
    cons_cases = [run_once(rng2, args.mu_a, args.sigma_a, args.mu_b, args.sigma_b,
                           args.p_rival, conservative=True)
                  for _ in range(args.cases)]
    sweep = ([] if args.no_sweep else
             sweep_true_lateness(args.seed, args.sweep_per_point,
                                 args.mu_b, args.sigma_b))
    duo_default = ([] if args.no_duo else
                   sweep_duo_spacing(args.seed, args.duo_per_point, conservative=False))
    duo_conservative = ([] if args.no_duo else
                        sweep_duo_spacing(args.seed, args.duo_per_point, conservative=True))

    default_tally = tally(cases)
    cons_tally = tally(cons_cases)

    report = {
        "distribution_assumption": {
            "note": "假设分布，不是真机数字；设备采集到实测迟到分布后替换参数重跑",
            "mu_a_ms": args.mu_a, "sigma_a_ms": args.sigma_a,
            "mu_b_ms": args.mu_b, "sigma_b_ms": args.sigma_b,
            "p_rival": args.p_rival, "grace_ms": GRACE_MS,
        },
        "sampling": {"cases": args.cases, "seed": args.seed,
                     "conservative": args.conservative},
        "outcome_distribution": default_tally,
        "outcome_distribution_conservative": cons_tally,
        "wrong_silent_rate": {
            "default": default_tally.get("wrong", {}).get("rate", 0.0),
            "conservative": cons_tally.get("wrong", {}).get("rate", 0.0),
            "note": "保守模式把 wrong 全部转成 ambiguous，代价是 correct 也大面积退化",
        },
        "lateness_a_distribution": summarize([c["lateness_a_ms"] for c in cases]),
        "lateness_b_distribution": summarize([c["lateness_b_ms"] for c in cases]),
        "lateness_sweep": {
            "swept": "mu_a_ms (A 平均迟到)",
            "per_point": args.sweep_per_point,
            "rival_distribution": f"N(mu_b={args.mu_b}, sigma_b={args.sigma_b}), 竞争者总在场",
            "points": sweep,
        },
        "duo_concurrency_cost": {
            "swept": "spacing_ms (两条流间距)",
            "per_point": args.duo_per_point,
            "anchors": "D407 实测：A 事件晚 24ms、B 事件晚 15ms（σ=20ms 抖动）",
            "default": duo_default,
            "conservative": duo_conservative,
            "note": "保守模式的代价：两条流并发且各自正确（both_correct）时，"
                    "对方事件落进自己窗口就弃权，correct 退化成 ambiguous。",
        },
        "caveat": "假设分布下的基准数字；真实误判率取决于设备实测迟到分布（P1 待办）。",
    }
    text = json.dumps(report, ensure_ascii=False, indent=2)
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(text + "\n", encoding="utf-8")
    print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
