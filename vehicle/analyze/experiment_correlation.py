#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""V-Scanner Phase 5 — 关联规则（read→egress）的量化实验（**离线，不需要设备**）。

仅用于授权测试（自有设备与自有 APK）/ For authorized testing on owned devices and APKs only.

**为什么需要它**：`window_ms=30000` 的取值依据是"两个夹具实测的读取→外发间隔"
（10634ms / 20292ms，见 D502）。那是**一组夹具**的校准，不是规则本身的性质。
报告与论文要回答的是"这个窗口在什么范围内够用、漏掉什么"，
所以把场景列成表、拿真实 `evaluate_data_egress` 跑出**查准/查全**，
而不是拿几句话描述。

**做法**：每个场景声明"应当产出哪些 (read, flow) 配对"，跑完比对，统计
TP / FP（凭空多出来的配对）/ FN（漏掉的真实配对）。FP 最要紧——它会把一次
没发生的外发写进报告。

    python experiment_correlation.py --out ../output/experiment-correlation.json
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from evaluation import evaluate_data_egress  # noqa: E402

PKG = "com.vscanner.targetapp"
OTHER = "com.vscanner.targetapp2"
PROP_ID = 289408000
PROP_NAME = "GEAR_SELECTION"
TOKEN = "GEAR_SELECTION"
T0 = 1_000_000

# 与 vehicle/rules/rules_library/rules.db 里 E001–E008 的 window_ms 一致（D502 实测校准）。
# 测试也引用这个常量，避免"实验用 30s、测试测 5s"这种两处各写一个数的情况。
RULE_WINDOW_MS = 30_000


def rule(window_ms: int, enabled: int = 1) -> dict:
    """一条与 rules.db 同形的 data_egress 规则（属性 GEAR_SELECTION = R004）。"""
    return dict(rule_id="VSC-R004", rule_revision=2, rule_type="data_egress",
                severity="high", conclusion_level="correlated", enabled=enabled,
                window_ms=window_ms, condition_json=json.dumps({"property_id": PROP_ID}),
                basis_refs_json="[]", source_refs_json="[]")


def read(evt_id: int, ts: int, *, pkg: str = PKG, outcome: str = "ok",
         session: str = "s1") -> dict:
    return dict(ev="VHAL_READ", evt_id=evt_id, host_received_ts=ts, pkg=pkg,
                prop_id=PROP_ID, prop_name=PROP_NAME, outcome=outcome, session_id=session)


def flow(evt_id: int, ts: int, *, pkg: str = PKG, tokens=(TOKEN,), session: str = "s1",
         ambiguous: bool = False, attribution: str = "app_process_hook") -> dict:
    return dict(evt_id=evt_id, ts=ts, package=pkg, session_id=session,
                request_tokens=list(tokens), attribution=attribution,
                attribution_ambiguous=ambiguous, method="POST", host="10.0.2.2",
                path="/collect", intercepted_tls=False)


# 每个场景是一个**具名字典**而不是元组：早先用元组时漏了"这条规则是否启用"这一维，
# 于是「禁用规则」场景实际拿 enabled=1 跑，凭空多出一个配对被记成 false positive，
# 算出来的 precision 0.8 是**实验脚本自己的错**，不是被测代码的。字段写全就不会再错。
#   expect  : 期望产出的 (read_evt_id, flow_evt_id) 集合
#   enabled : 该场景使用的规则是否启用（默认 1）
SCENARIOS: list[dict] = [
    dict(name="窗口内真配对", note="读→发 10.6s（实测值），应当命中",
         reads=[read(1, T0)], flows=[flow(101, T0 + 10_634)], expect={(1, 101)}),

    dict(name="窗口边界内", note="间隔恰好等于 window_ms，应当命中（闭区间）",
         reads=[read(2, T0)], flows=[flow(102, T0 + 30_000)], expect={(2, 102)}),

    dict(name="窗口外", note="间隔超出 window_ms 1ms，不该命中",
         reads=[read(3, T0)], flows=[flow(103, T0 + 30_001)], expect=set()),

    dict(name="只读不发", note="有读取、没有外发，不该产出外发结论",
         reads=[read(4, T0)], flows=[], expect=set()),

    dict(name="只发不读", note="有外发、没有对应读取，不该产出结论",
         reads=[], flows=[flow(104, T0)], expect=set()),

    dict(name="内容不匹配", note="报文里没有该属性名/ID，不该凭时间相邻就断言",
         reads=[read(5, T0)], flows=[flow(105, T0 + 100, tokens=("OTHER_FIELD",))],
         expect=set()),

    dict(name="先后次序倒置", note="外发早于读取（delta<0）不算",
         reads=[read(6, T0)], flows=[flow(106, T0 - 100)], expect=set()),

    dict(name="读取失败", note="outcome!=ok 的读取不算成功读取（D505）",
         reads=[read(7, T0, outcome="error")], flows=[flow(107, T0 + 100)], expect=set()),

    dict(name="跨包", note="流属于 B 包，读取属于 A 包，不得混合",
         reads=[read(8, T0)], flows=[flow(108, T0 + 100, pkg=OTHER)], expect=set()),

    dict(name="跨会话", note="同包但不同 session，不得关联",
         reads=[read(9, T0, session="s1")], flows=[flow(109, T0 + 100, session="s2")],
         expect=set()),

    dict(name="归因歧义", note="attribution_ambiguous 的流不得升级成结论",
         reads=[read(10, T0)], flows=[flow(110, T0 + 100, ambiguous=True)], expect=set()),

    dict(name="归因未解析", note="attribution=unresolved 的流不得升级成结论",
         reads=[read(11, T0)], flows=[flow(111, T0 + 100, attribution="unresolved")],
         expect=set()),

    # 用**本会命中**的输入跑禁用规则，才验得出"禁用生效"；空输入永远产出空结果，
    # 那种场景是假通过。同一条输入启用时的对照见 main 里的 disabling_control。
    dict(name="禁用规则", note="enabled=0 时，本会命中的输入也必须不产出结论",
         reads=[read(12, T0)], flows=[flow(112, T0 + 10_634)], expect=set(), enabled=0),

    dict(name="多属性只命中一个", note="报文只含其中一个属性名，只配对该属性",
         reads=[read(13, T0)],
         flows=[flow(113, T0 + 100, tokens=(TOKEN, "PERF_VEHICLE_SPEED"))],
         expect={(13, 113)}),

    # 下面这条**期望就是命中**：它是当前实现的已知边界（D403/D503），不是缺陷——
    # `content_match_basis` 已写明依据只是"属性名出现在报文里"。放进实验是为了
    # 让边界可度量，将来做值级匹配时能拿它对照。
    dict(name="同名不同值（已知边界）", note="报文含属性名但值来自别处，当前仍判命中",
         reads=[read(14, T0)], flows=[flow(114, T0 + 100, tokens=(TOKEN,))],
         expect={(14, 114)}),
]


def run_scenario(scenario: dict, window_ms: int) -> dict:
    enabled = scenario.get("enabled", 1)
    findings = evaluate_data_egress([rule(window_ms, enabled)],
                                    scenario["reads"], scenario["flows"])
    produced = {(p["read_event_id"], p["flow_event_id"])
                for finding in findings for p in finding.get("pairs", [])}
    expected = scenario["expect"]
    return {"name": scenario["name"], "note": scenario["note"], "enabled": enabled,
            "expected": sorted(expected), "produced": sorted(produced),
            "false_positives": sorted(produced - expected),   # 凭空多出来的配对
            "false_negatives": sorted(expected - produced)}   # 漏掉的真实配对


def sweep_window(deltas=(1_000, 3_000, 10_634, 20_292, 30_000, 30_001, 60_000, 120_000),
                 window_ms: int = 30_000) -> list[dict]:
    """读取→外发间隔扫描：多大的间隔还能被 30s 窗口捞到。

    实测锚点：10.6s（HTTP）/ 20.3s（HTTPS）。这条曲线就是"窗口够不够"的答案。
    """
    out = []
    for delta in deltas:
        findings = evaluate_data_egress([rule(window_ms)], [read(1, T0)],
                                        [flow(101, T0 + delta)])
        out.append({"delta_ms": delta, "detected": bool(findings),
                    "within_window": delta <= window_ms})
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--window-ms", type=int, default=RULE_WINDOW_MS)
    args = parser.parse_args()

    cases = [run_scenario(s, args.window_ms) for s in SCENARIOS]
    # 对照：把「禁用规则」场景的同一份输入改用启用规则跑。
    # 没有这个对照，"禁用生效"就是**假通过**——空输入本来就产出空结果。
    disabled_case = next(s for s in SCENARIOS if s.get("enabled") == 0)
    control = run_scenario(dict(disabled_case, enabled=1), args.window_ms)
    disabling_control = {"same_input_with_rule_enabled": control["produced"],
                         "disabled_produced": run_scenario(disabled_case,
                                                           args.window_ms)["produced"],
                         "proves_disable_takes_effect": bool(control["produced"])}

    tp = sum(len(c["expected"]) - len(c["false_negatives"]) for c in cases)
    fp = sum(len(c["false_positives"]) for c in cases)
    fn = sum(len(c["false_negatives"]) for c in cases)
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None

    report = {
        "window_ms": args.window_ms,
        "scenarios": cases,
        "disabling_control": disabling_control,
        "metrics": {"true_positives": tp, "false_positives": fp, "false_negatives": fn,
                    "precision": precision, "recall": recall,
                    "scenarios_total": len(cases),
                    "scenarios_passing": sum(1 for c in cases
                                             if not c["false_positives"]
                                             and not c["false_negatives"])},
        "window_sweep": sweep_window(window_ms=args.window_ms),
        "caveat": "场景是构造的，覆盖的是**规则语义**（谁和谁能配对），"
                  "不是真实 App 的行为分布。真实漏报率取决于读取→外发间隔的分布，"
                  "需要长时间真机采集才能估计。",
    }
    text = json.dumps(report, ensure_ascii=False, indent=2)
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(text + "\n", encoding="utf-8")
    print(text)
    # 非零 = 出现了凭空多出的配对或漏掉的配对，都是真问题
    return 0 if (fp == 0 and fn == 0
                 and disabling_control["proves_disable_takes_effect"]) else 1


if __name__ == "__main__":
    raise SystemExit(main())
