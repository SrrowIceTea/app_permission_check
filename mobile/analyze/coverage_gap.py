#!/usr/bin/env python3
"""静态/动态覆盖差集（C2）——「静态扫到的」与「动态观测到的」各自缺了什么。

仅用于授权测试（已获授权的样本与设备）。

**为什么需要**：静态（dex 方法引用）与动态（hook 读取 + 流量打标）是两条
独立证据链，各有一块盲区，且盲区**长得一样**——都是"这个数据类别没出现在
结论里"。不把差集摆出来，"静态有引用但动态没触发"（很可能是本轮场景没走到，
覆盖缺口）会被误读成"运行时没有这个行为"；反过来"动态观测到但静态无引用"
（反射/加壳/服务端下发）会被误读成"静态扫描漏报可以修"。这两句都不是事实。

**输入**（都可选，缺哪路差集就按"只有另一路"计算）：
  * static_supplement：`static_mobile_supplement.json`（static_scan_thirdparty 产物），
    用 `findings[].data_type_key` + `matched_apis` 取"静态有 dex 引用的数据类别"；
  * reads：会话的 PRIVACY_READ 事件（bundle 的 dynamic.reads 同形），
    用 `data_types` 取"动态读取观测"；
  * flows：会话的流记录（bundle 的 traffic.flows 同形），
    用 `request_tags`/`response_tags` 经 tagging 的词表映射取"形态级观测"。

**三条诚实边界**（写进输出的 caveats，消费方不得删）：
  1. static_only 不构成"未发生"的结论——只说明本轮没观测到，驱动下一轮场景设计。
  2. dynamic_only 不等于静态漏报可修——反射、加壳、服务端下发都能让 dex 无引用。
  3. 两侧词表不同源（static 用 dangerous_apis.data_type_key，动态用 hook 的
     data_types 与 tagging 的 TYPE_BY_LABEL），只做**精确 key 匹配**；
     词表对不齐本身会进 dynamic_only/static_only，差集不猜测同义词。
"""
from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
if str(HERE.parent / "traffic") not in sys.path:
    sys.path.insert(0, str(HERE.parent / "traffic"))
import tagging_mobile  # noqa: E402


def static_referenced_types(supp: dict | None) -> dict[str, dict]:
    """静态侧：有 dex 方法引用的数据类别 → {matched_apis, rule_ids}。"""
    out: dict[str, dict] = {}
    if not supp:
        return out
    for f in supp.get("findings") or []:
        key = f.get("data_type_key") or ""
        if not key:
            continue
        entry = out.setdefault(key, {"matched_apis": 0, "rule_ids": []})
        entry["matched_apis"] += len(f.get("matched_apis") or [])
        if f.get("rule_id") and f["rule_id"] not in entry["rule_ids"]:
            entry["rule_ids"].append(f["rule_id"])
    return out


def _flow_tag_types(flow: dict, out: dict[str, dict]) -> None:
    for label in (flow.get("request_tags") or []) + (flow.get("response_tags") or []):
        for t in tagging_mobile.types_for_labels([label]):
            dt = t.get("data_type")
            if dt:
                out.setdefault(dt, {"reads": 0, "flow_tags": 0})["flow_tags"] += 1


def dynamic_observed_types(reads: list[dict] | None,
                           flows: list[dict] | None) -> dict[str, dict]:
    """动态侧：读取事件（行为级）+ 流标签（形态级）观测到的数据类别。

    两个来源分开计数：读取是行为级证据，流标签只是形态线索，强度不同，
    合并计数会把"只出现形状"夸大成"观测到行为"。
    """
    out: dict[str, dict] = {}
    for r in reads or []:
        for dt in r.get("data_types") or []:
            if dt:
                out.setdefault(dt, {"reads": 0, "flow_tags": 0})["reads"] += 1
    for f in flows or []:
        _flow_tag_types(f, out)
    return out


def compute_gaps(static_supplement: dict | None,
                 reads: list[dict] | None,
                 flows: list[dict] | None) -> dict:
    """→ 差集报告（纯函数，输入缺失时按"该路为空"计算，不抛异常）。"""
    static_side = static_referenced_types(static_supplement)
    dynamic_side = dynamic_observed_types(reads, flows)

    both = sorted(set(static_side) & set(dynamic_side))
    static_only = {k: static_side[k] for k in sorted(set(static_side) - set(dynamic_side))}
    dynamic_only = {k: dynamic_side[k] for k in sorted(set(dynamic_side) - set(static_side))}

    caveats = [
        "static_only 中的类别**不是「运行时未发生」**：dex 引用只说明代码里存在能力，"
        "本轮未观测到多半是场景没触发（覆盖缺口），应驱动下一轮用例设计。",
        "dynamic_only 中的类别**不等于静态扫描漏报可修**：反射调用、加固壳、"
        "服务端下发逻辑都不会在 dex 里留下方法引用。",
        "两侧词表不同源（static: dangerous_apis.data_type_key；dynamic: hook data_types"
        " + tagging TYPE_BY_LABEL），本差集只做精确 key 匹配，不做同义词归并。",
        "流标签是形态级线索（strength=shape），不构成「该值被传输」的结论。",
    ]
    return {
        "generated_by": "mobile/analyze/coverage_gap.py::compute_gaps",
        "counts": {"static_types": len(static_side), "dynamic_types": len(dynamic_side),
                   "both": len(both), "static_only": len(static_only),
                   "dynamic_only": len(dynamic_only)},
        "both": both,
        "static_only": static_only,
        "dynamic_only": dynamic_only,
        "caveats": caveats,
    }
