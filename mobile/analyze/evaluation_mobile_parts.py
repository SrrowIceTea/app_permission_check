#!/usr/bin/env python3
"""evaluation_mobile 的取值 / 配对 / 成形部件（从 evaluation_mobile.py 拆出，§8.2 B-2）。

仅用于授权测试（已获授权的样本与设备）。

**为什么拆**：这些函数全是"把原始事件读成求值器要的形状"——时间戳归一、合格读取、
同意事件筛选、流的可用性、形态标签映射、值级匹配、结论字典成形。它们与
`evaluate()` 的八种谓词派发之间没有任何耦合，原文件只是越过了 300 行红线。

**为什么名字带下划线却跨模块用**：下划线在这里的语义是"不进公开 API"，不是
"本文件私有"——同一个包的相邻模块共享这些部件是正常的。对外仍然只有
`evaluate()` 一个入口（`correlate_mobile.py` 只认它和 `CONSENT_SIGNALS`）。

**这些函数错了不会报错**，只会静默漏水：`_ok_reads` 放进被拒绝的读取会凭空
多出"收集"结论；`_consent_for` 把 denied 的权限算成同意会让"同意前收集"反过来；
`_flow_unusable` 漏掉 unresolved 的流会把别的 App 的外发记到被审计包头上。
"""
from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "traffic"))
import tagging_mobile  # noqa: E402
from read_semantics import obtained_reads


def _ts(record: dict) -> int | None:
    v = record.get("host_received_ts")
    return v if v is not None else record.get("ts")


def _ok_reads(reads: list[dict], data_type: str) -> list[dict]:
    return obtained_reads(reads, data_type)




def _flow_unusable(f: dict) -> bool:
    """这条流能不能用于给被审计包下结论。

    排除两类：归因歧义（时间上分不清谁发的），和归因未解析（unresolved，可能是别的
    App 的流落进来、尚未对上）。历史/测试流没有 attribution 字段时不算 unresolved。
    """
    return (bool(f.get("attribution_ambiguous"))
            or f.get("attribution") in ("unresolved", "ambiguous"))


def _labels_for_flow(flow: dict) -> list[dict]:
    return tagging_mobile.types_for_labels(flow.get("request_tags") or [])


def _flow_types(flow: dict) -> set[str]:
    """流里的标签映射到的数据类别（形态级）。"""
    return {t["data_type"] for t in _labels_for_flow(flow) if t.get("data_type")}


def value_matches(read: dict, flow: dict) -> str | None:
    """读取的值哈希是否出现在流的令牌里。→ 命中的 token 或 None。"""
    vh = read.get("value_hash")
    if not vh:
        return None
    for token in (flow.get("request_tokens") or []):
        if token.endswith(":" + vh):
            return token
    return None


def _finding(rule: dict, *, evidence_kind: str, event_ids: list, extra: dict,
             data_type_zh: str | None = None, note: str) -> dict:
    cond = rule["condition"]
    base = {
        "rule_id": rule["rule_id"], "rule_revision": rule["rule_revision"],
        "title": rule["title"], "rule_type": rule["rule_type"],
        "severity": rule["severity"], "conclusion_level": rule["conclusion_level"],
        "rule_enabled": bool(rule["enabled"]), "predicate": cond.get("predicate"),
        "evidence_kind": evidence_kind, "event_ids": event_ids,
        "data_type": cond.get("data_type"), "data_type_zh": data_type_zh,
        "basis_refs": rule["basis_refs"], "source_refs": rule["source_refs"],
        "evidence_source": "mobile_runtime_or_traffic", "note": note,
    }
    base.update(extra)
    return base
