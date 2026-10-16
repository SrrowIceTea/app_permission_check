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
_REPO = str(HERE.parent.parent)
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)
import tagging_mobile  # noqa: E402
from core.collector import derive  # noqa: E402  派生值候选（C1，平台无关内核）


def _ts(record: dict) -> int | None:
    v = record.get("host_received_ts")
    return v if v is not None else record.get("ts")


def _ok_reads(reads: list[dict], data_type: str) -> list[dict]:
    return [r for r in reads
            if r.get("ev") == "PRIVACY_READ" and r.get("outcome") == "ok"
            and data_type in (r.get("data_types") or [])]


def _consent_for(data_type: str, consent: list[dict], hints: list[str]) -> list[dict]:
    """与该数据类别相关的同意事件。PERM_RESULT 只算 granted 的那些；
    部分授权时 denied 的权限不算同意（否则"同意前收集"会被反过来算）。"""
    out = []
    for c in consent:
        ev = c.get("ev")
        if ev == "PERM_RESULT":
            if any(h in (c.get("granted") or []) for h in hints):
                out.append(c)
        elif ev == "POLICY_VIEW":
            out.append(c)
    return out


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


def candidate_hashes(read: dict) -> dict[str, str]:
    """读取事件能提供的全部**值级**候选（C1）：形态名 → hash16。

    * `raw`：hook 记的原值 sha256 前 16 位（M005 口径，不变）；
    * `md5`/`sha1`/`sha256`：**完整**原值预览的各摘要形态的 hash16——
      应用"先摘要再外发"时，报文里出现的是摘要十六进制串，其令牌后缀
      等于这里的候选（与 tagging 侧 `sha*_hex_shape` 令牌配对）。
    预览以 …（U+2026）结尾 = 被截断：对截断串做摘要没有意义，
    摘要候选整体不参与（只可能漏配，不可能错配——错误方向的候选凑不出哈希相等）。
    """
    out: dict[str, str] = {}
    vh = read.get("value_hash")
    if vh:
        out["raw"] = vh
    preview = read.get("value_preview")
    if preview and not preview.endswith("\u2026"):
        out.update(derive.hash16_candidates(preview))
    return out


# 报文侧摘要形态标签 → 摘要形态名（用于配对溯源，判定可追溯）。
_HASH_FORM_BY_LABEL = {"md5_hex_shape": "md5", "sha1_hex_shape": "sha1",
                       "sha256_hex_shape": "sha256"}


def value_match_form(token: str | None) -> str:
    """命中的令牌用的是哪种形态：raw / md5 / sha1 / sha256 / none。

    报文侧摘要标签（sha*_hex_shape）→ 对应摘要形态；其余标签（含解码产物的
    digit15_shape 等）说明命中的是**原值本身**（可能只是传输途中被编码，
    解码后哈希对上了），一律记 raw。
    """
    if not token:
        return "none"
    label = token.split(":", 1)[0]
    return _HASH_FORM_BY_LABEL.get(label, "raw")


def value_matches(read: dict, flow: dict) -> str | None:
    """读取的值（原值或其摘要形态）的 hash16 是否出现在流的令牌里。

    → 命中的 token 或 None。C1 扩展前只比 `raw` 一种形态；现在比对
    `candidate_hashes(read)` 的全部候选。令牌后缀是 16 位 hex 短哈希，
    逐候选比较的成本可忽略。
    """
    cands = candidate_hashes(read)
    if not cands:
        return None
    for token in (flow.get("request_tokens") or []):
        if any(token.endswith(":" + h) for h in cands.values()):
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
