#!/usr/bin/env python3
"""移动隐私规则的求值器 —— 纯函数，可离线测试。

仅用于授权测试（已获授权的样本与设备）。

八种谓词与各自的**证据下限**（判定可追溯：每条结论都带 rule_id + 依据条款）：

    manifest_permission_requires_necessity_review  清单权限          → candidate
    successful_sensitive_api_read                  读取事件          → observed
    read_before_consent_or_permission_grant        读取 + 同意时序   → observed
    read_before_egress_within_window               读取 + 流         → correlated
    data_type_not_in_necessary_scope               读取 + 类目范围   → candidate
    sensitive_data_in_plaintext_flow               流                → observed
    sensitive_data_to_third_party_domain           流                 → candidate
    data_type_absent_from_policy_disclosure        读取 + 政策       → candidate

三条贯穿全篇的诚实规则：
  * **不同意就说不可判**：同意时序缺失时，no_consent 类结论不产出（进 gaps），
    不把"没采到同意事件"当成"没有同意"。同意时序存在但没有相关授权，
    才是"窗口内未授权"的证据。
  * **值级匹配 > 形态匹配**：只有读取事件的值哈希出现在报文的令牌里才算
    "确实发了这个值"；仅标签形状相同只给弱依据，并如实标注。
  * **缺输入不猜**：类目未知、政策未取得时，对应谓词返回 not_evaluable。
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "traffic"))
sys.path.insert(0, str(HERE.parent.parent))
import tagging_mobile  # noqa: E402
from core.collector.attribution import ATTRIB_LOOSE_MS, is_loose  # noqa: E402

CONSENT_SIGNALS = ("PERM_RESULT", "POLICY_VIEW")


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
    return bool(f.get("attribution_ambiguous")) or f.get("attribution") in ("unresolved", "ambiguous")


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


def evaluate(rule: dict, ctx: dict) -> dict | None:
    cond = rule["condition"]
    if not rule["enabled"]:
        return None
    pred = cond.get("predicate")
    version = rule["android_version"]

    if pred == "manifest_permission_requires_necessity_review":
        perm = cond.get("permission") or rule.get("permission_name")
        if perm and perm in (ctx.get("permissions") or []):
            return _finding(rule, evidence_kind="manifest_permission", event_ids=[],
                            extra={"package": ctx["package"], "permission": perm,
                                   "app_category": (ctx.get("category") or {}).get("name_zh")},
                            note="清单声明了该权限。是否超出业务必要，工具不判定。")
        return None

    dt = cond.get("data_type")
    reads = ctx.get("reads") or []
    if pred == "successful_sensitive_api_read":
        hits = _ok_reads(reads, dt)
        if not hits:
            return None
        return _finding(rule, evidence_kind="read_event",
                        event_ids=[r.get("evt_id") for r in hits],
                        extra={"package": ctx["package"], "read_count": len(hits)},
                        data_type_zh=ctx["dt_zh"].get(dt),
                        note=f"成功读取 {len(hits)} 次（outcome=ok）。被拒绝的读取不计入。")

    if pred == "read_before_consent_or_permission_grant":
        hits = _ok_reads(reads, dt)
        if not hits:
            return None
        consent = ctx.get("consent")
        if consent is None:
            return None          # 时序缺失 → 不产出（由 gaps 说明），不猜
        hints = ctx["dt_hints"].get(dt) or []
        rel = _consent_for(dt, consent, hints)
        first_read = min(_ts(r) for r in hits if _ts(r) is not None) if hits else None
        first_consent = min((_ts(c) for c in rel if _ts(c) is not None), default=None)
        if first_consent is not None and first_read is not None and first_consent <= first_read:
            return None          # 同意在先，不构成
        return _finding(rule, evidence_kind="read_event",
                        event_ids=[r.get("evt_id") for r in hits[:5]],
                        extra={"package": ctx["package"],
                               "first_read_ts": first_read, "first_consent_ts": first_consent,
                               "consent_evidence_ids": [c.get("evt_id") for c in rel],
                               "consent_absent": first_consent is None,
                               "related_permission_hints": hints},
                        data_type_zh=ctx["dt_zh"].get(dt),
                        note=("观察窗口内未出现该数据类别的同意事件（权限授予或政策页打开）。"
                              if first_consent is None else
                              "该数据类别的读取早于对应同意事件。")
                             + " 同意状态由权限结果/政策页打开代理，不是同意的直接证明。")

    if pred == "read_before_egress_within_window":
        hits = _ok_reads(reads, dt)
        if not hits:
            return None
        window = ctx["window_override_ms"] or rule.get("window_ms")
        if not window:
            return None
        pairs = []
        for r in hits:
            rt = _ts(r)
            if rt is None:
                continue
            for f in (ctx.get("flows") or []):
                ft = _ts(f)
                if ft is None or _flow_unusable(f):
                    continue
                if not (0 <= ft - rt <= window):
                    continue
                token = value_matches(r, f)
                shape = dt in _flow_types(f)
                if not token and not shape:
                    continue
                pairs.append({
                    "read_event_id": r.get("evt_id"), "flow_event_id": f.get("evt_id"),
                    "delta_ms": ft - rt, "clock_basis": "host_received_ts",
                    "content_match": True,
                    "content_match_basis": "value_hash_in_payload" if token else "shape_tag",
                    "matched_token": token,
                    "flow_host": f.get("host"), "flow_path": f.get("path"),
                    "flow_method": f.get("method"), "client_tls": f.get("intercepted_tls"),
                    # 归因置信信息（D414）：让"这条配对建立在多紧的归因上"可见。
                    "attribution_delta_ms": f.get("attribution_delta_ms"),
                    "attribution_runner_up": f.get("attribution_runner_up"),
                    "attribution_candidates": f.get("attribution_candidates"),
                    "attribution_loose": is_loose(f),
                })
        if not pairs:
            return None
        strong = any(p["content_match_basis"] == "value_hash_in_payload" for p in pairs)
        extra = {"package": ctx["package"], "pair_count": len(pairs),
                 "pairs": pairs, "window_ms": window,
                 "window_declared_ms": rule.get("window_ms"),
                 "window_overridden": window != rule.get("window_ms"),
                 "content_match": True,
                 "content_match_basis": ("value_hash_in_payload" if strong
                                         else "shape_tag")}
        if any(p.get("attribution_loose") for p in pairs):
            extra["conclusion_level"] = "candidate"
            extra["declared_conclusion_level"] = rule["conclusion_level"]
            extra["conclusion_capped_by"] = "attribution_loose"
            note = (f"值级匹配：读取到的值的哈希出现在报文中（但至少一条流的时间归因距离 ≥ "
                    f"{ATTRIB_LOOSE_MS}ms，归因偏松，结论封顶 candidate）。" if strong else
                    f"仅形态级匹配（报文出现同类形状），且至少一条流的时间归因距离 ≥ "
                    f"{ATTRIB_LOOSE_MS}ms，结论封顶 candidate。")
            return _finding(rule, evidence_kind="read_then_egress",
                            event_ids=sorted({p["read_event_id"] for p in pairs}
                                             | {p["flow_event_id"] for p in pairs}),
                            extra=extra, data_type_zh=ctx["dt_zh"].get(dt), note=note)
        return _finding(rule, evidence_kind="read_then_egress",
                        event_ids=sorted({p["read_event_id"] for p in pairs}
                                         | {p["flow_event_id"] for p in pairs}),
                        extra=extra, data_type_zh=ctx["dt_zh"].get(dt),
                        note=("值级匹配：读取到的值的哈希出现在报文中。"
                              if strong else
                              "仅形态级匹配（报文出现同类形状），**不等于**该值被传输。"))

    if pred == "data_type_not_in_necessary_scope":
        category = ctx.get("category") or {}
        if not category.get("known"):
            return None
        hits = _ok_reads(reads, dt)
        if not hits:
            return None
        necessary = {x["data_type_key"] for x in (category.get("necessary_data") or [])
                     if x.get("data_type_key")}
        if dt in necessary:
            return None
        return _finding(rule, evidence_kind="read_event",
                        event_ids=[r.get("evt_id") for r in hits[:5]],
                        extra={"package": ctx["package"],
                               "app_category": category.get("name_zh"),
                               "necessary_data_keys": sorted(necessary),
                               "no_personal_info_required": category.get("no_personal_info_required")},
                        data_type_zh=ctx["dt_zh"].get(dt),
                        note=(f"该类别不在「{category.get('name_zh')}」的必要个人信息范围内。"
                              "是否属于业务功能无关，仍需结合具体功能判断。"))

    if pred == "sensitive_data_in_plaintext_flow":
        out = []
        for f in (ctx.get("flows") or []):
            if _flow_unusable(f):
                continue
            plaintext = (f.get("scheme") == "http") or (f.get("intercepted_tls") is False)
            if not plaintext:
                continue
            types = _flow_types(f)
            if dt not in types:
                continue
            out.append(f)
        if not out:
            return None
        return _finding(rule, evidence_kind="flow_sensitive_payload",
                        event_ids=[f.get("evt_id") for f in out],
                        extra={"package": ctx["package"], "flow_count": len(out),
                               "flows": [{"event_id": f.get("evt_id"), "host": f.get("host"),
                                          "path": f.get("path"), "scheme": f.get("scheme"),
                                          "intercepted_tls": f.get("intercepted_tls")}
                                         for f in out]},
                        data_type_zh=ctx["dt_zh"].get(dt),
                        note="未使用 TLS 的报文中出现该类数据的形态标签。标签是线索，不是值级证明。")

    if pred == "sensitive_data_to_third_party_domain":
        out = [f for f in (ctx.get("flows") or [])
               if not _flow_unusable(f) and dt in _flow_types(f)]
        if not out:
            return None
        domains = sorted({f.get("host") for f in out if f.get("host")})
        return _finding(rule, evidence_kind="flow_sensitive_payload",
                        event_ids=[f.get("evt_id") for f in out],
                        extra={"package": ctx["package"], "domains": domains,
                               "flow_count": len(out)},
                        data_type_zh=ctx["dt_zh"].get(dt),
                        note="报文出现该类数据形态并送往上述域名。"
                             "**域名是否属于第三方尚未判定**（需注册主体/归属查询），故结论封顶 candidate。")

    if pred == "data_type_absent_from_policy_disclosure":
        policy = ctx.get("policy") or {}
        if not policy.get("available") or policy.get("extract_status") != "ok":
            return None
        scan = (policy.get("disclosure_scan") or {}).get(dt) or {}
        if scan.get("found"):
            return None
        hits = _ok_reads(reads, dt)
        if not hits:
            return None
        return _finding(rule, evidence_kind="read_event",
                        event_ids=[r.get("evt_id") for r in hits[:5]],
                        extra={"package": ctx["package"],
                               "policy_sha256": policy.get("raw_sha256"),
                               "disclosure_scan": scan},
                        data_type_zh=ctx["dt_zh"].get(dt),
                        note="观察到该类数据读取，且政策文本里未命中该类别的表述关键词。"
                             "**关键词未命中不等于政策未声明**，需人工/AI 复核语义。")

    return None
