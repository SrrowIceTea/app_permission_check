#!/usr/bin/env python3
"""移动隐私规则的求值器 —— 纯函数，可离线测试。

仅用于授权测试（已获授权的样本与设备）。

八种谓词与各自的**证据下限**（判定可追溯：每条结论都带 rule_id + 依据条款）：

    manifest_permission_requires_necessity_review  清单权限          → candidate
    successful_sensitive_api_read                  读取事件          → observed
    read_before_consent_or_permission_grant        读取 + 权限结果   → candidate
    read_before_egress_within_window               读取 + 流         → correlated
    data_type_not_in_necessary_scope               读取 + 类目范围   → candidate
    sensitive_data_in_plaintext_flow               流                → observed
    sensitive_data_to_third_party_domain           流                 → candidate
    data_type_absent_from_policy_disclosure        读取 + 政策       → candidate

三条贯穿全篇的诚实规则：
  * **不同意就说不可判**：同意时序缺失时，no_consent 类结论不产出（进 gaps），
    不把"没采到同意事件"当成"没有同意"。政策接受缺直接信号时未知，不能从缺事件反推未同意。
  * **值级匹配 > 形态匹配**：只有读取事件的值哈希出现在报文的令牌里才算
    "确实发了这个值"；仅标签形状相同只给弱依据，并如实标注。
  * **缺输入不猜**：类目未知、政策未取得时，对应谓词返回 not_evaluable。
"""
from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent.parent))
from core.collector.attribution import ATTRIB_LOOSE_MS, is_loose  # noqa: E402
# 取值/配对/成形部件搬到相邻模块（原文件越 300 行红线，§8.2 B-2）。
# `json` 一并去掉：它在本文件里已经没有任何用处（存量 F401）。
# ch 侧删除了 `_consent_for`（同意判定改由 `consent_semantics.permission_timing` 承担），
# main 侧新增 `value_match_form`（C1 摘要形态溯源）——两者互不冲突，一并保留。
from evaluation_mobile_parts import (_finding, _flow_types,  # noqa: E402
                                     _flow_unusable, _ok_reads, _ts, value_match_form,
                                     value_matches)

# 对外保留：`correlate_mobile.py` 用 `ev.CONSENT_SIGNALS` 过滤同意事件。
from consent_semantics import permission_timing
CONSENT_SIGNALS = ("PERM_REQ", "PERM_RESULT", "PERM_CHECK", "POLICY_VIEW")


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
                        note=f"观测到 {len(hits)} 次非空返回值/非空结果集。空值、拒绝、调用未证实取得值不计入。")

    if pred == "read_before_consent_or_permission_grant":
        hits = _ok_reads(reads, dt)
        if not hits:
            return None
        timing = permission_timing(hits, ctx.get("consent"), ctx["dt_hints"].get(dt) or [])
        if timing is None:
            return None
        note = timing.pop("note")
        result = _finding(rule, evidence_kind="read_event",
                          event_ids=[r.get("evt_id") for r in hits[:5]],
                          extra={"package": ctx["package"], **timing},
                          data_type_zh=ctx["dt_zh"].get(dt), note=note)
        result["title"] = "运行时权限时序待复核（政策同意未知）"
        result["conclusion_level"] = "candidate"
        return result

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
                    # C1 溯源：raw=原值哈希命中；md5/sha1/sha256=原值的摘要形态命中
                    #（报文里是摘要串，不是原值本身——如实区分，不许混称）。
                    "value_match_form": value_match_form(token),
                    # C1 溯源：raw=原值哈希命中；md5/sha1/sha256=原值的摘要形态命中
                    #（报文里是摘要串，不是原值本身——如实区分，不许混称）。
                    "value_match_form": value_match_form(token),
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
        # C1 溯源：收集所有值级命中用到的形态，区分「原值」与「原值的摘要形态」。
        forms = {p.get("value_match_form") for p in pairs
                 if p["content_match_basis"] == "value_hash_in_payload"}
        derived = forms - {"raw"}
        extra = {"package": ctx["package"], "pair_count": len(pairs),
                 "pairs": pairs, "window_ms": window,
                 "window_declared_ms": rule.get("window_ms"),
                 "window_overridden": window != rule.get("window_ms"),
                 "content_match": True,
                 "content_match_basis": ("value_hash_in_payload" if strong
                                         else "shape_tag")}
        # 值级命中的表述按实际形态如实区分（C1）：摘要命中 ≠ 原值明文出现。
        # 三种情形统一在此成形，避免归因偏松分支与正常分支给出不一致的说法。
        if strong:
            if derived:
                names = "、".join(sorted(derived))
                value_note = ("值级匹配（摘要形态）：读取值的 " + names +
                              " 摘要出现在报文中——原值本身未必以明文出现，"
                              "但摘要可由原值算出，仍属「确实发了这个值」的值级证据。")
            else:
                value_note = "值级匹配：读取到的值的哈希出现在报文中。"
        else:
            value_note = "仅形态级匹配（报文出现同类形状），**不等于**该值被传输。"
        if any(p.get("attribution_loose") for p in pairs):
            extra["conclusion_level"] = "candidate"
            extra["declared_conclusion_level"] = rule["conclusion_level"]
            extra["conclusion_capped_by"] = "attribution_loose"
            note = (value_note.rstrip("。") + f"（但至少一条流的时间归因距离 ≥ "
                    f"{ATTRIB_LOOSE_MS}ms，归因偏松，结论封顶 candidate）。")
            return _finding(rule, evidence_kind="read_then_egress",
                            event_ids=sorted({p["read_event_id"] for p in pairs}
                                             | {p["flow_event_id"] for p in pairs}),
                            extra=extra, data_type_zh=ctx["dt_zh"].get(dt), note=note)
        return _finding(rule, evidence_kind="read_then_egress",
                        event_ids=sorted({p["read_event_id"] for p in pairs}
                                         | {p["flow_event_id"] for p in pairs}),
                        extra=extra, data_type_zh=ctx["dt_zh"].get(dt), note=value_note)

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
            plaintext = f.get("intercepted_tls") is False
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
