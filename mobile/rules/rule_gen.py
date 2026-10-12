#!/usr/bin/env python3
"""从「数据类别 × 规则类型」矩阵生成 risk_rules 行。

仅用于授权测试（已获授权的样本与设备）。

设计要点：
  * 规则 ID 方案 MOB-<类型字母><三位序号>，序号按种子表声明顺序，稳定不重排；
    新规则一律追加，不改变既有 ID 的含义。
  * 每条 enabled 规则必须带 condition_json / evidence_requirements_json /
    source_refs_json / basis_refs_json（schema CHECK 会兜底），且
    **basis_refs 引用的是已核对的法规条款**（见 regulations/ 下的 JSON，
    带文件 sha256，可逐条回溯）。
  * window_ms 只出现在 data_egress —— 时间窗是夹具校准参数，
    不是法律阈值；未校准时如实标 uncalibrated。
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

# 规则类型元数据：前缀 / 谓词 / 结论上限 / 是否需要时间窗
RULE_TYPE_META = {
    "over_permission": {"prefix": "P", "predicate": "manifest_permission_requires_necessity_review",
                        "conclusion": "candidate", "window": False},
    "sensitive_read": {"prefix": "R", "predicate": "successful_sensitive_api_read",
                       "conclusion": "observed", "window": False},
    "no_consent_read": {"prefix": "C", "predicate": "read_before_consent_or_permission_grant",
                        "conclusion": "observed", "window": False},
    "data_egress": {"prefix": "E", "predicate": "read_before_egress_within_window",
                    "conclusion": "correlated", "window": True},
    "over_collection": {"prefix": "O", "predicate": "data_type_not_in_necessary_scope",
                        "conclusion": "candidate", "window": False},
    "plaintext_transmission": {"prefix": "T", "predicate": "sensitive_data_in_plaintext_flow",
                               "conclusion": "observed", "window": False},
    "third_party_share": {"prefix": "S", "predicate": "sensitive_data_to_third_party_domain",
                          "conclusion": "candidate", "window": False},
    "policy_mismatch": {"prefix": "M", "predicate": "data_type_absent_from_policy_disclosure",
                        "conclusion": "candidate", "window": False},
}

EVIDENCE_REQS = {
    "over_permission": ["manifest_requested_permission", "app_function_description", "apk_sha256"],
    "sensitive_read": ["read_event_id", "data_type", "hook_health_ok",
                       "uid_package_attribution", "rule_and_source_version"],
    "no_consent_read": ["read_event_id", "consent_timeline_event_or_documented_absence",
                        "hook_health_ok", "uid_package_attribution"],
    "data_egress": ["read_event_id", "egress_event_id", "flow_event_id",
                    "reliable_uid_package_attribution", "collector_health_ok"],
    "over_collection": ["collected_data_type", "app_category_declared", "necessary_scope_ref"],
    "plaintext_transmission": ["flow_event_id", "sensitive_tag_or_token", "tls_status",
                               "collector_health_ok"],
    "third_party_share": ["flow_event_id", "sensitive_tag_or_token",
                          "domain_ownership_status", "collector_health_ok"],
    "policy_mismatch": ["collected_data_type", "policy_text_sha256", "policy_disclosure_status"],
}

# 规则类型 → 法规条款（doc 指向 regulations/<id>.json 的 id；clause 为该文件内的编号）
BASIS_CLAUSES = {
    "over_permission": [("yrd-method-2019", "C4.1"), ("pipl-2021", "6")],
    "sensitive_read": [("gbt35273-2020", "3.2"), ("pipl-2021", "28")],
    "no_consent_read": [("yrd-method-2019", "C3.1"), ("pipl-2021", "29")],
    "data_egress": [("yrd-method-2019", "C3.1"), ("pipl-2021", "6")],
    "over_collection": [("yrd-method-2019", "C4.1"), ("necessary-info-2021", "5"), ("pipl-2021", "6")],
    "plaintext_transmission": [("pipl-2021", "51")],
    "third_party_share": [("yrd-method-2019", "C5.1")],
    "policy_mismatch": [("yrd-method-2019", "C2.1"), ("pipl-2021", "17")],
}

TITLE_BY_TYPE = {
    "over_permission": "{label}：清单声明需必要性复核",
    "sensitive_read": "{label}：敏感数据读取",
    "no_consent_read": "{label}：同意前/未授权读取",
    "data_egress": "{label}：读取后外发（窗口内）",
    "over_collection": "{label}：超出必要范围收集",
    "plaintext_transmission": "{label}：明文/未加密传输",
    "third_party_share": "{label}：向第三方域名外发",
    "policy_mismatch": "{label}：隐私政策未声明即收集",
}


def regulation_index(reg_dir: Path) -> dict[str, dict]:
    """读 regulations/*.json，返回 {id: {path, sha256, title}}，供 basis_refs 引用。"""
    index: dict[str, dict] = {}
    for p in sorted(reg_dir.glob("*.json")):
        doc = json.loads(p.read_text(encoding="utf-8"))
        index[doc["id"]] = {"path": str(p), "sha256": hashlib.sha256(p.read_bytes()).hexdigest(),
                            "title": doc["title"]}
    return index


def _basis_refs(rule_type: str, reg_index: dict[str, dict]) -> list[dict]:
    refs = []
    for doc_id, clause in BASIS_CLAUSES[rule_type]:
        meta = reg_index.get(doc_id)
        if meta is None:
            raise ValueError(f"规则类型 {rule_type} 引用了不存在的法规文件 id: {doc_id}")
        refs.append({"doc": doc_id, "clause": clause, "kind": "regulation",
                     "title": meta["title"], "path": meta["path"], "sha256": meta["sha256"]})
    return refs


def _condition(rule_type: str, *, data_type: str | None, permission: str | None,
               window_ms: int | None) -> dict:
    base: dict = {"draft_dsl": 1, "predicate": RULE_TYPE_META[rule_type]["predicate"],
                  "session_whitelist_required": True}
    if data_type:
        base["data_type"] = data_type
    if permission:
        base["permission"] = permission
    if rule_type == "data_egress":
        base.update({"content_match": "required_to_upgrade_beyond_temporal_correlation",
                     "same_session": True, "same_attributed_package": True,
                     "clock_normalized": True})
    if rule_type == "no_consent_read":
        base["consent_basis"] = "runtime_permission_grant_or_policy_consent"
        base["absence_requires_documented_timeline"] = True
    if rule_type == "over_collection":
        base["requires_app_category"] = True
    if rule_type == "third_party_share":
        base["requires_domain_ownership"] = True
    if rule_type == "policy_mismatch":
        base["requires_policy_text"] = True
    if rule_type == "plaintext_transmission":
        base["tls_required_for_absence"] = True
    return base


def generate(data_types: list[dict], permissions: list[dict], *, version: str,
             reg_index: dict[str, dict], window_ms: int | None,
             window_calibrated: bool) -> list[dict]:
    """生成规则行。data_types/permissions 为种子表条目。"""
    rules: list[dict] = []
    counters: dict[str, int] = {}

    def next_id(rule_type: str) -> str:
        prefix = RULE_TYPE_META[rule_type]["prefix"]
        counters[prefix] = counters.get(prefix, 0) + 1
        return f"MOB-{prefix}{counters[prefix]:03d}"

    # 1) over_permission：每条隐私权限一条
    for perm in permissions:
        meta = RULE_TYPE_META["over_permission"]
        rules.append({
            "rule_id": next_id("over_permission"), "title":
                TITLE_BY_TYPE["over_permission"].format(label=perm["permission_name"].rsplit(".", 1)[-1]),
            "rule_type": "over_permission", "severity": perm["severity"],
            "permission_name": perm["permission_name"], "data_type_key": None, "api_key": None,
            "condition_json": _condition("over_permission", data_type=None,
                                         permission=perm["permission_name"], window_ms=None),
            "evidence_requirements_json": {"all": EVIDENCE_REQS["over_permission"]},
            "window_ms": None, "conclusion_level": meta["conclusion"],
            "basis_refs_json": _basis_refs("over_permission", reg_index),
            "source_refs_json": [{"kind": "project_seed", "path": "seed/permissions.json",
                                  "note": perm["why"]}],
            "enabled": 1,
            "notes": f"权限必要性与业务功能相关，工具不判定必要性；{perm['why']}",
        })

    # 2) 数据类别 × 其余规则类型
    for dt in data_types:
        key, label = dt["data_type_key"], dt["name_zh"]
        for rule_type in dt["enable"]:
            if rule_type == "over_permission":
                continue
            meta = RULE_TYPE_META[rule_type]
            is_window = meta["window"]
            if is_window and window_ms is None:
                raise ValueError("data_egress 规则需要 --window-ms；不设窗口不得启用")
            rules.append({
                "rule_id": next_id(rule_type),
                "title": TITLE_BY_TYPE[rule_type].format(label=label),
                "rule_type": rule_type, "severity": dt["severity"],
                "permission_name": None, "data_type_key": key, "api_key": None,
                "condition_json": _condition(rule_type, data_type=key, permission=None,
                                             window_ms=window_ms if is_window else None),
                "evidence_requirements_json": {"all": EVIDENCE_REQS[rule_type]},
                "window_ms": window_ms if is_window else None,
                "conclusion_level": meta["conclusion"],
                "basis_refs_json": _basis_refs(rule_type, reg_index),
                "source_refs_json": [{
                    "kind": "project_seed", "path": "seed/sensitive_data_types.json",
                    "data_type_key": key, "sensitivity": dt["sensitivity"],
                    "gbt_category": dt["gbt_category"]}],
                "enabled": 1,
                "notes": (f"时间窗 {window_ms}ms，" + ("已由移动夹具校准。"
                          if window_calibrated else
                          "**尚未由移动夹具校准**，是声明值而非实测阈值；"
                          "在 WINDOW_CALIBRATION.md 记录实测前不得当作通用阈值。")
                          if is_window else dt.get("why", "")),
            })
    return rules


def summarize_rule_counts(rules: list[dict]) -> dict:
    counts: dict[str, int] = {}
    for r in rules:
        counts[r["rule_type"]] = counts.get(r["rule_type"], 0) + 1
    return dict(sorted(counts.items()))
