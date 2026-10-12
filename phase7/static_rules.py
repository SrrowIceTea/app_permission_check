#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Phase 7 — 拿 `rules.db` 去匹配 APK 里的静态事实。

仅用于授权测试（自有设备与自有 APK）/ For authorized testing on owned devices and APKs only.

**结论等级封顶在 `candidate`（D701）。** 本模块只能得出"代码里引用了 X"，
得不出"运行时读了 X"——`observed` 在本项目里的定义就是运行时观测到。
把引用当读取会让报告凭空多出违规，这正是 D507 要避免的那类问题。

**三种属性信号分开记，不合并成一个"命中"**，因为强度不同：

    property_name_string   属性名作为字符串出现        最弱（可能只是日志/注释文本）
    property_id_constant   属性 ID 常量出现在 dex 里    中（更像是真的在用这个属性）
    cpm_api_invoked        出现了 CPM 读取方法的调用    强（但仍不证明参数是它）

`strength` 只是把上面三项合成一个便于阅读的标签，原始三项**始终**保留在结论里，
避免让读者以为"strong"就等于"确认"。
"""
from __future__ import annotations

import json
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from core.rules_contract import load_rules as _load_rules  # noqa: E402

LEVEL_ORDER = ["candidate", "observed", "correlated", "policy_violation"]


def open_rules(db: Path) -> sqlite3.Connection:
    """只读打开——与 `phase6/dashboard.py:43` 同一套 idiom，避免误写规则库。"""
    return sqlite3.connect(f"file:{db.resolve().as_posix()}?mode=ro", uri=True)


def load_rules(db: Path, android_version: str) -> dict:
    """平台无关地读规则库（公共表 + 按平台读扩展表）。

    具体契约见 `core/rules_contract.py`：车载库读 `vhal_properties`，移动库不读
    （返回空 `properties`），这样移动库**不需要伪造空表**就能被同一套 evaluate() 处理。
    """
    return _load_rules(db, android_version)


def cap_level(declared: str) -> str:
    """把规则声明的等级压到 `candidate`。**静态证据不得高于它。**"""
    if declared not in LEVEL_ORDER:
        return "candidate"
    return "candidate" if LEVEL_ORDER.index(declared) > 0 else declared


def _api_referenced(api: dict, facts: dict) -> bool:
    cls, method, desc = api.get("class_name"), api.get("method_name"), api.get("jvm_descriptor")
    if not (cls and method and desc):
        return False
    return f"{cls}.{method}{desc}" in facts["method_refs"]


def cpm_read_api_referenced(loaded: dict, facts: dict) -> bool:
    """dex 里有没有调用 CPM 的读取方法。

    判据用 `dangerous_apis` 的 `(class_name, method_name, jvm_descriptor)` **三元组**，
    不用 `api_key`——`api_key` 只由 method+descriptor 组成、不含类名，
    跟着它走会把别的类的同名方法也算进来（`phase1/python/extract_seed.py:134`）。

    这是**整个 APK 级的**事实，不是逐属性的事实。早先把它算进每个属性的 signals，
    于是 8 条规则一起显示"strong"——看起来证据很强，其实毫无区分力。
    """
    return any(_api_referenced(api, facts) for api in loaded["apis"].values())


def _property_signals(prop: dict, facts: dict, present_ids: set) -> dict:
    """单个属性的静态信号 + **区分度**。

    实测夹具：`VhalProps` 一次性声明了全部 8 个属性 ID，于是 8 个 ID 和 8 个属性名
    **全都**出现在 dex 里。此时"ID 出现"这条对**区分这个属性与其它属性毫无作用**，
    报成 8 条强证据会直接误导读者（"这个 App 读了全部 8 个属性"）。

    所以这里显式算 `non_discriminating`：只有当这份 dex 里**没有**别的已知属性 ID 时，
    "ID 出现"才真的指向这一个属性；或者代码里出现了指向该属性的**字段引用**
    （例如 `android.car.VehiclePropertyIds.GEAR_SELECTION`），那才是逐属性的证据。
    """
    if not prop:
        return {}
    name, pid = prop.get("property_name"), prop.get("property_id")
    field_hit = bool(name) and any(ref.endswith("." + name) for ref in facts["field_refs"])
    id_hit = pid is not None and pid in facts["int_values"]
    name_hit = bool(name) and name in facts["strings"]
    others = present_ids - ({pid} if pid is not None else set())
    return {
        "property_field_ref": field_hit,
        "property_id_constant": id_hit,
        "property_name_string": name_hit,
        # 只靠 ID/名字出现、而同一份 dex 里还有别的属性 ID：无法区分是哪一个
        "non_discriminating": (id_hit or name_hit) and not field_hit and bool(others),
    }


def _strength(signals: dict) -> str:
    if signals.get("property_field_ref"):
        return "strong"                      # 指向该属性的字段引用，逐属性有效
    if signals.get("non_discriminating"):
        return "weak"                        # 只是"这份 dex 里提到过属性 ID/名字"
    if signals.get("property_id_constant") or signals.get("property_name_string"):
        return "medium"
    return "none"


def _finding(rule: dict, kind: str, signals: dict, note: str, context: dict) -> dict:
    return {
        "rule_id": rule["rule_id"], "rule_revision": rule["rule_revision"],
        "title": rule["title"], "rule_type": rule["rule_type"], "severity": rule["severity"],
        "evidence_kind": kind, "evidence_source": "static_dex_reference",
        # 封顶在 candidate：静态引用不证明运行时行为（D701）
        "conclusion_level": cap_level(rule["conclusion_level"]),
        "declared_conclusion_level": rule["conclusion_level"],
        "signals": signals, "static_strength": _strength(signals), "static_context": context,
        "note": note,
    }


def evaluate(loaded: dict, facts: dict, apk_permissions: list[str]) -> dict:
    """对每条启用的规则求静态匹配。禁用规则不产出结论（与 phase5 一致）。"""
    declared_perms = set(apk_permissions)
    known_ids = {p["property_id"] for p in loaded["properties"].values()
                 if p.get("property_id") is not None}
    present_ids = known_ids & set(facts["int_values"])
    context = {
        "cpm_read_api_referenced": cpm_read_api_referenced(loaded, facts),
        "known_property_ids": len(known_ids),
        "known_property_ids_present_in_dex": len(present_ids),
        "discrimination_note": (
            "这份 dex 里出现了全部/多数已知属性 ID，说明应用自带整张常量表；"
            "此时单条属性的 ID 出现**不能区隔**'用了哪个'，已标为 weak。"
            if len(present_ids) > 1 else
            "这份 dex 里只出现了一(零)个已知属性 ID，ID 出现对定位该属性有效。"),
    }
    findings: list[dict] = []
    evaluated = 0

    for rule in loaded["rules"]:
        if not rule["enabled"]:
            continue
        evaluated += 1
        kind, condition = rule["rule_type"], json.loads(rule["condition_json"] or "{}")

        if kind == "over_permission":
            permission = condition.get("permission") or rule.get("permission_name")
            if permission and permission in declared_perms:
                findings.append(_finding(rule, "static_manifest_permission",
                                         {"permission_declared": True},
                                         "清单声明了该权限；声明不等于会去用，必要性需人工复核。",
                                         context))
        elif kind in ("sensitive_read", "data_egress"):
            prop = loaded["properties"].get(rule.get("property_key") or "")
            if prop is None and condition.get("property_id") is not None:
                prop = next((p for p in loaded["properties"].values()
                             if p.get("property_id") == condition["property_id"]), None)
            signals = _property_signals(prop, facts, present_ids)
            if any(signals.values()):
                note = ("代码里引用了该属性；**这不证明运行时读取过它**，也不证明具体值被外发。"
                        if not signals.get("non_discriminating") else
                        "同一份 dex 里还出现其它已知属性 ID，本条**不能区分**是哪个属性被用到；"
                        "只说明这份代码带有属性常量表。")
                findings.append(_finding(rule, "static_dex_reference", signals, note, context))

    missing = sorted({r["rule_type"] for r in loaded["rules"] if r["enabled"]}
                     - {"over_permission", "sensitive_read", "data_egress"})
    return {"findings": findings, "rules_evaluated": evaluated,
            "static_context": context, "unhandled_rule_types": missing,
            "caveat": "静态结论来自 dex 里的引用，等级封顶 candidate；"
                      "不证明运行时行为，不产出 policy_violation。"}
