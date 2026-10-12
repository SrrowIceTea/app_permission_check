#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""规则库契约：车载与移动端两套规则库的公共加载接口 + 平台判别。

仅用于授权测试（自有设备与自有 APK）/ For authorized testing on owned devices and APKs only.

两套规则库物理独立、schema 大部分相同（`risk_rules` / `dangerous_apis` / `permissions`），
差异只在：

- 车载独有扩展表 `vhal_properties`，`risk_rules` 用 `property_key` 指 VHAL 属性；
- 移动独有 `sensitive_data_types` / `app_categories` / `policy_requirements`，
  `risk_rules` 用 `data_type_key` 指数据类别。

**`rule_id` 前缀是权威判别符**：`VSC-*` 车载、`MOB-*` 移动。凡是要按平台"多读/少读
一张扩展表"的地方，都必须走这里的 `load_rules`，不得在别处重写一份——那是漂移的
温床（本项目已为"两份相同实现各自漂移"付过多次代价）。

共同必需列（`risk_rules`）：`rule_id, rule_revision, rule_type, severity,
window_ms, conclusion_level, enabled`。
"""
from __future__ import annotations

import sqlite3
from pathlib import Path

# 平台 → 该平台独有、可选的扩展表。公共表（risk_rules/dangerous_apis/permissions）不列。
EXTENSION_TABLES: dict[str, tuple[str, ...]] = {
    "vehicle": ("vhal_properties",),
    "mobile": ("sensitive_data_types", "app_categories", "policy_requirements"),
}

# rule_id 前缀 → 平台。这是权威判别符。
PREFIX_PLATFORM = {"VSC-": "vehicle", "MOB-": "mobile"}

REQUIRED_RULE_COLUMNS = ("rule_id", "rule_revision", "rule_type", "severity",
                         "window_ms", "conclusion_level", "enabled")


def _readonly(db: Path) -> sqlite3.Connection:
    """只读打开——与 phase6/dashboard.py:43、phase7/static_rules.py 同一套 idiom。"""
    return sqlite3.connect(f"file:{db.resolve().as_posix()}?mode=ro", uri=True)


def detect_platform(conn: sqlite3.Connection) -> str | None:
    """判定平台：先看 rule_id 前缀，退到扩展表是否存在。

    优先规则前缀，因为它不会因为"有人顺手建了张空表"而误判；扩展表只作兜底。
    """
    row = conn.execute("SELECT rule_id FROM risk_rules LIMIT 1").fetchone()
    if row and row[0]:
        for prefix, platform in PREFIX_PLATFORM.items():
            if row[0].startswith(prefix):
                return platform
    tables = {r[0] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'")}
    if "vhal_properties" in tables:
        return "vehicle"
    if "sensitive_data_types" in tables:
        return "mobile"
    return None


def load_rules(db: Path, android_version: str) -> dict:
    """读公共表 + 按平台读扩展表，形状与 phase7/static_rules.load_rules 一致：

        {"rules": [...], "properties": {property_key: dict},
         "apis": {api_key: dict}, "known_permissions": set, "platform": str}

    `properties` 在移动库上为空 dict（没有 `vhal_properties`）——这是"移动样本没有
    属性信号维度"的正确表达，而不是伪造一张空表去骗过加载器（那是移动侧曾经的 hack）。
    """
    conn = _readonly(db)
    conn.row_factory = sqlite3.Row
    try:
        platform = detect_platform(conn) or "vehicle"
        rules = [dict(r) for r in conn.execute(
            "SELECT * FROM risk_rules WHERE android_version = ? ORDER BY rule_id",
            (android_version,))]
        props: dict = {}
        if "vhal_properties" in EXTENSION_TABLES.get(platform, ()):
            props = {r["property_key"]: dict(r) for r in conn.execute(
                "SELECT * FROM vhal_properties WHERE android_version = ?",
                (android_version,))}
        apis = {r["api_key"]: dict(r) for r in conn.execute(
            "SELECT * FROM dangerous_apis WHERE android_version = ?",
            (android_version,))}
        perms = {r["permission_name"] for r in conn.execute(
            "SELECT permission_name FROM permissions WHERE android_version = ?",
            (android_version,))}
    finally:
        conn.close()
    return {"rules": rules, "properties": props, "apis": apis,
            "known_permissions": perms, "platform": platform}
