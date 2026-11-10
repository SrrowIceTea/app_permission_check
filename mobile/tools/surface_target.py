#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""L2 目标集（敏感面作用域）的加载、校验与匹配。

仅用于授权测试（自有设备 / 公开第三方样本的授权评估）。

目标集是**独立文件**：`mobile/rules/targets/sensitive_surface_v1.json`。
它不进 `dangerous_apis`、不碰 `mobile/rules/rules_mobile.db`，规则引擎从不读它；
`observed_surface` 是它唯一的消费方。

它固定的是「**哪些类算敏感面**」，不是「有多少个签名」——签名一律从样本 dex 实测
（见目标集 `scope_rule.signature_source`）。这样做的原因写在该文件的 `scope_rule` 里，
不要在这里另立一套说法。
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

TARGET_SET_DIR = Path(__file__).resolve().parents[1] / "rules" / "targets"
DEFAULT_TARGET_SET = TARGET_SET_DIR / "sensitive_surface_v1.json"


def canonical_sha256(doc: dict) -> str:
    """对目标集除 `sha256` 与运行期附加字段（`_` 前缀）外的规范化 JSON 求哈希。"""
    payload = {k: v for k, v in doc.items() if k != "sha256" and not k.startswith("_")}
    text = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def load(path: str | Path | None = None) -> dict:
    """读目标集并校验 sha256；不匹配直接失败（宁可停下，也不要拿错分母出数）。"""
    p = Path(path) if path else DEFAULT_TARGET_SET
    doc = json.loads(p.read_text(encoding="utf-8"))
    actual = canonical_sha256(doc)
    if actual != doc.get("sha256"):
        raise SystemExit(
            f"[fatal] 目标集 sha256 不匹配：{p}\n  文件内 {doc.get('sha256')}\n  实算 {actual}\n"
            "  目标集被手改过，或该用 target_set_build.py 重新生成。")
    doc["_path"] = str(p)
    return doc


class Matcher:
    """类名 → 品类 / 命名空间组；并判定某个方法是否在作用域内。"""

    def __init__(self, doc: dict):
        self.doc = doc
        self.allowlists: dict[str, set[str]] = {
            cls: set(ms) for cls, ms in (doc.get("method_allowlists") or {}).items()}
        self.exact: dict[str, list[str]] = {}
        self.prefix: list[tuple[str, str]] = []
        for cat in doc["categories"]:
            for entry in cat["entries"]:
                if entry["kind"] == "exact":
                    self.exact.setdefault(entry["value"], []).append(cat["key"])
                else:
                    self.prefix.append((entry["value"], cat["key"]))
        self.groups = [(g["key"], tuple(g["prefixes"])) for g in doc["groups"]]

    def categories(self, cls: str) -> list[str]:
        """命中该类的品类（可能多个：一个类可以同时算两类敏感面）。"""
        hits = list(self.exact.get(cls, []))
        for value, cat in self.prefix:
            if cls.startswith(value) and cat not in hits:
                hits.append(cat)
        return hits

    def group(self, cls: str) -> str:
        for key, prefixes in self.groups:
            if cls.startswith(prefixes):
                return key
        return "other"

    def accepts(self, cls: str, method: str) -> bool:
        """方法是否在作用域内：只有登记了方法白名单的类会被方法级过滤。"""
        allow = self.allowlists.get(cls)
        return allow is None or method in allow


def describe(doc: dict) -> dict:
    """报告用摘要：目标集身份 + 来源 + 边界，字段名与目标集保持一致。"""
    return {
        "target_set_id": doc["target_set_id"],
        "version": doc["version"],
        "sha256": doc["sha256"],
        "generated_at": doc["generated_at"],
        "generated_by": doc["generated_by"],
        "path": doc["_path"],
        "categories": [{"key": c["key"], "zh": c["zh"],
                        "entries": len(c["entries"])} for c in doc["categories"]],
        "signature_source": doc["scope_rule"]["signature_source"],
    }
