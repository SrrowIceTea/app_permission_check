#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""解析结果的公共构造与落盘摘要裁剪。仅用于授权测试。

`parse_body()` 在内存里返回 `fields`（供打标），`parse_summary()` 只留元数据：
**不把字段值再写一份到 flows.jsonl**，否则等于绕过 redaction 复制原文。
二进制可打印串同理——只留计数与摘要，不留原文。
"""
from __future__ import annotations

import hashlib

from core.collector.parse_registry import confidence

_MISSING = object()


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _with_fields(dataset: dict, fields: list, **extra) -> dict:
    """回填 `field_count` / `field_paths_sha256`：只填 fields 不重算会让报告出现
    “已解析但 0 个字段”。"""
    paths = sorted(field["path"] for field in fields)
    if "parser" in extra:
        extra["parser_confidence"] = confidence(extra["parser"])
    return {**dataset, "fields": fields, "field_count": len(fields),
            "field_paths_sha256": _sha("\n".join(paths).encode("utf-8")) if paths else None,
            **extra}


def named(dataset: dict, parser: str, **extra) -> dict:
    """换 parser 时必须同步换置信度，避免沿用上一步的 confirmed。"""
    return {**dataset, "parser": parser, "parser_confidence": confidence(parser), **extra}


def _result(raw, content_type, parser, status, fields=None, reason=None,
            heuristic=False, gaps=None, payload_sha=_MISSING,
            content_encoding=None) -> dict:
    fields = fields or []
    paths = sorted(field["path"] for field in fields)
    result = {
        "parser": parser,
        "parser_confidence": confidence(parser),
        "parse_status": status,
        "content_type": content_type,
        "bytes": len(raw),
        "truncated": False,
        "decode_error": False,
        "field_count": len(fields),
        "field_paths_sha256": _sha("\n".join(paths).encode("utf-8")) if paths else None,
        "unparsed_reason": reason,
        "payload_sha256": _sha(raw) if payload_sha is _MISSING else payload_sha,
        "heuristic": heuristic,
        "coverage_gaps": sorted(set(gaps or ())),
        "fields": fields,
    }
    # 只在声明存在时出现：老封存样本没有该键，重放摘要必须逐字不变。
    if content_encoding:
        result["content_encoding"] = content_encoding
    return result


def parse_summary(parsed: dict) -> dict:
    """落盘用：去掉字段值与二进制可打印串，只留可复核的元数据。"""
    result = {key: value for key, value in parsed.items() if key != "fields"}
    probe = result.get("binary_probe")
    if isinstance(probe, dict):
        result["binary_probe"] = {key: value for key, value in probe.items()
                                  if key != "printable_strings"}
    return result
