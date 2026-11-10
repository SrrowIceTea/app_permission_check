#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""入站响应侧的**事实记录**：只写"响应包含某某"，不升级任何结论。仅用于授权测试。

出站请求体匹配到隐私值才走外发关联（30 秒窗口）。响应体里出现同样的值只说明
服务端回传了它，**不能**证明 App 外发了它，也不能提升结论级别。本模块的返回值
固定 `used_for_egress=False`，下游评估不得把它当外发证据。

本工具仍然不输出 `policy_violation`。
"""
from __future__ import annotations

import hashlib

OBSERVATION_ONLY = "observation_only"


def _token_digest(tokens: list[str]):
    if not tokens:
        return None
    return hashlib.sha256("\n".join(sorted(tokens)).encode("utf-8")).hexdigest()


def observe_response(parse: dict | None, tags=None, tokens=None, payload=None) -> dict:
    """构造响应侧观测块。没有响应时 `observed=False`，与"响应为空"区分。"""
    parse = parse or {}
    tags = sorted(set(tags or ()))
    tokens = sorted(set(tokens or ()))
    observed = payload is not None or (
        bool(parse) and parse.get("unparsed_reason") != "no_response_body")
    return {
        "direction": parse.get("direction") or "inbound",
        "observed": observed,
        "parse_status": parse.get("parse_status"),
        "contains_sensitive": bool(tags or tokens),
        "labels": tags,
        "token_count": len(tokens),
        "token_sha256": _token_digest(tokens),
        # 这三项是硬边界：响应侧命中只作事实保留，不参与外发判定。
        "evidence_level": OBSERVATION_ONLY,
        "used_for_egress": False,
        "conclusion": None,
    }
