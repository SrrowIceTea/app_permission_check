#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""解析器登记表：每个 parser 必须显式声明 confirmed / heuristic。仅用于授权测试。

`heuristic` 的解析结果（protobuf 猜测、二进制可打印串）**不得**参与
`value_match`——猜测出来的字段不能当"确实发送了这个值"的证据。
"""
from __future__ import annotations

PARSER_CONFIDENCE = {
    "none": "confirmed",
    "json": "confirmed",
    "form": "confirmed",
    "multipart": "confirmed",
    "websocket_text": "confirmed",
    "binary": "confirmed",
    "protobuf": "heuristic",
    "binary_probe": "heuristic",
}


def confidence(parser) -> str:
    """未知 parser 一律按 heuristic 处理：没登记过就不能算确定解析。"""
    return PARSER_CONFIDENCE.get(parser or "none", "heuristic")
