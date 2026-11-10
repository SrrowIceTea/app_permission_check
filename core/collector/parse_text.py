#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""文本报文的字段提取：JSON / form / multipart。仅用于授权测试。

从 `parse.py` 拆出（保持单文件 ≤300 行）。这里只回答"文本能拆出哪些字段"，
不决定 `parse_status`——状态与分派留在 `parse.py`。
"""
from __future__ import annotations

import json
import re
from urllib.parse import parse_qsl

from core.collector.parse_result import _sha

MAX_FIELDS = 4096
BAD_PERCENT = re.compile(r"%(?![0-9a-fA-F]{2})")
FORM_PAIR = re.compile(r"^[\w%.\-]+=")
FILE_GAP = "multipart_file_bodies_uninspected"


def leaf_fields(value, path: str, out: list[dict]) -> None:
    if len(out) >= MAX_FIELDS:
        return
    if isinstance(value, dict):
        for key, item in value.items():
            leaf_fields(item, f"{path}.{key}" if path else str(key), out)
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            leaf_fields(item, f"{path}[{index}]", out)
        return
    if value is None:
        text = "null"
    elif isinstance(value, bool):
        text = "true" if value else "false"
    else:
        text = str(value)
    out.append({"path": path or "$", "value": text})


def json_fields(text: str):
    try:
        parsed = json.loads(text)
    except (ValueError, TypeError):
        return None
    fields: list[dict] = []
    leaf_fields(parsed, "", fields)
    return fields


def form_fields(text: str):
    if BAD_PERCENT.search(text):
        return None
    return [{"path": key or "$", "value": value}
            for key, value in parse_qsl(text, keep_blank_values=True)]


def looks_like_form(text: str) -> bool:
    """无 Content-Type 的 WebSocket 文本帧专用嗅探。

    负控：`notice`（无 `=`）、`a=%1`（百分号非法）、base64 的 `abc=`
    （键有值空）都不算表单，留给 `unparsed_websocket_text`。
    """
    if not text or BAD_PERCENT.search(text) or re.search(r"\s", text):
        return False
    pairs = [pair for pair in text.split("&") if pair]
    return bool(pairs) and all(FORM_PAIR.match(pair) for pair in pairs) and any(
        pair.split("=", 1)[1] for pair in pairs)


def multipart_fields(raw: bytes, content_type: str):
    match = re.search(r'boundary="?([^";]+)"?', content_type or "", re.I)
    if not match:
        return None
    boundary = b"--" + match.group(1).encode("utf-8", "replace")
    if not raw.rstrip(b"\r\n").endswith(boundary + b"--"):
        return None
    fields: list[dict] = []
    for chunk in raw.split(boundary):
        chunk = chunk.strip(b"\r\n")
        if not chunk or chunk == b"--" or len(fields) >= MAX_FIELDS:
            continue
        head, _, body = chunk.partition(b"\r\n\r\n")
        name = re.search(rb'name="([^"]*)"', head, re.I)
        filename = re.search(rb'filename="([^"]*)"', head, re.I)
        if not name:
            continue
        key = name.group(1).decode("latin-1", "replace")
        if filename:
            # 文件正文不解析、不落内容；只记名字与摘要，报告必须写"正文未覆盖"。
            fields.append({"path": key, "value": None,
                           "filename": filename.group(1).decode("latin-1", "replace"),
                           "size": len(body), "sha256": _sha(body)[:16]})
        else:
            fields.append({"path": key, "value": body.decode("utf-8", "replace")})
    return fields
