#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""统一报文解析入口：每条报文必须带 `parser` / `parse_status`。仅用于授权测试。

`body.py` 只回答"文本读出来没有、读全没有"，`tagging.py` 只在整段文本上跑正则。
multipart、protobuf、二进制响应、WebSocket 文本帧解析失败时，空标签与"内容真的
没有敏感字段"长得一模一样——"0 条发现"会被读成"没事"。这里把"没解析"变成**显式
状态**：状态是封闭枚举，失败也返回状态、不抛异常。

落盘约束：`parse_body()` 在内存里返回 `fields`（供打标），`parse_summary()` 只保留
元数据——**不把字段值再写一份到 flows.jsonl**，否则等于绕过 redaction 复制原文。
"""
from __future__ import annotations

import hashlib
import json
import re
from urllib.parse import parse_qsl

from core.collector.media import FORM_MEDIA, is_json_media, is_json_text
from core.collector.parse_binary import protobuf_fields
from core.collector.parse_source import (content_of, full_text, header_of, media_of,
                                         raw_of, text_scan)
from core.collector.payloads import LIMIT

STATUSES = frozenset({
    "parsed_json", "parsed_form", "parsed_multipart", "parsed_websocket_text",
    "parsed_protobuf_heuristic", "unparsed_binary", "unparsed_truncated",
    "unparsed_decode_error", "unparsed_empty", "unparsed_unknown_content_type",
})
PARSED_STATUSES = frozenset(status for status in STATUSES if status.startswith("parsed_"))
MULTIPART_MEDIA = frozenset({"multipart/form-data"})
PROTO_MEDIA = frozenset({"application/x-protobuf", "application/protobuf",
                         "application/grpc"})
MAX_FIELDS = 4096
BAD_PERCENT = re.compile(r"%(?![0-9a-fA-F]{2})")
FILE_GAP = "multipart_file_bodies_uninspected"
_MISSING = object()


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _with_fields(dataset: dict, fields: list, **extra) -> dict:
    """回填 `field_count` / `field_paths_sha256`：只填 fields 不重算会让报告出现
    “已解析但 0 个字段”。"""
    paths = sorted(field["path"] for field in fields)
    return {**dataset, "fields": fields, "field_count": len(fields),
            "field_paths_sha256": _sha("\n".join(paths).encode("utf-8")) if paths else None,
            **extra}


def _leaf_fields(value, path: str, out: list[dict]) -> None:
    if len(out) >= MAX_FIELDS:
        return
    if isinstance(value, dict):
        for key, item in value.items():
            _leaf_fields(item, f"{path}.{key}" if path else str(key), out)
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _leaf_fields(item, f"{path}[{index}]", out)
        return
    if value is None:
        text = "null"
    elif isinstance(value, bool):
        text = "true" if value else "false"
    else:
        text = str(value)
    out.append({"path": path or "$", "value": text})


def _json_fields(text: str):
    try:
        parsed = json.loads(text)
    except (ValueError, TypeError):
        return None
    fields: list[dict] = []
    _leaf_fields(parsed, "", fields)
    return fields


def _form_fields(text: str):
    if BAD_PERCENT.search(text):
        return None
    return [{"path": key or "$", "value": value}
            for key, value in parse_qsl(text, keep_blank_values=True)]


def _multipart_fields(raw: bytes, content_type: str):
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


def _websocket_fields(text: str) -> list[dict]:
    return _json_fields(text) or [{"path": "frame", "value": text[:4096]}]


def _result(raw, content_type, parser, status, fields=None, reason=None,
            heuristic=False, gaps=None, payload_sha=_MISSING,
            content_encoding=None) -> dict:
    fields = fields or []
    paths = sorted(field["path"] for field in fields)
    result = {
        "parser": parser,
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
    """落盘用：去掉字段值，只留可复核的元数据（避免复制原文）。"""
    return {key: value for key, value in parsed.items() if key != "fields"}


def parse_body(message, frame_type: str | None = None,
               content_type: str | None = None,
               content_encoding: str | None = None) -> dict:
    """唯一解析入口。任何失败都返回状态，**不抛异常**。

    `frame_type` 只能由**可信的帧来源**显式传入；请求头里的标记不可信，不能凭它
    把普通 HTTP 报文当 WebSocket 文本帧。

    `content_type` / `content_encoding` 是**离线重放**用的兜底：封存 payload 带声明
    时直接复用；报文自身有同名头时以头为准（实时采集路径逐字不变）。两者都没有
    就继续按旧逻辑嗅探，失败时记 `missing_content_type`——不因缺字段报错。
    """
    raw = raw_of(message)
    content = content_of(message, raw)
    declared = header_of(message, "content-type")
    if not declared and isinstance(content_type, str) and content_type.strip():
        declared = content_type
    declared_encoding = header_of(message, "content-encoding")
    if not declared_encoding and isinstance(content_encoding, str) and content_encoding.strip():
        declared_encoding = content_encoding
    content_type = declared
    if message is None:
        return _result(b"", None, "none", "unparsed_empty", reason="no_response_body",
                       payload_sha=None, content_encoding=declared_encoding)
    try:
        text, scan = text_scan(message, raw)
    except Exception:  # noqa: BLE001
        text, scan = "", {"decode_error": True, "truncated": False}
    media = media_of(content_type)
    dataset = _result(raw, content_type, "binary", "unparsed_binary",
                      content_encoding=declared_encoding)
    dataset.update(truncated=False,
                   decode_error=bool(scan.get("decode_error")))
    try:
        if scan.get("decode_error"):
            return {**dataset, "parse_status": "unparsed_decode_error",
                    "unparsed_reason": "decode_failed", "decode_error": True}
        if len(raw) > LIMIT or len(content) > LIMIT:
            return {**dataset, "parse_status": "unparsed_truncated",
                    "unparsed_reason": "body_exceeds_limit", "truncated": True}
        if not text and not raw:
            return {**dataset, "parser": "none", "parse_status": "unparsed_empty",
                    "unparsed_reason": "empty_body", "payload_sha256": _sha(b"")}
        if is_json_media(media) or media == FORM_MEDIA or not media:
            try:
                content.decode("utf-8")
            except UnicodeDecodeError:
                return {**dataset, "parse_status": "unparsed_decode_error",
                        "unparsed_reason": "invalid_utf8", "decode_error": True}
        full = full_text(message, raw)
        if full is None:
            return {**dataset, "parse_status": "unparsed_decode_error",
                    "unparsed_reason": "invalid_utf8", "decode_error": True}
        text = full
        # 打标窗口只有 256KB；解析用完整正文，窗口截断只记 `scan_truncated`，
        # 不能反过来把“解析截断”写进 parse_status。
        if scan.get("truncated"):
            dataset["scan_truncated"] = True
        if frame_type == "text":
            return _with_fields(dataset, _websocket_fields(text), parser="websocket_text",
                                parse_status="parsed_websocket_text")
        if frame_type == "binary":
            return {**dataset, "parse_status": "unparsed_binary",
                    "unparsed_reason": "websocket_binary_frame"}
        if is_json_text(media, text):
            fields = _json_fields(text)
            if fields is None:
                return {**dataset, "parser": "json", "parse_status": "unparsed_binary",
                        "unparsed_reason": "json_decode_failed"}
            return _with_fields(dataset, fields, parser="json", parse_status="parsed_json")
        if media == FORM_MEDIA:
            fields = _form_fields(text)
            if fields is None:
                return {**dataset, "parser": "form", "parse_status": "unparsed_binary",
                        "unparsed_reason": "form_decode_failed"}
            return _with_fields(dataset, fields, parser="form", parse_status="parsed_form")
        if media in MULTIPART_MEDIA:
            fields = _multipart_fields(raw, content_type)
            if fields is None:
                return {**dataset, "parser": "multipart",
                        "parse_status": "unparsed_binary",
                        "unparsed_reason": "multipart_incomplete_or_boundary_missing"}
            gaps = [FILE_GAP] if any(field.get("value") is None for field in fields) else []
            return _with_fields(dataset, fields, parser="multipart",
                                parse_status="parsed_multipart", coverage_gaps=gaps)
        if media in PROTO_MEDIA or media in ("application/octet-stream", ""):
            fields = protobuf_fields(raw)
            if fields is not None:
                return _with_fields(dataset, fields, parser="protobuf",
                                    parse_status="parsed_protobuf_heuristic", heuristic=True)
            return {**dataset, "parser": "binary",
                    "parse_status": ("unparsed_unknown_content_type" if not media
                                     else "unparsed_binary"),
                    "unparsed_reason": ("missing_content_type" if not media
                                        else "no_structured_fields")}
        return {**dataset, "parse_status": "unparsed_unknown_content_type",
                "unparsed_reason": "unsupported_content_type"}
    except Exception as exc:  # noqa: BLE001 — 解析失败绝不能把一条流丢掉
        return {**dataset, "parse_status": "unparsed_binary",
                "unparsed_reason": f"parser_error:{type(exc).__name__}"}
