#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""统一报文解析入口：每条报文必须带 `parser` / `parse_status`。仅用于授权测试。

`body.py` 只回答"文本读出来没有、读全没有"，`tagging.py` 只在整段文本上跑正则。
multipart、protobuf、二进制响应、WebSocket 帧解析失败时，空标签与"内容真的
没有敏感字段"长得一模一样——"0 条发现"会被读成"没事"。这里把"没解析"变成**显式
状态**：状态是封闭枚举，失败也返回状态、不抛异常。

落盘约束：`parse_body()` 在内存里返回 `fields`（供打标），`parse_summary()` 只保留
元数据——**不把字段值再写一份到 flows.jsonl**，否则等于绕过 redaction 复制原文。
"""
from __future__ import annotations

from core.collector.media import FORM_MEDIA, is_json_media, is_json_text
from core.collector.parse_binary import binary_probe, protobuf_fields
from core.collector.parse_registry import confidence
from core.collector.parse_result import _result, _sha, _with_fields, named, parse_summary
from core.collector.parse_source import (content_of, full_text, header_of, media_of,
                                         raw_of, text_scan)
from core.collector.parse_text import (FILE_GAP, form_fields, json_fields,
                                       looks_like_form, multipart_fields)
from core.collector.payloads import LIMIT

STATUSES = frozenset({
    "parsed_json", "parsed_form", "parsed_multipart", "parsed_websocket_text",
    "parsed_protobuf_heuristic", "unparsed_binary", "unparsed_websocket_text",
    "unparsed_truncated", "unparsed_decode_error", "unparsed_empty",
    "unparsed_unknown_content_type",
})
PARSED_STATUSES = frozenset(status for status in STATUSES if status.startswith("parsed_"))
MULTIPART_MEDIA = frozenset({"multipart/form-data"})
PROTO_MEDIA = frozenset({"application/x-protobuf", "application/protobuf",
                         "application/grpc"})
BINARY_MEDIA_PREFIX = ("image/", "audio/", "video/", "font/")
MAX_BINARY_PROBE_BYTES = 8 * 1024 * 1024


def _websocket_text(dataset: dict, text: str, media: str):
    """文本帧走 JSON / form 链；都没有结构就落 `unparsed_websocket_text`。"""
    fields = json_fields(text)
    if fields is not None:
        return _with_fields(dataset, fields, parser="websocket_text",
                            parse_status="parsed_websocket_text")
    if media == FORM_MEDIA or looks_like_form(text):
        form = form_fields(text)
        if form:
            return _with_fields(dataset, form, parser="websocket_text",
                                parse_status="parsed_websocket_text")
    return named(dataset, "websocket_text",
                 parse_status="unparsed_websocket_text",
                 unparsed_reason="websocket_text_no_structure")


def _binary_frame(dataset: dict, raw: bytes):
    """二进制帧：结构探测 + 可打印串，但**不**算解析成功。"""
    probe = binary_probe(raw) if len(raw) <= MAX_BINARY_PROBE_BYTES else None
    return named(dataset, "binary_probe", parse_status="unparsed_binary",
                 unparsed_reason="websocket_binary_frame", binary_probe=probe)


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
        # 二进制帧的解码失败是预期行为，不能盖掉"这是二进制帧"的显式状态。
        if frame_type != "binary" and scan.get("decode_error"):
            return {**dataset, "parse_status": "unparsed_decode_error",
                    "unparsed_reason": "decode_failed", "decode_error": True}
        if len(raw) > LIMIT or len(content) > LIMIT:
            return {**dataset, "parse_status": "unparsed_truncated",
                    "unparsed_reason": "body_exceeds_limit", "truncated": True}
        if frame_type == "binary":
            if not raw:
                return {**dataset, "parser": "none", "parse_status": "unparsed_empty",
                        "unparsed_reason": "empty_body", "payload_sha256": _sha(b"")}
            return _binary_frame(dataset, raw)
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
            return _websocket_text(dataset, text, media)
        if is_json_text(media, text):
            fields = json_fields(text)
            if fields is None:
                return named(dataset, "json", parse_status="unparsed_binary",
                             unparsed_reason="json_decode_failed")
            return _with_fields(dataset, fields, parser="json", parse_status="parsed_json")
        if media == FORM_MEDIA:
            fields = form_fields(text)
            if fields is None:
                return named(dataset, "form", parse_status="unparsed_binary",
                             unparsed_reason="form_decode_failed")
            return _with_fields(dataset, fields, parser="form", parse_status="parsed_form")
        if media in MULTIPART_MEDIA:
            fields = multipart_fields(raw, content_type)
            if fields is None:
                return named(dataset, "multipart", parse_status="unparsed_binary",
                             unparsed_reason="multipart_incomplete_or_boundary_missing")
            gaps = [FILE_GAP] if any(field.get("value") is None for field in fields) else []
            return _with_fields(dataset, fields, parser="multipart",
                                parse_status="parsed_multipart", coverage_gaps=gaps)
        if media in PROTO_MEDIA or media in ("application/octet-stream", ""):
            fields = protobuf_fields(raw)
            if fields is not None:
                return _with_fields(dataset, fields, parser="protobuf",
                                    parse_status="parsed_protobuf_heuristic", heuristic=True)
            return named(dataset, "binary_probe",
                         parse_status=("unparsed_unknown_content_type" if not media
                                       else "unparsed_binary"),
                         unparsed_reason=("missing_content_type" if not media
                                          else "no_structured_fields"),
                         binary_probe=binary_probe(raw))
        if media.startswith(BINARY_MEDIA_PREFIX):
            return named(dataset, "binary_probe", parse_status="unparsed_binary",
                         unparsed_reason="binary_without_structured_fields",
                         binary_probe=binary_probe(raw))
        return {**dataset, "parse_status": "unparsed_unknown_content_type",
                "unparsed_reason": "unsupported_content_type"}
    except Exception as exc:  # noqa: BLE001 — 解析失败绝不能把一条流丢掉
        return {**dataset, "parse_status": "unparsed_binary",
                "unparsed_reason": f"parser_error:{type(exc).__name__}"}


__all__ = ["STATUSES", "PARSED_STATUSES", "parse_body", "parse_summary", "confidence"]
