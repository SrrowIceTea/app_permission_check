#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WebSocket 帧级建模：每条帧独立解析、独立归因、独立留痕。仅用于授权测试。

mitmproxy 在 `websocket_message` 钩子里已能看到帧，但长连接容易被当成"一条流"
整体处理。这里把每帧记成一条 `kind=websocket_frame` 记录：序号、方向、帧类型、
长度、所属连接、`frame_parse`。归因仍按连接 + 包名逐条解析，不因为长连接放弃。

长连接归因不到时**不静默丢弃**：记 `unattributed=True` 后仍交给落盘层，
由 `scope.persist` 决定是否只保留丢弃计数。
"""
from __future__ import annotations

import os
import time
from types import SimpleNamespace

from core.collector import flow_entry
from core.collector.attribution import Attribution
from core.collector.inspection import inspect_body
from core.collector.origin import classify_origin
from core.collector.payloads import capture
from core.collector.redaction import redact_path


def _frame_type(message) -> str:
    return "text" if getattr(message, "is_text", False) else "binary"


def _direction(message) -> str:
    return "client_to_server" if getattr(message, "from_client", False) else "server_to_client"


def frame_record(flow, message, seq: int, ts_ms: int, session: str, found,
                 tag_sensitive, tag_fields) -> dict:
    """一帧一条记录。字段与 HTTP 记录保持同名键，`_emit` 才能复用同一条落盘路径。"""
    req = getattr(flow, "request", None)
    content = bytes(getattr(message, "content", b"") or b"")
    frame_type, direction = _frame_type(message), _direction(message)
    frame = SimpleNamespace(raw_content=content, content=content, headers={})
    _, summary, labels, tokens = inspect_body(
        frame, tag_sensitive, tag_fields, direction=direction, frame_type=frame_type)
    origin = classify_origin(getattr(req, "headers", None), found.package)
    return {
        "v": "1",
        "src": "proxy",
        "ev": "WS_FRAME",
        "kind": "websocket_frame",
        "session_id": session,
        "evt_id": None,
        "ts": ts_ms,
        "host_received_ts": ts_ms,   # 事件库按它建时序，缺了会落成 NULL
        "connection_id": getattr(flow, "id", None),
        "package": found.package,
        "uid": found.uid,
        "user_id": found.user_id,
        "attribution": found.label,
        "attribution_source": found.source,
        "attribution_delta_ms": found.delta_ms,
        "attribution_ambiguous": found.ambiguous,
        "attribution_runner_up": found.runner_up,
        "attribution_candidates": list(found.candidates),
        "method": "WS",
        "host": getattr(req, "pretty_host", None),
        "path": redact_path(req.path) if req is not None else None,
        "target_host": getattr(req, "host", None),
        "target_port": getattr(req, "port", None),
        "status_code": None,
        "request_origin": origin["origin"],
        "request_origin_signals": origin["signals"],
        "frame_seq": seq,
        "direction": direction,
        "frame_type": frame_type,
        "frame_bytes": len(content),
        "frame_parse": summary,
        "frame_payload": capture(frame),
        # 与 HTTP 记录共用日志/落盘代码，这两个键不能少。
        "request_tags": labels,
        "request_tokens": tokens,
        "response_tags": [],
        "response_tokens": [],
    }


def hook(*, flush, resolve, emit, session, whitelist, tag_sensitive, tag_fields):
    """构造 `websocket_message` 回调。只有**新增**的帧会被落盘。"""
    seen: dict = {}

    def websocket_message(flow) -> None:
        flush()
        data = getattr(flow, "websocket", None)
        messages = list(getattr(data, "messages", ()) or ()) if data is not None else []
        start = seen.get(getattr(flow, "id", None), 0)
        if start >= len(messages):
            return
        ts_ms = int(time.time() * 1000)
        found = getattr(flow, "metadata", {}).get("vscan_found")
        if found is None or not getattr(found, "resolved", False):
            found = resolve(ts_ms, flow_entry.target(flow))
        if (not getattr(found, "resolved", False) and len(whitelist) == 1
                and os.environ.get("VSCAN_STRICT_PACKAGE_SCOPE") != "1"):
            found = Attribution(package=next(iter(whitelist)), delta_ms=None,
                                source="single_package_fallback")
        for index in range(start, len(messages)):
            record = frame_record(flow, messages[index], index + 1, ts_ms, session,
                                  found, tag_sensitive, tag_fields)
            if found.package not in whitelist:
                record["unattributed"] = True
            emit(record)
        seen[getattr(flow, "id", None)] = len(messages)

    return websocket_message
