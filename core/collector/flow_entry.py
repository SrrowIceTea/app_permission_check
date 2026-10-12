#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""V-Scanner Phase 4 — 把一条流变成要落盘的记录。

仅用于授权测试（自有设备与自有 APK）/ For authorized testing on owned devices and APKs only.

从 `addon.py` 拆出来（2026-09-28，原文超过 300 行上限）。这里只管**记录长什么样**，
不管流的生命周期（挂起、重试、归因、落盘时机）——那部分留在 `addon.py`。

两种记录**必须**长成同一个键集：`addon._emit` 对 `request_tags` / `response_tags` /
`method` / `host` / `path` / `status_code` / `package` / `attribution` 是直接下标访问，
少一个键就会在冲刷线程里抛出来（那里被吞成一条 warn，最难发现的那种失效）。
所以两个构造函数并排放，改一个就看得见另一个。
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from core.collector.body import body_of  # noqa: E402
from core.collector.payloads import capture  # noqa: E402


def _common(flow, found, ts_ms: int, session: str) -> dict:
    """两种记录共有的字段。

    **不在这里放 `terminal`**：只有失败记录才带它，`addon._emit` 据此分流。
    成功记录保持原样，`flows.jsonl` 的字段集与加固前逐字一致——它是对外证据契约，
    "字段看起来没坏"不等于下游没人在按固定形状解析。
    """
    req = flow.request
    return {
        "v": "1",
        "src": "proxy",
        "session_id": session,
        "evt_id": None,          # 由 _emit 分配
        "ts": ts_ms,
        "package": found.package,
        "attribution": found.label,
        "attribution_source": found.source,
        "attribution_delta_ms": found.delta_ms,
        "attribution_ambiguous": found.ambiguous,
        "attribution_runner_up": found.runner_up,
        "scheme": req.scheme,
        "method": req.method,
        "host": req.pretty_host,
        "server_ip": (flow.server_conn.peername or (None,))[0],
        "path": req.path,
        "intercepted_tls": client_tls(flow),
        "request_preview": body_of(req)[:400],
    }


def client_tls(flow) -> bool:
    """客户端连接本身有没有握手。

    反向模式下 `req.scheme` 是**上游**协议，不是客户端侧——直接用它会把
    "客户端走了 TLS、上游是明文"记成 tls=False，把成功拦截误报成没拦截。
    """
    for attr in ("tls_established", "tls_version"):
        try:
            return bool(getattr(flow.client_conn, attr))
        except AttributeError:
            continue
    return False


def answered(flow, found, ts_ms: int, session: str, tags: dict, scans: dict) -> dict:
    """一次**拿到了响应**的外发。"""
    req, resp = flow.request, flow.response
    entry = _common(flow, found, ts_ms, session)
    entry.update({
        "status_code": resp.status_code if resp else None,
        "request_tags": tags["request_tags"],
        "request_tokens": tags["request_tokens"],
        "response_tags": tags["response_tags"],
        "response_tokens": tags["response_tokens"],
        "request_bytes": len(req.raw_content or b""),
        "response_bytes": len(resp.raw_content or b"") if resp else 0,
        "request_payload": capture(req),
        "response_payload": capture(resp),
        "response_preview": body_of(resp)[:200] if resp else "",
        # 扫描状态：**"没打上标签"与"内容没被完整看过"必须能分开**。
        # truncated=true 时标签为空只说明"已扫的部分没有"，不代表整条报文不含敏感字段。
        "request_scan": scans["request_scan"],
        "response_scan": scans["response_scan"],
    })
    return entry


def unanswered(flow, found, ts_ms: int, session: str, failure: str) -> dict:
    """一次**没拿到响应**的尝试（上游连接失败 / 超时 / 协议错误）。

    `request_tokens` / `response_tags` 一律为空：`vehicle/analyze/evaluation.py` 的外发判定
    **不看 `status_code`**，只要 tokens 里有属性名就会生成 `content_match=True` 的
    外发结论——那等于把一次失败的上传写成了"确实发出了这个数据"。
    """
    entry = _common(flow, found, ts_ms, session)
    entry.update({
        "terminal": "error",   # addon._emit 按它选文件；成功记录不带这个键
        "status_code": None,
        "failure": failure,
        "request_tags": [], "request_tokens": [],
        "response_tags": [], "response_tokens": [],
        "request_scan": None, "response_scan": None,
        "request_bytes": len(flow.request.raw_content or b""),
        "response_bytes": 0,
        "request_payload": capture(flow.request),
        "response_payload": None,
        "response_preview": "",
    })
    return entry
