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


def refresh_identity(entry, found):
    """Update ALL attribution fields together, including delayed collector retries."""
    entry.update(package=found.package, uid=found.uid, user_id=found.user_id,
        attribution=found.label, attribution_source=found.source,
        attribution_delta_ms=found.delta_ms, attribution_ambiguous=found.ambiguous,
        attribution_runner_up=found.runner_up, attribution_candidates=list(found.candidates))


def target(flow):
    peer = getattr(flow, 'server_conn', None)
    address = getattr(peer, 'peername', None)
    return {'host': getattr(flow.request, 'host', None), 'ip': address[0] if address else None}

# **系统自身的连通性探测**（2026-10-19 实测）：每次联网 Android 自己都会打
# `connectivitycheck.gstatic.com/generate_204`，跟被测应用毫无关系。它走明文 HTTP，
# 所以 `ignore_hosts`（只管 TLS 拦截）拦不住，会落进 unattributed 通道。
# 后果不小：那条通道的语义是"应用**可能**外发了、只是钩子没覆盖"，下游据此
# **禁止**写「应用未外发」。一条系统探测就能让这个结论永远写不出来——01 号样本
# （有 INTERNET 权限、真零外发）当场踩到了。
# 按「主机 + 路径」精确认：只认这些固定探测路径，不按域名一刀切
# （`www.google.com` 也可能被应用当普通站点访问）。
#
# 放在这里而不是 `addon.py`：addon 导入时要求 `VSCAN_PACKAGES`，带副作用的模块
# 没法单测；这是纯判据，归 `flow_entry`（只管"记录长什么样"）。
SYSTEM_PROBE_PATHS = {
    "connectivitycheck.gstatic.com": {"/generate_204", "/gen_204"},
    "clients3.google.com": {"/generate_204", "/gen_204"},
    "connectivitycheck.android.com": {"/generate_204", "/gen_204"},
    "www.google.com": {"/gen_204"},
}


def is_system_probe(entry: dict) -> bool:
    """这条流是不是操作系统自己的联网探测（而非被测应用的外发）。"""
    host = str(entry.get("host") or "").lower()
    return str(entry.get("path") or "") in SYSTEM_PROBE_PATHS.get(host, ())


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
        "uid": found.uid,
        "user_id": found.user_id,
        "attribution": found.label,
        "attribution_source": found.source,
        "attribution_delta_ms": found.delta_ms,
        "attribution_ambiguous": found.ambiguous,
        "attribution_runner_up": found.runner_up,
        "attribution_candidates": list(found.candidates),
        "scheme": req.scheme,
        "method": req.method,
        "host": req.pretty_host,
        # 目标地址（供目标校验 / 取证）。`host` 保留 pretty_host 不变（对外证据契约），
        # 这里另存**原始** host 与 port：与 hook 侧的 getHostString()/getAddress() 口径一致。
        # 用 getattr：测试/假 flow 的最小报文可能只有 pretty_host 而没有 host/port。
        "target_host": getattr(req, "host", None),
        "target_port": getattr(req, "port", None),
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


def unanswered(flow, found, ts_ms: int, session: str, failure: str,
               failure_kind: str | None = None,
               connect_ms: int | None = None) -> dict:
    """一次**没拿到响应**的尝试（上游连接失败 / 超时 / 协议错误）。

    `request_tokens` / `response_tags` 一律为空：`vehicle/analyze/evaluation.py` 的外发判定
    **不看 `status_code`**，只要 tokens 里有属性名就会生成 `content_match=True` 的
    外发结论——那等于把一次失败的上传写成了"确实发出了这个数据"。

    `failure_kind`（2026-10-19 新增）把原始的 `failure` 字符串**归成类别**。原因：
    实测「上游黑洞 + 客户端等不住先断」时 mitmproxy 报的是 `client disconnected`，
    与"客户端自己取消"字面完全相同；不分类就会把"上游不可达"记成"应用主动放弃"，
    报告据此会写"应用没打算外发"。类别见 `addon.classify_upstream_failure`。
    """
    entry = _common(flow, found, ts_ms, session)
    entry.update({
        "terminal": "error",   # addon._emit 按它选文件；成功记录不带这个键
        "status_code": None,
        "failure": failure,
        "failure_kind": failure_kind,
        "connect_ms": connect_ms,
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
