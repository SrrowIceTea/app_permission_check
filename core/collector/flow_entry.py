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
from core.collector.parse import parse_body, parse_summary  # noqa: E402
from core.collector.origin import classify_origin  # noqa: E402
from core.collector.payloads import capture  # noqa: E402
from core.collector.redaction import redact_path  # noqa: E402
from core.collector.response_observation import observe_response  # noqa: E402
from core.collector.upstream_failures import classify_upstream_failure  # noqa: E402


def refresh_identity(entry, found):
    """Update ALL attribution fields together, including delayed collector retries."""
    entry.update(package=found.package, uid=found.uid, user_id=found.user_id,
        attribution=found.label, attribution_source=found.source,
        attribution_delta_ms=found.delta_ms, attribution_ambiguous=found.ambiguous,
        attribution_runner_up=found.runner_up, attribution_candidates=list(found.candidates))


def target(flow):
    """Use the actual proxy mode, never infer reverse mode from a custom Host.

    Reverse rewrites the network destination to its upstream: only there use the
    preserved Host, without the upstream peer IP. Regular uses the URL/peer.
    """
    req = flow.request
    addressed, raw_host = getattr(req, 'pretty_host', None), getattr(req, 'host', None)
    peer = getattr(flow, 'server_conn', None)
    address = getattr(peer, 'peername', None)
    mode = getattr(getattr(flow, 'client_conn', None), 'proxy_mode', None)
    reverse = getattr(mode, 'type_name', None) == 'reverse'
    return {'host': (addressed or raw_host) if reverse else (raw_host or addressed),
            'ip': address[0] if address and not reverse else None}


def recorded_target(entry):
    """Use the same anchor in delayed retries as in the original callback."""
    saved = entry.get('attribution_target')
    if isinstance(saved, dict):
        return saved
    # A legacy/minimal record has no mode; do not guess from its Host or peer IP.
    return {'host': entry.get('target_host') or entry.get('host'), 'ip': None}

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
    """
    req = flow.request
    request_payload = capture(req)
    origin = classify_origin(getattr(req, "headers", None), found.package)
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
        # 取证用：另存**原始** host 与 port（reverse 模式下 host 是上游地址）。
        # 目标校验锚定的是上面的 `host`（pretty_host），见 target() 与 D417。
        # 用 getattr：测试/假 flow 的最小报文可能只有 pretty_host 而没有 host/port。
        "target_host": getattr(req, "host", None),
        "target_port": getattr(req, "port", None),
        "attribution_target": target(flow),
        "server_ip": (flow.server_conn.peername or (None,))[0],
        "path": redact_path(req.path),
        "intercepted_tls": client_tls(flow),
        # 来源类别只到 webview/native/unknown 这一层，不假装能归因到具体 JS。
        "request_origin": origin["origin"],
        "request_origin_signals": origin["signals"],
        "request_payload": request_payload,
        "request_preview": request_payload["text"][:400],
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


def parse_side(message, direction: str = "outbound") -> dict:
    """请求与响应各记一次，`direction` 明示这是出站还是入站正文。"""
    return {**parse_summary(parse_body(message)), "scan_basis": "not_scanned",
            "direction": direction}


def parsing(flow, parses: dict | None = None) -> dict:
    """两个构造器共用：请求/响应都带 parser + parse_status，缺一不可。"""
    if parses is not None:
        return {key: parses[key] for key in ("request_parse", "response_parse")}
    return {"request_parse": parse_side(flow.request, "outbound"),
            "response_parse": parse_side(getattr(flow, "response", None), "inbound")}


def answered(flow, found, ts_ms: int, session: str, tags: dict, scans: dict,
             parses: dict | None = None) -> dict:
    """一次**拿到了响应**的外发。"""
    req, resp = flow.request, flow.response
    response_payload = capture(resp)
    entry = _common(flow, found, ts_ms, session)
    entry.update({
        "status_code": resp.status_code if resp else None,
        "request_tags": tags["request_tags"],
        "request_tokens": tags["request_tokens"],
        "response_tags": tags["response_tags"],
        "response_tokens": tags["response_tokens"],
        "request_bytes": len(req.raw_content or b""),
        "response_bytes": len(resp.raw_content or b"") if resp else 0,
        "response_payload": response_payload,
        "response_preview": response_payload["text"][:200],
        # 扫描状态：**"没打上标签"与"内容没被完整看过"必须能分开**。
        # truncated=true 时标签为空只说明"已扫的部分没有"，不代表整条报文不含敏感字段。
        "request_scan": scans["request_scan"],
        "response_scan": scans["response_scan"],
        # 解析状态：multipart/protobuf/二进制解析不出来时这里必须留痕，
        # 不能只留下空标签让人误读成"没有敏感字段"。
        **parsing(flow, parses),
    })
    # 入站响应命中隐私值只作事实记录：不参与外发判定、不升级结论、不输出 policy_violation。
    entry["response_observation"] = observe_response(
        entry["response_parse"], entry["response_tags"], entry["response_tokens"],
        response_payload)
    return entry


def unanswered(flow, found, ts_ms: int, session: str, failure: str,
               failure_kind: str | None = None,
               connect_ms: int | None = None,
               parses: dict | None = None) -> dict:
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
    kind = failure_kind or classify_upstream_failure(failure, connect_ms)
    entry.update({
        "terminal": "error",   # addon._emit 按它选文件；成功记录不带这个键
        "status_code": None,
        "failure": kind,
        "failure_kind": kind,
        "connect_ms": connect_ms,
        "request_tags": [], "request_tokens": [],
        "response_tags": [], "response_tokens": [],
        "request_scan": None, "response_scan": None,
        "request_bytes": len(flow.request.raw_content or b""),
        "response_bytes": 0,
        "response_payload": None,
        "response_preview": "",
        # 失败流同样要能回答"请求体是什么格式、解析出来没有"。
        **parsing(flow, parses),
    })
    entry["response_observation"] = observe_response(
        entry["response_parse"], [], [], None)
    return entry
