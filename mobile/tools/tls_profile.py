#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""TLS 事件画像：回答"keylog 为什么是 0"。

仅用于授权测试（已获授权的样本与设备）。

**为什么需要**：`http-stats.json` 的 `error` 一直写"keylog 未装上"，而实测有三种完全
不同的情形都表现为 `keylog_lines=0`，混在一起会把排查方向带偏：

| 情形 | 证据 | 真实含义 | 能修吗 |
|---|---|---|---|
| `no_tls_in_window` | 无握手、无 SSL_*_PLAINTEXT | 窗口内没跑 TLS（应用未联网/没被驱动到） | 不是 keylog 的问题，改 UI 触发 |
| `reused_session` | 有 SSL_*_PLAINTEXT 但无 `SSL_new` | 会话在**钩子装上之前**就建好了，窗口内全是复用 | attach 模式的结构性限制；只有 spawn 能解 |
| `callback_not_fired` | 有 `TLS_HANDSHAKE` 但无 `TLS_KEYLOG` | 回调装了却没被调用（被覆盖/该副本关闭 keylog） | 真 bug，查 `KEYLOG_SETTER_CALLED` |

结论来自 2026-10-20 三次单样本实测（openmensa ×2、towercollector ×1）。
"""
from __future__ import annotations

import json
from pathlib import Path

_HANDSHAKE = ("TLS_HANDSHAKE",)
_KEYLOG = ("TLS_KEYLOG",)
_PLAIN = ("SSL_WRITE_PLAINTEXT", "SSL_READ_PLAINTEXT")
_STAMP = ("KEYLOG_INSTALLED", "KEYLOG_SETTER_CALLED", "TLS_SNI", "KEYLOG_UNAVAILABLE")


def _count_events(session: Path) -> dict:
    counts: dict[str, int] = {}
    if not session.exists():
        return counts
    for path in session.glob("*.jsonl"):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for line in text.split("\n"):
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line).get("ev")
            except json.JSONDecodeError:
                continue
            if ev:
                counts[ev] = counts.get(ev, 0) + 1
    return counts


def profile(session: Path) -> dict:
    """统计与 TLS 有关的事件，给出可判定的结论（见模块说明的三分法）。"""
    c = _count_events(session)
    handshakes = sum(c.get(k, 0) for k in _HANDSHAKE)
    plain = sum(c.get(k, 0) for k in _PLAIN)
    keylogs = sum(c.get(k, 0) for k in _KEYLOG)
    installed = c.get("KEYLOG_INSTALLED", 0)
    verifier = c.get("KEYLOG_SETTER_CALLED", 0)
    sni = c.get("TLS_SNI", 0)
    if keylogs:
        verdict = "ok"
    elif handshakes:
        verdict = "callback_not_fired"
    elif plain and installed:
        verdict = "reused_session"
    elif plain:
        verdict = "reused_session"
    else:
        verdict = "no_tls_in_window"
    return {"handshakes": handshakes, "ssl_plaintext_events": plain,
            "tls_keylog": keylogs, "keylog_installed": installed,
            "setter_calls": verifier, "sni": sni, "verdict": verdict}


_WHY = {
    "ok": "已取得 keylog，pcap 可解密。",
    "no_tls_in_window": "窗口内没有 TLS 握手，也没有内存 Hook 明文：应用没被驱动到联网界面。"
                        "keylog 无输入，不是采集链故障。",
    # 同一 verdict 的第二种情况：pcap 里明明有 TLS 帧，但钩子一次 SSL_* 都没看到。
    # 典型是 WebView/Chromium（静态链接 BoringSSL，不导出 SSL_* 符号）——
    # 这是 keylog 与 native 明文两条旁路共同的边界，实测 03 geoportail（409 帧）。
    "other_tls_stack": "pcap 里有 TLS 流量，但钩子没看到任何 SSL_* 调用：这些 TLS 不走"
                       " libjavacrypto 的导出符号（WebView/Chromium 静态 BoringSSL 是典型）。"
                       "keylog 与 native 明文两条旁路对此类栈都不适用，只能靠代理侧解密。",
    "reused_session": "窗口内有 TLS 应用数据，但没有任何 SSL_new —— 会话在钩子装上之前"
                      "就建好了，窗口内全是复用连接，keylog 回调无处可挂。"
                      "这是 attach 模式的结构性限制（spawn 不可用时的已知边界）。",
    "callback_not_fired": "有握手、回调也装过，但从未被调用：查 KEYLOG_SETTER_CALLED "
                          "（是否被设成 NULL）与该模块是否关闭了 keylog。",
}


def explain(prof: dict, undecrypted: int) -> str:
    """替掉 pcap_http 那句笼统的"keylog 未装上"。"""
    why_key = prof["verdict"]
    # 没有 TLS 事件的两种情形，靠 pcap 有没有加密帧区分——否则会把"钩子够不着"
    # 误写成"应用没联网"，那是把工具盲区说成样本行为。
    if why_key == "no_tls_in_window" and undecrypted > 0:
        why_key = "other_tls_stack"
    return (f"{undecrypted} 帧 TLS 应用数据未解密；keylog=0 的原因：{_WHY[why_key]}"
            f"（握手 {prof['handshakes']}、SSL_new 回调安装 {prof['keylog_installed']}、"
            f"内存明文 {prof['ssl_plaintext_events']}、SNI {prof['sni']}）")
