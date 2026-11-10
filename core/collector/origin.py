#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""请求来源判定：WebView 页面内 JS vs App 原生代码。仅用于授权测试。

**只做到"来源类别"这一层**：不假装能归因到具体 JS 函数或脚本文件。
信号不足时返回 `unknown`——猜错来源比没有来源更糟，它会让报告把
WebView 的请求写成 App 原生外发。

判据只用报文里可复核的头部（UA / X-Requested-With / Referer / Sec-Fetch）。
"""
from __future__ import annotations

import re

WEBVIEW_UA = re.compile(r"(?:^|[;(\s])wv(?:[;)\s]|$)", re.I)
NATIVE_UA = re.compile(
    r"\b(okhttp|dart|dalvik|flutter|libcurl|ktor|cronet|java/|python-requests)\b", re.I)
WEBVIEW, NATIVE, UNKNOWN = "webview", "native", "unknown"
# 单一弱信号不足以定性：至少两个弱信号，或一个强信号（UA 特征给 2 分）。
CONFIDENT_SCORE = 2


def _header(headers, name: str) -> str:
    if headers is None:
        return ""
    try:
        value = headers.get(name)
    except Exception:  # noqa: BLE001
        value = None
    if value is None:
        try:
            items = headers.items()
        except Exception:  # noqa: BLE001
            return ""
        value = next((item for key, item in items if str(key).lower() == name), None)
    return str(value) if value is not None else ""


def classify_origin(headers, package=None) -> dict:
    """返回 `{origin, signals, scores}`；`origin` 只取 webview/native/unknown。"""
    signals: list[str] = []
    web = native = 0
    user_agent = _header(headers, "user-agent")
    if WEBVIEW_UA.search(user_agent):
        signals.append("ua_wv")
        web += 2
    if NATIVE_UA.search(user_agent):
        signals.append("ua_native_client")
        native += 2
    requested_with = _header(headers, "x-requested-with").strip()
    if package and requested_with.lower() == str(package).lower():
        signals.append("xrw_package")
        web += 1
    if requested_with.lower() == "xmlhttprequest":
        signals.append("xrw_xmlhttprequest")
        web += 1
    if _header(headers, "sec-fetch-mode"):
        signals.append("sec_fetch")
        web += 1
    if _header(headers, "referer").lower().startswith(("http://", "https://")):
        signals.append("referer_http")
        web += 1
    if "text/html" in _header(headers, "accept").lower():
        signals.append("accept_html")
        web += 1
    if web >= CONFIDENT_SCORE and native == 0:
        origin = WEBVIEW
    elif native >= CONFIDENT_SCORE and web == 0:
        origin = NATIVE
    else:
        origin = UNKNOWN
    return {"origin": origin, "signals": signals,
            "scores": {"webview": web, "native": native}}
