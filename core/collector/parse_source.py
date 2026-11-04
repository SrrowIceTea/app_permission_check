#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""报文读取适配：原始字节 / 解压正文 / 完整文本 / 声明头 / 媒体类型。仅用于授权测试。

`parse.py` 只负责“解析成什么”，这里只负责“从报文里取到什么”。拆开是因为两类错误
完全不同：取不到是采集缺字段，解析不了是协议不支持；把两者混在一个文件里，
"读不到"就会被当成"没有敏感字段"。
"""
from __future__ import annotations

from core.collector.body import MAX_BODY_SCAN, scan_body


def raw_of(message) -> bytes:
    """压缩态原始字节（mitmproxy 的 `raw_content`）；没有就退回解压后的 content。"""
    if message is None:
        return b""
    try:
        raw = getattr(message, "raw_content", None)
    except Exception:  # noqa: BLE001
        raw = None
    if isinstance(raw, (bytes, bytearray)):
        return bytes(raw)
    return content_of(message)


def content_of(message, fallback: bytes = b"") -> bytes:
    """解压后的正文（mitmproxy 的 `content`）；拿不到就用调用方给的退回值。"""
    try:
        content = getattr(message, "content", None)
    except Exception:  # noqa: BLE001
        content = None
    return bytes(content) if isinstance(content, (bytes, bytearray)) else fallback


def full_text(message, raw: bytes):
    """完整正文（不截断）。解析不能拿打标用的 256KB 窗口当解析上限。"""
    get_text = getattr(message, "get_text", None)
    if callable(get_text):
        try:
            value = get_text(strict=False)
        except Exception:  # noqa: BLE001
            return None
        return value if isinstance(value, str) else ""
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return None


def header_of(message, name: str):
    if message is None:
        return None
    try:
        value = message.headers.get(name)
    except Exception:  # noqa: BLE001
        return None
    return str(value) if value is not None else None


def media_of(content_type) -> str:
    return (content_type or "").split(";", 1)[0].strip().lower()


def text_scan(message, raw: bytes) -> tuple[str, dict]:
    """最小假报文可能没有 get_text；此时按原始字节严格解码，失败即记 decode_error。"""
    if not callable(getattr(message, "get_text", None)):
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            return "", {"decode_error": True, "truncated": False}
        return text[:MAX_BODY_SCAN], {
            "decode_error": False, "chars": len(text),
            "truncated": len(text) > MAX_BODY_SCAN,
        }
    try:
        return scan_body(message)
    except Exception:  # noqa: BLE001
        return "", {"decode_error": True, "truncated": False}
