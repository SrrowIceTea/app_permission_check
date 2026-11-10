#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""二进制结构探测（从 parse.py 拆出，保持单文件 ≤300 行）。仅用于授权测试。

**只做结构探测与可打印串提取，不做深度反序列化。** 目的不是"解析出内容"，
而是把"采到了、但确实没有可解析结构"变成显式状态（`unparsed_binary` + probe），
避免随机二进制被当成解析成功而制造误判。仅用于授权测试。
"""
from __future__ import annotations

import hashlib
import re

PRINTABLE = re.compile(rb"[\x20-\x7e]{4,}")
SCAN_LIMIT = 64 * 1024
MAX_STRINGS = 32
MAX_STRING_CHARS = 128
MAGIC = (
    (b"\x89PNG\r\n\x1a\n", "png"),
    (b"\xff\xd8\xff", "jpeg"),
    (b"GIF87a", "gif"),
    (b"GIF89a", "gif"),
    (b"%PDF-", "pdf"),
    (b"\x1f\x8b", "gzip"),
    (b"PK\x03\x04", "zip"),
    (b"\x7fELF", "elf"),
    (b"\x00asm", "wasm"),
    (b"RIFF", "riff"),
    (b"fLaC", "flac"),
    (b"OggS", "ogg"),
    (b"\x1a\x45\xdf\xa3", "matroska"),
)


def _varint(buf: bytes, pos: int):
    value = shift = 0
    while pos < len(buf) and shift < 64:
        byte = buf[pos]
        pos += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, pos
        shift += 7
    return None, pos


def protobuf_fields(raw: bytes):
    """返回字段列表；不像 protobuf 时返回 None。

    只做结构猜测：wire type 合法、至少两个字段、至少一个可打印长度字段、字节被完整
    消费，才认为"像 protobuf"。**猜不出就返回 None**，由调用方落成 `unparsed`。
    """
    pos, fields, printable = 0, [], 0
    while pos < len(raw):
        key, pos = _varint(raw, pos)
        if key is None or key >> 3 == 0:
            return None
        number, wire = key >> 3, key & 7
        if wire == 0:
            value, pos = _varint(raw, pos)
            if value is None:
                return None
        elif wire == 1:
            pos += 8
        elif wire == 5:
            pos += 4
        elif wire == 2:
            length, pos = _varint(raw, pos)
            if length is None or length > len(raw) - pos:
                return None
            body, pos = raw[pos:pos + length], pos + length
            if length >= 4 and all(32 <= b < 127 or b in (9, 10, 13) for b in body):
                fields.append({"path": f"field[{number}]",
                               "value": body.decode("utf-8", "replace")})
                printable += 1
        else:
            return None
        if pos > len(raw):
            return None
    return fields if len(fields) >= 2 and printable else None


def printable_strings(raw: bytes) -> list[str]:
    strings: list[str] = []
    for match in PRINTABLE.finditer(raw[:SCAN_LIMIT]):
        strings.append(match.group(0).decode("ascii", "ignore")[:MAX_STRING_CHARS])
        if len(strings) >= MAX_STRINGS:
            break
    return strings


def format_hint(raw: bytes) -> str:
    for magic, name in MAGIC:
        if raw.startswith(magic):
            return name
    return "unknown"


def binary_probe(raw: bytes) -> dict:
    """结构探测结果。`printable_strings` 只在内存里，落盘摘要会裁掉。"""
    strings = printable_strings(raw)
    joined = "\n".join(strings)
    return {
        "format_hint": format_hint(raw),
        "magic_hex": raw[:16].hex(),
        "printable_count": len(strings),
        "printable_sha256": hashlib.sha256(joined.encode("utf-8")).hexdigest() if strings else None,
        "printable_strings": strings,
        "confidence": "heuristic",
    }
