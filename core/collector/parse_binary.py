#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""protobuf 保守启发式（从 parse.py 拆出，保持单文件 ≤300 行）。

只做结构猜测：wire type 合法、至少两个字段、至少一个可打印长度字段、字节被完整
消费，才认为"像 protobuf"。**猜不出就返回 None**，由调用方落成 `unparsed`，
绝不把随机二进制当成解析成功。仅用于授权测试。
"""
from __future__ import annotations


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
    """返回字段列表；不像 protobuf 时返回 None。"""
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
