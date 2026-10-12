#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""V-Scanner Phase 4 — 敏感载荷打标。

仅用于授权测试（自有设备与自有 APK）/ For authorized testing on owned devices and APKs only.

从 `addon.py` 拆出来，理由与 `attribution.py` 当初一样：`addon.py` 已经贴着
单文件 300 行的上限，而这两块（**流的一生** vs **报文里有什么**）本来就无关。
拆开之后指纹表可以脱离 mitmproxy 单独测——它现在只能靠抓真流量来验证，
而"规则表写错一条正则"是那种**永远不报错、只是少打一个标签**的失效。

**标签是线索，不是结论。** 命中 `vhal_property_name` 只说明报文里出现了
`PERF_VEHICLE_SPEED` 这个字符串，不说明这是泄露、也不说明它来自哪个读取。
是否构成违规由 Phase 5 的规则与人来判定。
"""
from __future__ import annotations

import re

# 敏感字段指纹。属性名/ID 来自 phase1/rules_library/rules.db 的 vhal_properties，
# **不是猜的**；VIN / 经纬度是形态匹配，只能标"疑似"，所以标签名带 `_like`。
SENSITIVE: list[tuple[str, re.Pattern[str]]] = [
    ("vhal_property_name", re.compile(
        r"\b(INFO_VIN|PERF_VEHICLE_SPEED|GEAR_SELECTION|CURRENT_GEAR|PERF_ODOMETER"
        r"|ENGINE_RPM|FUEL_LEVEL|EV_BATTERY_LEVEL)\b")),
    ("vhal_property_id", re.compile(
        r"\b(286261504|291504647|289408000|289408001|291504644|291504901|291504903|291504905)\b")),
    ("vin_like", re.compile(r"\b[A-HJ-NPR-Z0-9]{17}\b")),
    ("json_key_vehicle", re.compile(
        r'"(vin|speed|gear|rpm|odometer|fuel|battery|vehicleSpeed|gearSelection)"\s*:', re.I)),
    ("coordinate_like", re.compile(r"-?\d{1,3}\.\d{4,},\s*-?\d{1,3}\.\d{4,}")),
]

# 单条报文最多扫这么多字节。不是"够用"，是防止一个超大上传把代理拖死；
# 256KB 远大于实测载荷（约 2.4KB），越界这件事本身要能在日志里看见。
MAX_BODY_SCAN = 256 * 1024


def scan_body(message) -> tuple[str, dict]:
    """报文文本 + **这次扫描本身的状态**。

    为什么必须返回状态：扫两处会悄悄打折——解码失败返回空串、超过 `MAX_BODY_SCAN`
    截断。两者都让"没打上标签"与"内容根本没被完整看过"变得无法区分，而报告里
    前者读作"这条流不含敏感字段"、后者是"我们不知道"。实测：把属性名放到 256KB
    之后，标签一个都没有，日志里看不出任何异常——未命中与未扫到长得完全一样。

    长度单位是**字符**（`get_text` 返回 str），不是字节；别和 `payloads.capture`
    的 `raw_bytes` 混着用。
    """
    try:
        raw = message.get_text(strict=False)
    except Exception:  # noqa: BLE001
        return "", {"decode_error": True, "chars": None, "truncated": False,
                    "scanned_chars": 0, "limit_chars": MAX_BODY_SCAN}
    text = raw or ""
    return text[:MAX_BODY_SCAN], {
        "decode_error": False, "chars": len(text),
        "truncated": len(text) > MAX_BODY_SCAN,
        "scanned_chars": min(len(text), MAX_BODY_SCAN),
        "limit_chars": MAX_BODY_SCAN,
    }


def body_of(message) -> str:
    """报文文本。解不出来就返回空串——**不抛异常**。

    一条解不开的报文不该让整条流丢失：它是"内容没打上标签"，
    与"这条流没被抓到"是两回事，后者严重得多。

    只看文本、不看扫描状态的调用方用这个；需要知道有没有扫全的用 `scan_body`。
    """
    return scan_body(message)[0]


def tag_sensitive(text: str) -> tuple[list[str], list[str]]:
    """返回 (标签, 命中的字面量)。

    第二项是给 Phase 5 做内容匹配用的。**不能拿 preview 去匹配**——
    preview 截断到 400 字符，而载荷常有 2KB 以上，命中的属性名很可能落在截断点之后，
    于是"报文里确实出现了该属性"被误判成没出现。所以本函数扫的是**完整报文**。
    """
    labels: set[str] = set()
    tokens: set[str] = set()
    for label, pattern in SENSITIVE:
        for match in pattern.finditer(text):
            labels.add(label)
            tokens.add(match.group(0))
    return sorted(labels), sorted(tokens)
