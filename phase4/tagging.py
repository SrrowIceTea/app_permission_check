#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""V-Scanner 车载版敏感载荷打标表。

仅用于授权测试（自有设备与自有 APK）/ For authorized testing on owned devices and APKs only.

**这里只剩平台专有的部分**：指纹表 + `tag_sensitive`。
"怎么把报文读出来、读全了没有"（`scan_body` / `body_of` / `MAX_BODY_SCAN`）与平台无关，
已抽到 `core/collector/body.py`——它与移动端 `tagging_mobile.py` 里那份曾逐字相同，
两份一样的实现必然漂移，而那边每条注释都是实测踩坑换来的。

打标表由 `core/collector/addon.py` 通过 `VSCAN_TAGGING` 环境变量按路径加载，
契约是 `tag_sensitive(text) -> (labels, tokens)`。

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


def tag_sensitive(text: str) -> tuple[list[str], list[str]]:
    """返回 (标签, 命中的字面量)。

    第二项是给 Phase 5 做内容匹配用的。**不能拿 preview 去匹配**——
    preview 截断到 400 字符，而载荷常有 2KB 以上，命中的属性名很可能落在截断点之后，
    于是"报文里确实出现了该属性"被误判成没出现。所以本函数扫的是**完整报文**。

    车载版回传**原文字面量**；移动端版回传 `标签:sha256前16位`（那边要做值级匹配，
    且不愿在报告与 LLM 里再留一份个人信息副本）。两者都满足同一契约：
    tokens 是可比较的字符串集合。
    """
    labels: set[str] = set()
    tokens: set[str] = set()
    for label, pattern in SENSITIVE:
        for match in pattern.finditer(text):
            labels.add(label)
            tokens.add(match.group(0))
    return sorted(labels), sorted(tokens)
