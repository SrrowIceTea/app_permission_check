#!/usr/bin/env python3
"""移动版敏感载荷打标表 —— 与 `phase4/tagging.py`（车载版）同一契约。

仅用于授权测试（已获授权的样本与设备）。

接口契约（`core/collector/addon.py` 按 `VSCAN_TAGGING` 路径加载本文件）：
    tag_sensitive(text) -> (labels, tokens)

"怎么把报文读出来、读全了没有"（`scan_body` / `body_of` / `MAX_BODY_SCAN`）与平台无关，
在 `core/collector/body.py`，本模块**不再各存一份**——那两份曾逐字相同。

与车载版的**关键差异**（这是必须有独立一张表的原因）：
  1) 敏感面从「VHAL 属性名/ID + VIN」换成个人信息的**形态**（15 位数字标识、
     16 位十六进制 AndroidID、MAC、手机号、身份证号、坐标、含个人信息的 JSON 键）。
  2) `tokens` 不再回传原文，而是回传 **`标签:sha256前16位`**。
     原因有二：报告与 LLM 不该再拿到一份个人信息副本；而哈希仍可用于
     **值级匹配**——与 hook_privacy 记录的值哈希比对，能把「时间上相近」
     升级成「确实发了这个值」（车载侧只有关键字匹配，D 记录里明确说那是弱证据）。
  3) 形态命中一律标 `_shape`：15 位数字**不等于** IMEI（订单号、时间戳拼接都长这样），
     所以它是线索不是结论；结论要靠值哈希对上。

边界：本模块只做正则形态识别与哈希，不做语义判断；命中与否都不改变报文。
"""
from __future__ import annotations

import hashlib
import re

# 标签 → (数据类别, 强度)。
#
# **为什么大多数映射的类别是 None**：形态分不出具体类别——
#   * 15 位数字：IMEI 与 IMSI 都是 15 位，仅凭形状无法区分；
#   * 19–20 位数字：更像 ICCID，本规则库尚未收录该类别。
# 按形态断言"这是 IMEI"就是过度声称。**正确做法**：形态只给线索（strength=shape），
# 具体类别由**值哈希**与 hook_privacy 记录的读取事件对上后确定（strength=value）。
# 能直接定类别的只有那些形态唯一的（MAC 的冒号分组、身份证号、坐标对）。
TYPE_BY_LABEL: dict[str, tuple[str | None, str]] = {
    "digit15_shape": (None, "shape"),        # IMEI 或 IMSI，待值哈希定性
    "digit19_shape": (None, "shape"),        # 疑似 ICCID，未收录
    "android_id_shape": ("android_id", "shape"),
    "mac_shape": ("mac_address", "shape"),
    "phone_cn_shape": ("phone_number", "shape"),
    "id_card_shape": ("id_card", "shape"),
    "coordinate_shape": ("precise_location", "shape"),
    "email_shape": ("email", "shape"),
    "json_key_personal": (None, "key"),      # 键名线索，具体类别看键名内容
}

SENSITIVE: list[tuple[str, re.Pattern[str]]] = [
    # 顺序有意义：先长后短，避免 19 位被 15 位规则截走。
    ("digit19_shape", re.compile(r"(?<!\d)\d{19,20}(?!\d)")),
    ("digit15_shape", re.compile(r"(?<!\d)\d{15}(?!\d)")),
    ("id_card_shape", re.compile(r"(?<!\d)\d{17}[\dXx](?!\d)")),
    ("android_id_shape", re.compile(r"(?<![0-9a-fA-F])[0-9a-f]{16}(?![0-9a-fA-F])")),
    ("mac_shape", re.compile(r"(?<![0-9a-fA-F:])(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}(?![0-9a-fA-F:])")),
    ("phone_cn_shape", re.compile(r"(?<!\d)1[3-9]\d{9}(?!\d)")),
    ("coordinate_shape", re.compile(r"(?<![\d.])-?\d{1,3}\.\d{4,}\s*,\s*-?\d{1,3}\.\d{4,}")),
    ("email_shape", re.compile(r"[\w.+-]+@[\w-]+\.[\w.]{2,}")),
    ("json_key_personal", re.compile(
        r"\"(imei|imsi|meid|iccid|device_?id|android_?id|oaid|mac_?address|"
        r"latitude|longitude|lat|lon|lng|phone|mobile|contact|sms|location)\"\s*:",
        re.IGNORECASE)),
]

# 命中的原文最长参与哈希的长度：超长匹配（如整段 base64）没有比对价值，且拖慢扫描。
HASH_MAX_LEN = 256


def _hash16(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


def tag_sensitive(text: str) -> tuple[list[str], list[str]]:
    """→ (标签列表, 令牌列表)。令牌形如 `digit15_shape:9f2c…`，**不含原文**。"""
    labels: set[str] = set()
    tokens: set[str] = set()
    if not text:
        return [], []
    for label, pattern in SENSITIVE:
        for m in pattern.finditer(text):
            labels.add(label)
            value = m.group(0)
            if len(value) <= HASH_MAX_LEN:
                tokens.add(f"{label}:{_hash16(value)}")
    return sorted(labels), sorted(tokens)


def types_for_labels(labels: list[str]) -> list[dict]:
    """标签 → [{label, data_type, strength}]，供下游把标签映射回规则库的数据类别。"""
    out = []
    for label in labels:
        dt, strength = TYPE_BY_LABEL.get(label, (None, "unknown"))
        out.append({"label": label, "data_type": dt, "strength": strength})
    return out
