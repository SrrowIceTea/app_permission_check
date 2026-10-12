#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""报文文本的安全读取 + **这次读取本身的状态**。

仅用于授权测试（自有设备与自有 APK）/ For authorized testing on owned devices and APKs only.

从 `tagging.py` 抽出来的原因：车载版与移动版的 `scan_body` / `body_of` /
`MAX_BODY_SCAN` 曾各存一份**逐字相同**的实现（移动版的注释还写着"与车载版同语义"）。
两份一样的代码必然漂移，而这里的每一条注释都是实测踩坑换来的，漂移一次就丢一条教训。

平台专有的只有**指纹表**（VHAL 属性名 vs 个人信息形态），那部分留在各产品的
tagging 模块里；"怎么把报文读出来、读全了没有"与平台无关。
"""
from __future__ import annotations

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
