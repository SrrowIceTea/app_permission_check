#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""把 `code_locs` 渲染成报告里的一行文字（R8 混淆样本要能读得懂）。

仅用于授权测试（已获授权的样本与设备）。

**为什么单独一个文件**：`report_sections.py` 已经 404 行（超 300 红线，见
`PLAN_OPTIMIZATION_20261020.md` 的工程债清单），这块纯字符串处理不该再往里塞。
"""
from __future__ import annotations

import re

# R8 把源文件名换成了 `r8-map-id-<64 位 hex>`：行号是真的，文件名不可读。
# 原样打印会把 PDF 撑成一行乱码，所以压成短标记——但不假装它是源码文件名。
_R8 = re.compile(r"r8-map-id-[0-9a-f]+")
_ROLE_ZH = {"read": "读取侧", "egress": "外发侧"}


def _short(text: str) -> str:
    return _R8.sub("r8-map-id…", str(text))


def code_loc_text(finding: dict) -> str:
    """帧 + 调用链；取不到位置时返回原因（"本来没有代码"与"没找到"必须分开）。"""
    locs = finding.get("code_locs") or []
    if not locs:
        return finding.get("code_loc_note") or "—"
    loc = next((x for x in locs if x.get("line")), locs[0])
    frame = loc.get("frame") or f"{loc.get('class')}.{loc.get('method')}"
    head = _short(frame) if loc.get("line") else f"{_short(frame)}（无行号）"
    chain = [_short(c) for c in (loc.get("chain_with_lines") or [])[1:3]]
    role = _ROLE_ZH.get(loc.get("role"), "")
    return head + (f" ← {' ← '.join(chain)}" if chain else "") + (f"（{role}）" if role else "")


def sdk_attribution_text(finding: dict) -> str:
    """SDK 归属一栏：把「含 SDK」（静态）与「SDK 在链上」（运行时）分开呈现。

    核心契约（见 core/evidence/sdk_attribution.py 与 DECISIONS D712）：
    「APK 打包了某 SDK」≠「SDK 出现在本次调用链」≠「SDK 采集了数据」。
    这里只陈述前两个可验证事实，绝不把"在链上"渲染成"在采集"。

    取不到任何归属信息时返回空串（卡片层据此决定是否显示这一行）。
    """
    locs = finding.get("code_locs") or []
    sdk_summaries = []
    for loc in locs:
        attr = loc.get("sdk_attribution")
        if not attr:
            continue
        sdk_summaries.append(attr)

    # 没有任何 loc 带归属 → 无信息可展示
    if not sdk_summaries:
        return ""

    # 链上出现过的 SDK（去重、保序），只统计非通用库的采集类 SDK
    chain_sdks: list[str] = []
    has_collection = False
    third_party_frames = 0
    for s in sdk_summaries:
        for name in s.get("sdk_in_chain") or []:
            if name not in chain_sdks:
                chain_sdks.append(name)
        if s.get("has_collection_sdk"):
            has_collection = True
        third_party_frames += s.get("third_party_frames") or 0

    parts: list[str] = []
    if chain_sdks:
        parts.append("本次调用链出现 SDK：" + "、".join(chain_sdks)
                     + ("（含采集/归因类 SDK，需复核其是否在采集本项数据）" if has_collection
                        else "（通用库，非采集类 SDK）"))
    elif has_collection:
        parts.append("调用链出现采集类 SDK 帧")
    if third_party_frames:
        parts.append(f"另有 {third_party_frames} 帧属打包内的第三方代码（认不出是哪家 SDK）")
    if not parts:
        # 链上全是宿主代码
        parts.append("调用链均为宿主自身代码（未发现 SDK 帧）")

    return "；".join(parts)
