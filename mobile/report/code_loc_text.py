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
