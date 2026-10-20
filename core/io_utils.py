#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""JSONL 读取的**唯一**实现。

仅用于授权测试（自有设备与自有 APK）/ For authorized testing on owned devices and APKs only.

**为什么抽这一层**：全仓曾有 6 份各自手写的 `load_jsonl`，而且**容错语义相反**——
车载侧（`vehicle/analyze/correlate.py`）坏行直接 `raise ValueError`，移动侧
（`mobile/ai/evidence_bundle.py`、`mobile/analyze/correlate_mobile.py`）静默 `continue`。
同一批采集产物被两侧读，一边整批失败、一边悄悄少几条，两边都不报错（§8.2 B-2）。

容错策略显式化为参数，不再由"这个模块是谁写的"决定：

* `on_bad_line="raise"`（默认）——坏行立即失败，带**文件路径与行号**；
* `on_bad_line="count"`——跳过坏行，但**把跳过数交还给调用方**，由它写进 `gaps`
  或告警。静默跳过在 gaps 里是被禁止的（§8.6 铁律 3：失败必须与空结果可区分）。

文件不存在 / 路径为 None 一律返回空列表：这是"这一路输入缺失"，上层已有
`gaps` 在管（"缺失 ≠ 没发生"），不属于本层的解析失败。
"""
from __future__ import annotations

import json
from pathlib import Path


def split_jsonl_lines(text: str) -> list[str]:
    """把 JSONL 文本切成记录，**只认 LF**，返回去掉空白的非空行。

    **不要用 `str.splitlines()`**：它按 Unicode 行边界切分，JSON 字符串里合法的
    U+0085（NEL）/ U+2028 / U+2029 也会被当成换行。mitmproxy 落盘的 flow 记录里
    `response_payload.text` 是 latin-1 解码出的正文，二进制响应里 0x85 遍地都是——
    实测 `36-ign-geoportail/session/flows.jsonl` 一条 6.7KB 的记录里有 59 个 U+0085，
    用 splitlines() 读会把 **34 条记录读成 93 段无法解析的碎片**，全部被当坏行丢掉，
    于是"有流"变成"没流"。这不是理论问题，是 2026-10-20 在真实批次里实测到的。

    本函数是这条口径的唯一出口：新代码要自己逐行解析 JSONL 时用它，
    或者直接用 `load_jsonl` / `load_jsonl_counting`。
    """
    return [ln for ln in (line.strip() for line in text.split("\n")) if ln]


def _read(path: Path | None, on_bad_line: str) -> tuple[list[dict], int]:
    if on_bad_line not in ("raise", "count"):
        raise ValueError(f"on_bad_line 只能是 'raise' 或 'count'，收到 {on_bad_line!r}")
    if path is None or not Path(path).exists():
        return [], 0
    rows: list[dict] = []
    skipped = 0
    # errors="replace"：坏字节不至于让整个文件读不出来；被替换的那一行随后
    # 多半 JSON 解析失败，仍会按策略抛出或被计数——不会静默消失。
    # **分行只认 LF**（理由见 split_jsonl_lines 的 docstring）。这里不用它而直接
    # `split("\n")`，是为了让报错里的行号等于**物理行号**——空行被过滤掉后如果
    # 继续用过滤后的序号，`raise` 分支给的 `:N:` 会比真实位置偏小，而这条报错是
    # 定位坏证据的唯一线索（`test_jsonl_unicode` 正是按物理行号断言的）。
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    for lineno, raw in enumerate(text.split("\n"), 1):
        raw = raw.strip()
        if not raw:
            continue
        try:
            rows.append(json.loads(raw))
        except json.JSONDecodeError as exc:
            if on_bad_line == "raise":
                raise ValueError(f"无效 JSONL {path}:{lineno}: {exc}") from exc
            skipped += 1
    return rows, skipped


def load_jsonl(path: Path | None, *, on_bad_line: str = "raise") -> list[dict]:
    """读 JSONL；坏行默认**抛出**（带文件:行号）。"""
    rows, _ = _read(path, on_bad_line)
    return rows


def load_jsonl_counting(path: Path | None) -> tuple[list[dict], int]:
    """读 JSONL 并返回 `(记录, 跳过行数)`。

    跳过数**必须**被调用方写进 `gaps` 或告警——拿它却不用，等于把本层的
    "静默跳过"又搬到了上一层。
    """
    return _read(path, "count")
