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


def _read(path: Path | None, on_bad_line: str) -> tuple[list[dict], int]:
    if on_bad_line not in ("raise", "count"):
        raise ValueError(f"on_bad_line 只能是 'raise' 或 'count'，收到 {on_bad_line!r}")
    if path is None or not Path(path).exists():
        return [], 0
    rows: list[dict] = []
    skipped = 0
    # errors="replace"：坏字节不至于让整个文件读不出来；被替换的那一行随后
    # 多半 JSON 解析失败，仍会按策略抛出或被计数——不会静默消失。
    # JSON strings may legally contain U+0085/U+2028/U+2029. Only LF frames records;
    # str.splitlines() would split those string contents into invalid JSON fragments.
    for lineno, raw in enumerate(
            Path(path).read_text(encoding="utf-8", errors="replace").split("\n"), 1):
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
