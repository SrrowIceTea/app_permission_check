#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""device_run_thirdparty 的纯函数层（从 device_run_thirdparty.py 拆出，零行为改动）。

只放**与设备无关的独立函数**：aapt2 权限解析 / LLM key 判定 / JSONL 行数 / 事件落盘。
设备操作与编排留在 device_run_thirdparty.py 的 main() 及六个阶段模块。
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
MOBILE = ROOT / "mobile"


def apk_permissions(apk: Path, build_tools: str) -> list[str]:
    import subprocess
    aapt2 = str(Path(build_tools) / "aapt2.exe")
    # 必须给超时：无超时的 subprocess.run 一卡住就是整条链停摆，报错里还毫无线索。
    out = subprocess.run([aapt2, "dump", "permissions", str(apk)],
                         capture_output=True, text=True, encoding="utf-8",
                         errors="replace", timeout=180).stdout
    return sorted({m.group(1) for m in re.finditer(r"uses-permission: name='([^']+)'", out)})


def has_api_key() -> bool:
    """是否已配置可用的 LLM key（环境变量优先，其次 config.local.json）。

    与 `ai/llm_client.py` 的判定口径保持一致：占位符等于没配。
    """
    placeholders = {"", "PUT-YOUR-KEY-HERE", "sk-xxx", "YOUR_API_KEY"}
    key = (os.environ.get("VSCAN_LLM_API_KEY") or "").strip()
    if not key:
        cfg = MOBILE / "ai" / "config.local.json"
        if cfg.exists():
            try:
                key = str(json.loads(cfg.read_text(encoding="utf-8")).get("api_key") or "").strip()
            except (json.JSONDecodeError, OSError):
                key = ""
    return key not in placeholders


def _count_jsonl(path: Path) -> int:
    """产物里已有多少行（段账目用）。文件不存在 = 0 行，不抛。"""
    try:
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            return sum(1 for _ in fh)
    except OSError:
        return 0


def _emit_events(events: Path | None, stage: str, status: str, message: str = "") -> None:
    """把阶段事件追加到 events.jsonl，供编排层（pipeline server）的 SSE 实时读取。

    只追加、只 flush；**绝不失败主流程**——事件上报是旁路，不能因为它把检测搞挂。
    status 取值：running（进入阶段）/ done（成功）/ failed（失败）/ skipped（跳过）。
    """
    if events is None:
        return
    try:
        with events.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps({"ts": time.time(), "stage": stage, "status": status,
                                 "message": message}, ensure_ascii=False) + "\n")
            fh.flush()
    except OSError:
        pass
