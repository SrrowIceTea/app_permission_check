#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""一键审计流水线的阶段定义与事件读写。仅用于授权测试（自有设备 / 已授权样本）。

阶段事件是流水线（runner）、编排服务（server SSE）、前端（时间线）三方的**唯一契约**，
schema 就一种：`{"ts": float, "stage": str, "status": str, "message": str}`。
status 取值：running（进入）/ done（成功）/ failed（失败）/ skipped（跳过）/
unavailable（阶段跑完了但结果不可用，**不影响流水线终态**，必须带原因）。
"""
from __future__ import annotations

import json
import time
from pathlib import Path

# 阶段顺序即前端时间线的展示顺序。动态侧各阶段对应 device_run_thirdparty.py 的埋点。
#
# `surface`（敏感面统计，L2）插在 `static` 之后、`boot` 之前，理由：
#   * 它是**派生统计**，输入是 APK 的 dex + 静态扫描口径，设备不参与；
#   * 因此绝不能抢在 `static` 之前（会让时间线看起来"统计先于扫描"），
#     也不该排在动态阶段后面（设备不可用时它照样能出数，这正是它的价值）；
#   * 它**不出结论**：不产候选、不进四桶、不折算检出率。
# 加了它之后阶段数由 16 变 17（见 mobile/pipeline/README.md「阶段」）。
STAGES: list[tuple[str, str]] = [
    ("prepare", "环境准备"),
    ("boot", "模拟器就绪"),
    ("static", "静态剖析"),
    ("surface", "敏感面统计"),
    ("frida_server", "Frida 服务就绪"),
    ("network", "网络连通"),
    ("install", "安装样本"),
    ("launch", "启动应用"),
    ("conn_probe", "连接采样"),
    ("mitm", "流量镜像"),
    ("hooks", "Frida 插桩"),
    ("explore", "交互驱动"),
    ("death_probe", "存活取证"),
    ("correlate", "关联分析"),
    ("bundle", "证据封装"),
    ("ai_review", "AI 研判"),
    ("report", "报告生成"),
]

STAGE_ORDER: dict[str, int] = {sid: i for i, (sid, _) in enumerate(STAGES)}
STAGE_LABEL: dict[str, str] = dict(STAGES)

# 设备不可用时，这些动态阶段会整段降级为 skipped（静态阶段仍正常出结论）。
# `surface` 必须留在非设备一侧：它只读 APK 与目标集，设备挂了也照样出数，
# 若误算进 DYNAMIC_STAGES，会在一台设备不可用时被标成 skipped（假的"没跑"）。
NON_DEVICE_STAGES = ("prepare", "boot", "static", "surface")
DYNAMIC_STAGES = [sid for sid, _ in STAGES if sid not in NON_DEVICE_STAGES]


def emit_events(path: Path | None, stage: str, status: str, message: str = "") -> None:
    """把一条阶段事件追加到 events.jsonl。只追加、只 flush，绝不抛异常拖垮主流程。"""
    if path is None:
        return
    try:
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps({"ts": time.time(), "stage": stage, "status": status,
                                 "message": message}, ensure_ascii=False) + "\n")
            fh.flush()
    except OSError:
        pass


def read_events(path: Path, offset: int = 0) -> tuple[list[dict], int]:
    """读取 events.jsonl 中 offset 之后的新事件。返回 (事件列表, 新 offset)。

    只读不删；offset 用「已读行数」即可（事件文件只追加、从不改写）。
    """
    if not path.exists():
        return [], offset
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return [], offset
    if offset >= len(lines):
        return [], offset
    events: list[dict] = []
    for line in lines[offset:]:
        line = line.strip()
        if not line:
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return events, len(lines)
