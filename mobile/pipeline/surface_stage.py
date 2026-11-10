#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""流水线 `surface` 阶段（L2 只读覆盖统计）的编排胶水。

仅用于授权测试（自有设备 / 公开第三方样本的授权评估）。

为什么单独一个模块：
  * `runner.py`（默认路径）与 `formal_runner.py`（--audit-config 路径）都要跑这一步，
    两个执行器各写一份必然漂移；这里只有一份实现。
  * L2 只依赖 `job.apk` + 目标集 + 规则库（**只读**），不依赖设备、不依赖反编译产物，
    所以两条执行器都能在 `static` 之后直接调用。

**软着陆是本模块的核心契约**：目标集 sha 对不上、dex 缺失、目标集文件丢失，
一律收敛为 `status="unavailable"` + 原因，绝不抛出去拖垮流水线；
也绝不静默省略——调用方必须把返回值原样落盘（见 `runner.finalize` 的 `job.result`）。
"""
from __future__ import annotations

from pathlib import Path

from mobile.pipeline import stages

STAGE_ID = "surface"
DEFAULT_VERSION = "36"
FILE_NAME = "observed_surface.json"


def _unavailable(reason: str, **extra) -> dict:
    info = {"status": "unavailable", "reason": reason, "file": None,
            "stage": STAGE_ID, "note": "L2 未产出统计数据；这是「不可用」，不是「没有这一项」，"
                                      "也不表示该样本的敏感面已排除"}
    info.update(extra)
    return info


def run(job, events: Path | None = None, rules_db: Path | None = None,
        version: str = DEFAULT_VERSION) -> dict:
    """跑 L2 统计并把结果写进 `job.out`；任何失败都降级为 unavailable。"""
    stages.emit_events(events, STAGE_ID, "running", "闭集之外的敏感面（只读统计，不出结论）")
    out = Path(job.out)
    try:
        from mobile.tools import observed_surface  # 延迟导入：pipeline 启动时不背 frida/sqlite 依赖

        doc = observed_surface.run(Path(job.apk), out, rules_db or observed_surface.RULES_DB,
                                   version)
    except SystemExit as exc:  # 目标集 sha 不匹配 / 规则库版本不存在
        info = _unavailable(f"目标集或规则库校验失败：{str(exc).strip() or 'SystemExit'}")
    except Exception as exc:  # noqa: BLE001  目标集文件丢失、权限、dexdump 崩溃
        info = _unavailable(f"{type(exc).__name__}: {exc}")
    else:
        surf = doc.get("observed_surface") or {}
        ts = doc.get("target_set") or {}
        status = surf.get("status")
        if status == "ok":
            inv = surf.get("invisible") or {}
            dens = surf.get("denominators") or {}
            info = {"status": "ok", "reason": None, "stage": STAGE_ID,
                    "file": str(out / FILE_NAME),
                    "target_set": {k: ts.get(k) for k in ("target_set_id", "version", "sha256")},
                    "denominators": {
                        "signature_surface": {k: (dens.get("signature_surface") or {}).get(k)
                                              for k in ("total", "registered", "unregistered")},
                        "call_points": {k: (dens.get("call_points") or {}).get(k)
                                        for k in ("total", "registered", "unregistered")},
                    },
                    "invisible": {"signature_share": inv.get("signature_share"),
                                  "call_point_share": inv.get("call_point_share")},
                    "note": "样本内口径的覆盖统计，不是行业结论，也不得与四桶相加或加权"}
        else:
            # run() 自己已落盘一份带 status 的 observed_surface.json（no_dex / scan_failed），
            # 这里如实转述，并把文件留着——"没有数字"和"没有这一项"必须能分辨。
            info = _unavailable(
                surf.get("error") or f"observed_surface status={status}",
                file=str(out / FILE_NAME) if (out / FILE_NAME).exists() else None,
                upstream_status=status,
                target_set={k: ts.get(k) for k in ("target_set_id", "version", "sha256")})
    if info["status"] == "ok":
        ditems = info["denominators"]
        stages.emit_events(events, STAGE_ID, "done",
                           "签名面 {}/{} 登记；调用点 {}/{}".format(
                               ditems["signature_surface"]["registered"],
                               ditems["signature_surface"]["total"],
                               ditems["call_points"]["registered"],
                               ditems["call_points"]["total"]))
    else:
        stages.emit_events(events, STAGE_ID, "unavailable", info["reason"] or "不可用")
    job.result["observed_surface"] = info
    return info
