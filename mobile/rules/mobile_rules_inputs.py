#!/usr/bin/env python3
"""移动规则库的输入路径、JSON 读取与设备标定解析（build 与 insert 两侧共用）。

仅用于授权测试（已获授权的样本与设备）。

**为什么单独一份**：`SEED` / `REG` / `BUILD` / `CALIB` 这些目录既有"装载种子数据"的
一侧用（`insert_all`），也有"校验既有产物"的一侧用（`validate`），而这两侧已经拆成了
两个文件。常量留在任一侧都会造成循环导入，所以提到这里——顺带让"规则库的输入从哪来"
只有一处定义：输入目录写错时的症状是**构建成功但内容为空**，不会报错。

**`_protection_level_value` 为什么在这里**：它只被 `load_calibration` 用（设备实测的
`protectionLevel` 复合串 → 整数位值），跟着标定解析一起走。认不出的级别词返回 None
而不是编造一个值——over_permission 规则靠这一维，猜错等于凭空生成一条结论。
"""
from __future__ import annotations

import json
import os
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCHEMA = HERE / "schema_mobile.sql"
SEED = HERE / "seed"
BUILD = HERE / "build"
REG = HERE / "regulations"
CALIB = Path(os.environ["VSCAN_MOBILE_CALIB"]) if os.environ.get("VSCAN_MOBILE_CALIB") \
    else HERE / "calibration"
DEFAULT_OUT = HERE / "rules_mobile.db"
DEFAULT_WINDOW_MS = 30000  # 声明值；未由移动夹具校准前不是通用阈值


def read_json(p: Path):
    return json.loads(p.read_text(encoding="utf-8"))


def read_jsonl(p: Path) -> list[dict]:
    if not p.exists():
        return []
    return [json.loads(line) for line in p.read_text(encoding="utf-8").splitlines() if line.strip()]


def jdump(obj) -> str:
    return json.dumps(obj, sort_keys=True, ensure_ascii=False)


def load_calibration(calib_dir: Path | None = None) -> dict[str, dict]:
    """设备实测权限 → {permission_name: {"observations": [...], "protection_level_raw", ...}}。

    没有标定文件时返回空。**注意**：`definition_status` 一律保持 pending——schema 规定
    设备观测不得标 source_verified（javap 才是 source_verified 的唯一来源）；但实测到的
    protectionLevel 要落进 protection_level_raw/value，否则 over_permission 规则
    永远缺「权限保护级别」这一维（此处曾是个死路：INSERT 根本没写这两列）。

    接受两种字段名：`protection_level` 与车载标定产物用的 `protection_level_raw`，
    因此 `vehicle/rules/python/extract_device_calibration.py --prefix android.permission.`
    的产物可直接喂进来。
    """
    calib_dir = calib_dir or CALIB
    out: dict[str, dict] = {}
    for row in read_jsonl(calib_dir / "permissions-device.jsonl"):
        entry = out.setdefault(row["permission_name"], {"observations": [],
                                                        "protection_level_raw": None,
                                                        "protection_level_value": None})
        if row.get("observation"):
            entry["observations"].append(row["observation"])
        # 兼容车载侧标定产物的字段名（protection_level_raw），使同一格式可直接复用。
        raw = row.get("protection_level") or row.get("protection_level_raw")
        if raw:
            entry["protection_level_raw"] = raw
            pv = _protection_level_value(raw)
            if pv is not None:
                entry["protection_level_value"] = pv
    return out


# AOSP AndroidManifest.xml 里 protectionLevel 的位值（同一套值车载侧已用）
PROTECTION_LEVEL_BITS = {"normal": 0, "dangerous": 1, "signature": 2, "privileged": 4,
                         "system": 0x10, "development": 0x20, "appop": 0x40,
                         "pre23": 0x80, "installer": 0x100, "verifier": 0x200,
                         "preinstalled": 0x400, "setup": 0x800, "instant": 0x1000,
                         "runtime_only": 0x2000}


def _protection_level_value(raw: str) -> int | None:
    """把 'dangerous|instant' 这类复合串按位或汇总成整数；认不出的返回 None（不编造）。"""
    total = 0
    known = False
    for part in str(raw).split("|"):
        part = part.strip().lower()
        if part in PROTECTION_LEVEL_BITS:
            total |= PROTECTION_LEVEL_BITS[part]
            known = True
    return total if known else None
