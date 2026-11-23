#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Build the multi-version rule library.

Source versions (android-13/14/16) are copied from their locked baselines and stay
`source_verified`. android-15 rows are DEVICE OBSERVATIONS and stay `pending`. The
two are never merged: a protection level read off a running build says nothing
about which AOSP release declared it, and nothing here may claim otherwise.

android-14 is copied verbatim from `--base` (its packaged baseline database).
android-13/16 are inserted from their seed directories, whose `sources.lock.json`
digests, source references and evidence locators are re-verified on the way in.

android-13/16 have no egress-window calibration. Their `data_egress` rows are
registered but stay disabled, and they never inherit the E1 30000ms calibration:
only versions listed in `--egress-versions` may carry enabled egress rules.

android-15 行本身的构造在 device_rows.py，额外源码基线的校验/插入在 source_rows.py
（两个文件都是为了守住单文件 300 行）。

Usage:
  python python/build_multiversion_rules.py \
      --base baseline_android14/rules.db \
      --source-seed baseline_android13 --source-seed baseline_android16 \
      --calibration device_calibration/permissions-car-android15.jsonl \
      --general-permissions device_calibration/permissions-general-android15.jsonl \
      --property-ids device_calibration/vhal-property-ids-device35.json \
      --cpm-signatures device_calibration/cpm-signatures-device35.json \
      --device-facts device_calibration/device-facts.json \
      --enable-types over_permission,sensitive_read,data_egress \
      --egress-window-ms 30000 --egress-versions 14,15 \
      --out rules_library/rules.db
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
import sys
from pathlib import Path

from device_rows import DEVICE_VERSION, build_device_rows
from egress_calibration import calibrate
from permission_levels import BUILD_ID, REPORT, REVIEW_SHA256, load_levels
from privacy_rows import insert_privacy_rules
from privacy_observation import DEFAULT_OBSERVATION
from source_rows import insert_source_rows

TABLES = ("permissions", "vhal_properties", "dangerous_apis", "risk_rules")
RULE_TYPES = ("over_permission", "sensitive_read", "data_egress")
SOURCE_VERSION = "14"


def copy_rows(src: sqlite3.Connection, dst: sqlite3.Connection, version: str) -> dict:
    counts = {}
    for table in TABLES:
        columns = [r[1] for r in src.execute(f"PRAGMA table_info({table})")]
        placeholders = ",".join("?" * len(columns))
        rows = src.execute(
            f"SELECT {','.join(columns)} FROM {table} WHERE android_version = ?", (version,)
        ).fetchall()
        dst.executemany(
            f"INSERT INTO {table} ({','.join(columns)}) VALUES ({placeholders})", rows
        )
        counts[table] = len(rows)
    return counts


def apply_enablement(dst: sqlite3.Connection, enabled_types: set[str], egress_versions) -> dict:
    """启用指定谓词的规则，其余保持 disabled。

    `enabled = 1` 的含义是"这条规则适合产出审计结论"，不是"这条规则存在"。
    `data_egress` 依赖 `window_ms`，而该参数**实测偏小一个数量级**
    （规则 3000ms，靶子 App 实际读取→外发 10.6s / 20.3s），只有在
    EGRESS_CALIBRATION.md 批准过的版本才启用。android-13/16 未做窗口标定，
    因此即便传入了 data_egress，也只对 --egress-versions 内的版本置 1。

    schema 的 CHECK 约束会强制 enabled=1 的行必须具备完整出处，这里依赖它兜底。
    """
    if enabled_types - set(RULE_TYPES):
        raise ValueError("未知规则类型")
    before = {t: dst.execute(
        "SELECT COUNT(*), COALESCE(SUM(enabled),0) FROM risk_rules WHERE rule_type = ?", (t,)
    ).fetchone() for t in RULE_TYPES}

    dst.execute("UPDATE risk_rules SET enabled=0")
    for rule_type in sorted(enabled_types):
        if rule_type == "data_egress":
            marks = ",".join("?" * len(egress_versions))
            dst.execute(
                f"UPDATE risk_rules SET enabled = 1 WHERE rule_type = ? "
                f"AND android_version IN ({marks})", (rule_type, *egress_versions))
        else:
            dst.execute("UPDATE risk_rules SET enabled = 1 WHERE rule_type = ?", (rule_type,))

    after = {}
    for rule_type in RULE_TYPES:
        row = dst.execute(
            "SELECT COUNT(*), COALESCE(SUM(enabled),0) FROM risk_rules WHERE rule_type = ?",
            (rule_type,)).fetchone()
        after[rule_type] = {"total": row[0], "enabled": row[1]}
    return {"before": {t: {"total": v[0], "enabled": v[1]} for t, v in before.items()},
            "after": after,
            "egress_versions": sorted(egress_versions)}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--base", type=Path, required=True, help="android-14 打包基线库")
    parser.add_argument("--source-seed", action="append", default=[], type=Path, metavar="DIR",
                        help="额外源码基线的 seed 目录（版本取自其 sources.lock.json）；可重复")
    parser.add_argument("--calibration", type=Path, required=True)
    parser.add_argument("--general-permissions", type=Path, required=True,
                        help="已冻结 pm 输出中白名单抽取的通用权限（仅 '15'，设备观测）")
    parser.add_argument("--property-ids", type=Path, required=True)
    parser.add_argument("--cpm-signatures", type=Path, required=True)
    parser.add_argument("--device-facts", type=Path)
    parser.add_argument("--privacy-observation", type=Path, default=DEFAULT_OBSERVATION,
                        help="通用隐私来源独立实测快照；不得使用旧 VHAL device-facts 代替")
    parser.add_argument("--enable-types", default="",
                        help="逗号分隔的 rule_type，这些类型的规则置 enabled=1。"
                             "data_egress 还必须指定 --egress-window-ms 30000 且在 --egress-versions 内")
    parser.add_argument("--egress-versions", default="14,15",
                        help="允许启用 data_egress 的版本；13/16 未做窗口标定，不要加入")
    parser.add_argument("--egress-window-ms", type=int, help="按 EGRESS_CALIBRATION.md 校准，当前批准值 30000")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--summary", type=Path)
    args = parser.parse_args()

    if args.out.exists():
        print(json.dumps({"status": "failed", "message": f"Refusing to overwrite {args.out}"}),
              file=sys.stderr)
        return 1

    egress_versions = tuple(v.strip() for v in args.egress_versions.split(",") if v.strip())
    schema = Path(__file__).resolve().parents[1] / "schema.sql"
    device_facts = json.loads(args.device_facts.read_text(encoding="utf-8")) if args.device_facts else {}
    try:
        protection_levels = load_levels(args.calibration, args.general_permissions)
    except (KeyError, OSError, ValueError) as error:
        print(json.dumps({"status": "failed", "message": str(error)}), file=sys.stderr)
        return 1

    args.out.parent.mkdir(parents=True, exist_ok=True)
    dst = sqlite3.connect(args.out)
    dst.executescript(schema.read_text(encoding="utf-8"))
    dst.execute("PRAGMA foreign_keys = ON")

    src = sqlite3.connect(f"file:{args.base.resolve().as_posix()}?mode=ro", uri=True)
    counts = {SOURCE_VERSION: copy_rows(src, dst, SOURCE_VERSION)}
    src.close()

    for seed_dir in args.source_seed:
        lock = json.loads((seed_dir / "sources.lock.json").read_text(encoding="utf-8"))
        version = lock["android_version"]
        if version == DEVICE_VERSION or version in counts:
            raise ValueError("Unexpected or duplicate source baseline: " + version)
        counts[version] = insert_source_rows(dst, seed_dir)

    counts[DEVICE_VERSION] = build_device_rows(dst, args.calibration, args.general_permissions,
                                               args.property_ids, args.cpm_signatures, device_facts,
                                               protection_levels)
    versions = sorted(counts)
    # General-privacy rules are registered after the device rows on purpose: they are
    # project-policy rules about Android SDK sources, so insert_device_rules must not
    # mirror them (its device provenance records car permissions/dexdump evidence).
    privacy = insert_privacy_rules(dst, versions, egress_versions, args.privacy_observation)
    enabled_types = {t.strip() for t in args.enable_types.split(",") if t.strip()}
    if "data_egress" in enabled_types and args.egress_window_ms is None:
        raise ValueError("启用 data_egress 必须显式指定 --egress-window-ms 30000")
    if args.egress_window_ms is not None:
        calibrate(dst, args.egress_window_ms, egress_versions)
    enablement = apply_enablement(dst, enabled_types, egress_versions)
    dst.commit()

    actual = {v: {t: dst.execute(f"SELECT COUNT(*) FROM {t} WHERE android_version = ?", (v,)).fetchone()[0]
                  for t in TABLES} for v in versions}
    enabled_by_version = {v: dst.execute(
        "SELECT COUNT(*) FROM risk_rules WHERE enabled = 1 AND android_version = ?", (v,)
    ).fetchone()[0] for v in versions}
    enabled = dst.execute("SELECT COUNT(*) FROM risk_rules WHERE enabled = 1").fetchone()[0]
    dst.close()
    source_versions = sorted(v for v in versions if v != DEVICE_VERSION)

    summary = {
        "status": "multi_version_library",
        "counts": actual,
        "enabled_rules": enabled,
        "enabled_by_version": enabled_by_version,
        "privacy_rules": privacy,
        "source_versions": source_versions,
        "android15_source": "device_observation",
        "android15_protection_levels": {
            "build_id": BUILD_ID, "review_file": REPORT.name,
            "review_content_sha256": REVIEW_SHA256, "imported": len(protection_levels),
        },
        "android15_rule_policy": "policy_mirrored_from_android14_with_device_provenance",
        "egress_versions": sorted(egress_versions),
        "enablement": enablement,
        "database_sha256": hashlib.sha256(args.out.read_bytes()).hexdigest(),
        "note": "android-15 rows are device observations (definition_status=pending). "
                "android-" + "/".join(source_versions) + " are source extractions. "
                "Egress rules stay disabled outside egress_versions because no window "
                "calibration exists for those releases.",
    }
    if args.summary:
        args.summary.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n",
                                encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
