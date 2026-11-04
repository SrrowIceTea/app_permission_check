#!/usr/bin/env python3
"""Build the dual-version rule library: android-14 source rows + android-15 device rows.

android-14 rows are copied verbatim from the locked baseline and stay source_verified.
android-15 rows are DEVICE OBSERVATIONS and stay `pending`. The two are never merged:
a protection level read off a running build says nothing about which AOSP release
declared it, and nothing here may claim otherwise.

android-15 policy rules mirror the project predicates, while source_refs_json
is replaced with device provenance by device_rows.py (D009/D010). Source and
device observations must remain distinguishable.

android-15 行本身的构造在 device_rows.py（它贴着单文件 300 行的上限才拆出去）。
Usage:
  python python/build_multiversion_rules.py \
      --base baseline_android14/rules.db \
      --calibration device_calibration/permissions-car-android15.jsonl \
      --property-ids device_calibration/vhal-property-ids-device35.json \
      --cpm-signatures device_calibration/cpm-signatures-device35.json \
      --device-facts device_calibration/device-facts.json \
      --enable-types over_permission,sensitive_read \
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
from privacy_rows import insert_privacy_rules
from privacy_observation import DEFAULT_OBSERVATION

TABLES = ("permissions", "vhal_properties", "dangerous_apis", "risk_rules")
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


def apply_enablement(dst: sqlite3.Connection, enabled_types: set[str]) -> dict:
    """启用指定谓词的规则，其余保持 disabled。

    `enabled = 1` 的含义是"这条规则适合产出审计结论"，不是"这条规则存在"。
    D005 当初设的门槛是"没有求值器就不启用"，Phase 5 提供了求值器，门槛已跨过；
    但还要看规则本身站不站得住：

    * `over_permission` / `sensitive_read` 谓词简单，无已知缺陷 → 启用。
    * `data_egress` 依赖 `window_ms`，而该参数**实测偏小一个数量级**
      （规则 3000ms，靶子 App 实际读取→外发 10.6s / 20.3s）。
      启用一条已知会漏报的规则，等于对外声明它可用。**在窗口被校准前不启用。**

    schema 的 CHECK 约束会强制 enabled=1 的行必须具备完整出处（版本非 UNRESOLVED、
    condition/evidence/source_refs/basis_refs 齐全），这里依赖它兜底，不自己再判一遍。
    """
    before = {t: dst.execute(
        "SELECT COUNT(*) FROM risk_rules WHERE enabled = 1 AND rule_type = ?", (t,)
    ).fetchone()[0] for t in ("over_permission", "sensitive_read", "data_egress")}

    if enabled_types - {"over_permission", "sensitive_read", "data_egress"}:
        raise ValueError("未知规则类型")
    dst.execute("UPDATE risk_rules SET enabled=0")
    for rule_type in sorted(enabled_types):
        dst.execute("UPDATE risk_rules SET enabled = 1 WHERE rule_type = ?", (rule_type,))

    after = {}
    for rule_type in ("over_permission", "sensitive_read", "data_egress"):
        row = dst.execute(
            "SELECT COUNT(*), SUM(enabled) FROM risk_rules WHERE rule_type = ?", (rule_type,)
        ).fetchone()
        after[rule_type] = {"total": row[0], "enabled": row[1] or 0}
    return {"before": before, "after": after}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--base", type=Path, required=True)
    parser.add_argument("--calibration", type=Path, required=True)
    parser.add_argument("--property-ids", type=Path, required=True)
    parser.add_argument("--cpm-signatures", type=Path, required=True)
    parser.add_argument("--device-facts", type=Path)
    parser.add_argument("--privacy-observation", type=Path, default=DEFAULT_OBSERVATION,
                        help="通用隐私来源独立实测快照；不得使用旧 VHAL device-facts 代替")
    parser.add_argument("--enable-types", default="",
                        help="逗号分隔的 rule_type，这些类型的规则置 enabled=1。"
                             "留空则全部保持禁用。data_egress 还必须指定"
                             " --egress-window-ms 30000（见 EGRESS_CALIBRATION.md）")
    parser.add_argument("--egress-window-ms", type=int, help="按 EGRESS_CALIBRATION.md 校准，当前批准值 30000")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--summary", type=Path)
    args = parser.parse_args()

    if args.out.exists():
        print(json.dumps({"status": "failed", "message": f"Refusing to overwrite {args.out}"}),
              file=sys.stderr)
        return 1

    schema = Path(__file__).resolve().parents[1] / "schema.sql"
    device_facts = json.loads(args.device_facts.read_text(encoding="utf-8")) if args.device_facts else {}

    args.out.parent.mkdir(parents=True, exist_ok=True)
    dst = sqlite3.connect(args.out)
    dst.executescript(schema.read_text(encoding="utf-8"))

    src = sqlite3.connect(f"file:{args.base.resolve().as_posix()}?mode=ro", uri=True)
    counts = {SOURCE_VERSION: copy_rows(src, dst, SOURCE_VERSION)}
    src.close()

    counts[DEVICE_VERSION] = build_device_rows(dst, args.calibration, args.property_ids,
                                               args.cpm_signatures, device_facts)
    # General-privacy rules are registered after the device rows on purpose: they are
    # project-policy rules about Android SDK sources, so insert_device_rules must not
    # mirror them (its device provenance records car permissions/dexdump evidence).
    privacy = insert_privacy_rules(dst, args.privacy_observation)
    enabled_types = {t.strip() for t in args.enable_types.split(",") if t.strip()}
    if "data_egress" in enabled_types and args.egress_window_ms is None:
        raise ValueError("启用 data_egress 必须显式指定 --egress-window-ms 30000")
    if args.egress_window_ms is not None:
        calibrate(dst, args.egress_window_ms)
    enablement = apply_enablement(dst, enabled_types)
    dst.commit()

    actual = {
        v: {t: dst.execute(f"SELECT COUNT(*) FROM {t} WHERE android_version = ?", (v,)).fetchone()[0]
            for t in TABLES}
        for v in (SOURCE_VERSION, DEVICE_VERSION)
    }
    enabled = dst.execute("SELECT COUNT(*) FROM risk_rules WHERE enabled = 1").fetchone()[0]
    dst.close()

    summary = {
        "status": "dual_version_library",
        "counts": actual,
        "enabled_rules": enabled,
        "privacy_rules": privacy,
        "android15_source": "device_observation",
        "android15_rule_policy": "policy_mirrored_from_android14_with_device_provenance",
        "enablement": enablement,
        "database_sha256": hashlib.sha256(args.out.read_bytes()).hexdigest(),
        "note": "android-15 rows are device observations (definition_status=pending). "
                "They are not source extractions and must not be reported as such.",
    }
    if args.summary:
        args.summary.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n",
                                encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
