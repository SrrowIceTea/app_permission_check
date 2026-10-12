#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Device-observed android-15 rows for the dual-version rule library.

从 build_multiversion_rules.py 拆出（它贴着单文件 300 行的上限）。这半边是
**设备观测行的构造**：权限、属性、API、规则四张表的 '15' 行，全部标
`definition_status='pending'`、出处记 `device_calibration_json`；这半边不碰
android-14 源码行（那些由主文件 copy_rows 原样复制，保持 source_verified）。

两条版本绝不能混为一谈：设备上读到的 protectionLevel 说明不了它来自哪个
AOSP 版本，任何声称它来自源码的记录都是伪造出处（D009）。风险规则的
`source_refs_json` 一律替换成设备观测记录——沿用 android-14 的 commit 引用
等于给 android-15 的规则安上 android-14 的出处。

调用顺序有讲究，由 build_device_rows 保证：
  1. 先 permissions / vhal_properties / dangerous_apis；
  2. risk_rules 最后——它的行带指向上面三张表的外键。
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

DEVICE_VERSION = "15"
SOURCE_VERSION = "14"


def insert_device_permissions(dst: sqlite3.Connection, calibration: Path) -> int:
    rows = [json.loads(line) for line in calibration.read_text(encoding="utf-8").splitlines() if line.strip()]
    payload = []
    for row in rows:
        provenance = row["provenance"]
        payload.append((
            row["permission_name"], DEVICE_VERSION,
            row["protection_level_raw"],
            # protection_level_value stays NULL: PM reports a name, not the numeric
            # flag set, and the project forbids hardcoding flag values.
            None,
            row["permission_group"], row["description"],
            "pending",
            "[]",
            json.dumps([{
                "kind": "device_observation",
                "method": provenance["source"],
                "device_api_level": provenance["device"].get("ro.build.version.sdk"),
                "device_fingerprint": provenance["device"].get("ro.build.fingerprint"),
                "source_file_sha256": provenance["source_file_sha256"],
                "defining_package": row["defining_package"],
            }], ensure_ascii=False),
            f"设备实测（非源码抽取）。label={row['label']!r}",
        ))
    dst.executemany(
        "INSERT INTO permissions (permission_name, android_version, protection_level_raw,"
        " protection_level_value, permission_group, description, definition_status,"
        " source_refs_json, device_calibration_json, notes)"
        " VALUES (?,?,?,?,?,?,?,?,?,?)",
        payload,
    )
    return len(payload)


def insert_device_properties(dst: sqlite3.Connection, device_ids: Path, provenance: dict) -> int:
    """Carry the android-14 attribute set forward only where the device confirms the ID."""
    ids = json.loads(device_ids.read_text(encoding="utf-8"))
    source_rows = dst.execute(
        "SELECT property_key, property_name, property_id, value_type, access_mode, change_mode,"
        " area_type, unit, data_category FROM vhal_properties WHERE android_version = ?",
        (SOURCE_VERSION,),
    ).fetchall()

    payload, unverified = [], []
    for key, name, pid, vtype, access, change, area, unit, category in source_rows:
        if ids.get(name) != pid:
            unverified.append(name)
            continue
        payload.append((
            key, DEVICE_VERSION, name, pid, vtype, access, change, area, unit, category,
            None, None, "pending", "[]",
            json.dumps([{
                "kind": "device_observation",
                "method": "dexdump android.car.VehiclePropertyIds from /system/framework/android.car.jar",
                "device_api_level": provenance.get("ro.build.version.sdk"),
                "device_fingerprint": provenance.get("ro.build.fingerprint"),
                "observed_value": ids[name],
            }], ensure_ascii=False),
            "属性 ID 经设备 dex 常量表核对一致；其余字段沿用源码抽取值，未从 android-15 源码重新抽取。",
        ))
    dst.executemany(
        "INSERT INTO vhal_properties (property_key, android_version, property_name, property_id,"
        " value_type, access_mode, change_mode, area_type, unit, data_category,"
        " read_permission_expr_json, write_permission_expr_json, definition_status,"
        " source_refs_json, device_calibration_json, notes) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        payload,
    )
    if unverified:
        raise ValueError("Device does not confirm these property IDs: " + ", ".join(unverified))
    return len(payload)


def insert_device_apis(dst: sqlite3.Connection, signatures_path: Path, provenance: dict) -> int:
    """Same rule as properties: carry the android-14 attributes forward only where the
    device confirms the exact JVM signature is still present."""
    signatures = set(json.loads(signatures_path.read_text(encoding="utf-8"))["signatures"])
    source_rows = dst.execute(
        "SELECT api_key, class_name, method_name, jvm_descriptor, api_role, property_arg_index,"
        " observation_spec_json, permission_expr_json FROM dangerous_apis WHERE android_version = ?",
        (SOURCE_VERSION,),
    ).fetchall()

    payload, missing = [], []
    for key, cls, method, desc, role, arg_index, spec, perm in source_rows:
        if (method + desc) not in signatures:
            missing.append(method + desc)
            continue
        payload.append((
            key, DEVICE_VERSION, cls, method, desc, role, arg_index, spec, perm,
            "pending", "[]",
            json.dumps([{
                "kind": "device_observation",
                "method": "dexdump android.car.hardware.property.CarPropertyManager from "
                          "/system/framework/android.car.jar",
                "device_api_level": provenance.get("ro.build.version.sdk"),
                "device_fingerprint": provenance.get("ro.build.fingerprint"),
                "observed_signature": method + desc,
            }], ensure_ascii=False),
            "方法签名经设备 dex 核对存在；其余字段沿用源码抽取值，未从 android-15 源码重新抽取。",
        ))
    dst.executemany(
        "INSERT INTO dangerous_apis (api_key, android_version, class_name, method_name,"
        " jvm_descriptor, api_role, property_arg_index, observation_spec_json,"
        " permission_expr_json, definition_status, source_refs_json, device_calibration_json,"
        " notes) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
        payload,
    )
    if missing:
        raise ValueError("Device does not expose these signatures: " + ", ".join(missing))
    return len(payload)


def insert_device_rules(dst: sqlite3.Connection, provenance: dict) -> int:
    """Mirror the policy drafts onto android-15 with device-sourced provenance.

    What carries over and what does not is the whole point:

    * basis_refs_json DOES carry over unchanged. It points at POLICY.md - project
      policy, which is about what V-Scanner chooses to flag, not about any AOSP
      release. The necessity-review predicate means the same thing on both versions.
    * source_refs_json does NOT carry over. It cites AOSP android-14 commits and line
      numbers for the property and signature definitions. Reusing it under version 15
      would assert android-14 provenance for an android-15 rule, so it is replaced
      with what was actually observed on the device.
    """
    columns = [r[1] for r in dst.execute("PRAGMA table_info(risk_rules)")]
    source_rows = dst.execute(
        f"SELECT {','.join(columns)} FROM risk_rules WHERE android_version = ? "
        "ORDER BY rule_id", (SOURCE_VERSION,)
    ).fetchall()
    if not source_rows:
        raise ValueError("No android-14 rules to mirror")

    payload = []
    for row in source_rows:
        rule = dict(zip(columns, row))
        observed: dict = {}
        observed["permission"] = rule["permission_name"] and {
            "name": rule["permission_name"],
            "protection_level": dst.execute(
                "SELECT protection_level_raw FROM permissions WHERE permission_name = ?"
                " AND android_version = ?", (rule["permission_name"], DEVICE_VERSION)).fetchone()[0],
        }
        if rule["property_key"]:
            observed["property"] = {
                "key": rule["property_key"],
                "id": dst.execute(
                    "SELECT property_id FROM vhal_properties WHERE property_key = ?"
                    " AND android_version = ?", (rule["property_key"], DEVICE_VERSION)).fetchone()[0],
                "verified_against": "device VehiclePropertyIds dex constants",
            }
        if rule["api_key"]:
            observed["api"] = {
                "key": rule["api_key"],
                "verified_against": "device CarPropertyManager dex signatures",
            }

        source_refs = json.dumps([{
            "kind": "device_observation",
            "device_api_level": provenance.get("ro.build.version.sdk"),
            "device_fingerprint": provenance.get("ro.build.fingerprint"),
            "observed": observed,
            "captured_from": [
                "adb shell pm list permissions -f -g",
                "dexdump /system/framework/android.car.jar",
            ],
            "not_carried_over": "AOSP android-14 source refs: they describe a different "
                                "release and would misattribute this rule's provenance",
        }], ensure_ascii=False)

        payload.append((
            rule["rule_id"], DEVICE_VERSION, rule["rule_revision"], rule["title"],
            rule["rule_type"], rule["severity"], rule["permission_name"],
            rule["property_key"], rule["api_key"], rule["evaluator_version"],
            rule["condition_json"], rule["evidence_requirements_json"], rule["window_ms"],
            rule["conclusion_level"], source_refs, rule["basis_refs_json"],
            0,  # still disabled: D005 stands until an evaluator exists
            "DISABLED draft, mirrored onto android-15. Project policy (POLICY.md) is "
            "version-independent and carried over unchanged; source refs were replaced with "
            "device observations because the android-14 AOSP citations do not describe this "
            "release. No evaluator implemented. Not a legal verdict.",
        ))

    dst.executemany(
        "INSERT INTO risk_rules (rule_id, android_version, rule_revision, title, rule_type,"
        " severity, permission_name, property_key, api_key, evaluator_version, condition_json,"
        " evidence_requirements_json, window_ms, conclusion_level, source_refs_json,"
        " basis_refs_json, enabled, notes) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        payload,
    )
    return len(payload)


def build_device_rows(dst: sqlite3.Connection, calibration: Path, property_ids: Path,
                      cpm_signatures: Path, device_facts: dict) -> dict:
    """构造全部 android-15 设备观测行，返回各表行数。

    risk_rules 必须最后构造——它的行带指向上面三张表的外键。
    """
    return {
        "permissions": insert_device_permissions(dst, calibration),
        "vhal_properties": insert_device_properties(dst, property_ids, device_facts),
        "dangerous_apis": insert_device_apis(dst, cpm_signatures, device_facts),
        # Last on purpose: the rule rows carry foreign keys into the three tables above.
        "risk_rules": insert_device_rules(dst, device_facts),
    }
