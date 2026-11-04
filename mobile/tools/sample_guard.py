#!/usr/bin/env python3
"""样本 runner 的设备状态守卫：改前记原值、只删自己插入的行、还原后回读比对。

仅用于授权测试（自有模拟器）。三条边界写死在这里：

1. 定位开关 / mock_location 的"原值"必须先读；读不到就记 null，不假装知道；
2. **绝不 `pm clear` 任何 provider**——联系人/通话记录只在基线之上插入自己的一行，
   清理时只删这一行的 `_id`，删完回读 `_id` 集合必须回到基线；
3. 还原不是"发过命令"，是"回读到的值等于原值"；不等就返回 ok=False，由调用方
   写成 cleanup 失败。

实测（2026-11-04，generic Android 17 / user 0）：`content insert` **成功但不打印 URI**，
所以"自己插入的行"用插入前后的 `_id` 差集识别，不依赖命令输出。
"""
from __future__ import annotations

import re
import time

CONTACTS = "content://com.android.contacts/raw_contacts"
CONTACT_DATA = "content://com.android.contacts/data"
CALL_LOG = "content://call_log/calls"


def list_ids(device, uri: str, user: str) -> list:
    """provider 里的 `_id` 集合（升序）。空结果时 content 只打印 No result found。"""
    text = device.sh("content", "query", "--user", user, "--uri", uri, "--projection", "_id")
    return sorted({int(value) for value in re.findall(r"_id=(\d+)", text)})


def _new_id(device, uri: str, user: str, before: list, timeout_s: float = 3.0) -> int:
    """插入后等 provider 落盘再取差集：该镜像 insert 不打 URI，且写入不是即时的。"""
    deadline = time.monotonic() + timeout_s
    while True:
        added = sorted(set(list_ids(device, uri, user)) - set(before))
        if len(added) == 1:
            return added[0]
        if len(added) > 1:
            raise RuntimeError(f"{uri} 插入后新增 {added}，无法确定哪一行是自己插入的")
        if time.monotonic() >= deadline:
            raise RuntimeError(f"{uri} 插入后没有新增行，无法确认写入")
        time.sleep(0.4)


def snapshot(device, user: str) -> dict:
    """改前原值。读不到就记 null（还原时按 null 处理，不假装知道）。"""
    contacts, calls = list_ids(device, CONTACTS, user), list_ids(device, CALL_LOG, user)
    return {"location_enabled": device.sh("cmd", "location", "is-location-enabled") or "true",
            "mock_location": device.sh("settings", "get", "secure", "mock_location"),
            "contacts_ids": contacts, "call_log_ids": calls}


def restore_settings(device, original: dict) -> dict:
    """还原 + 回读；返回逐项比对结果。"""
    checks = {}
    expected = original.get("location_enabled") or "true"
    device.sh("cmd", "location", "set-location-enabled", expected)
    observed = device.sh("cmd", "location", "is-location-enabled")
    checks["location_enabled"] = {"expected": expected, "observed": observed,
                                  "ok": observed == expected}
    mock = original.get("mock_location")
    if mock in (None, "", "null"):
        device.sh("settings", "delete", "secure", "mock_location")
        expected_mock = "null"
    else:
        device.sh("settings", "put", "secure", "mock_location", str(mock))
        expected_mock = str(mock)
    observed = device.sh("settings", "get", "secure", "mock_location")
    checks["mock_location"] = {"expected": expected_mock, "observed": observed,
                               "ok": observed == expected_mock}
    return checks


def seed_rows(device, args, user: str, journal, sample: str) -> list:
    seeds = []
    if "contact" in args.seed:
        before = list_ids(device, CONTACTS, user)
        device.sh("content", "insert", "--user", user, "--uri", CONTACTS,
                  "--bind", "account_name:s:vscan-runtime",
                  "--bind", "account_type:s:vscan-runtime")
        row_id = _new_id(device, CONTACTS, user, before)
        device.sh("content", "insert", "--user", user, "--uri", CONTACT_DATA,
                  "--bind", f"raw_contact_id:i:{row_id}",
                  "--bind", "mimetype:s:vnd.android.cursor.item/name",
                  "--bind", "data1:s:VScan-Alice")
        seeds.append({"kind": "contact", "uri": CONTACTS, "id": row_id,
                      "before": len(before), "before_ids": before})
        journal.line(sample, "content insert",
                     f"raw_contacts _id={row_id}（基线 {len(before)} 行）", "已写入")
    if "call-log" in args.seed:
        before = list_ids(device, CALL_LOG, user)
        device.sh("content", "insert", "--user", user, "--uri", CALL_LOG,
                  "--bind", "number:s:10086", "--bind", "name:s:VScan-Alice",
                  "--bind", "date:l:1793700000000", "--bind", "duration:i:0",
                  "--bind", "type:i:1", "--bind", "new:i:1")
        row_id = _new_id(device, CALL_LOG, user, before)
        seeds.append({"kind": "call-log", "uri": CALL_LOG, "id": row_id,
                      "before": len(before), "before_ids": before})
        journal.line(sample, "content insert",
                     f"call_log/calls _id={row_id}（基线 {len(before)} 行）", "已写入")
    return seeds


def revert_seeds(device, seeds: list, user: str, journal, sample: str) -> list:
    """只删本次插入的 id；删后回读 `_id` 集合必须回到基线，残留要写进证据。"""
    checks = []
    for item in reversed(seeds):
        if item["kind"] == "contact":
            device.sh("content", "delete", "--user", user, "--uri", CONTACT_DATA,
                      "--where", f"raw_contact_id={item['id']}")
        # 实测该镜像不支持 content://.../<id> 的 delete（UnsupportedOperationException），
        # 必须走 --where；行数回读仍能证明是否真的删掉。
        device.sh("content", "delete", "--user", user, "--uri", item["uri"],
                  "--where", f"_id={item['id']}")
        remaining = list_ids(device, item["uri"], user)
        residual = [value for value in remaining if value not in item["before_ids"]]
        check = {"kind": item["kind"], "id": item["id"], "baseline": item["before"],
                 "observed": len(remaining), "residual_ids": residual,
                 "ok": len(remaining) == item["before"]}
        checks.append(check)
        journal.line(sample, "content delete",
                     f"{item['kind']} _id={item['id']} → {len(remaining)} 行"
                     f"（基线 {item['before']}，残留 {residual}）",
                     "ok" if check["ok"] else "残留")
    return checks


def restore_appops(device, recorded: dict) -> list:
    """app-op 也要还原成原 mode，并回读确认。"""
    checks = []
    for permission, item in recorded.items():
        before = item.get("before") or ""
        match = re.search(r"Uid mode:\s*(\w+)", before)
        mode = match[1] if match else "default"
        device.sh("appops", "set", "--uid", item["package"], permission, mode)
        observed = device.sh("appops", "get", "--uid", item["package"], permission)
        checks.append({"permission": permission, "expected": mode, "observed": observed,
                       "ok": f"Uid mode: {mode}" in observed})
    return checks
