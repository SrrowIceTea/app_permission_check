#!/usr/bin/env python3
"""Parse saved `pm list permissions -f -g` output into structured, traceable facts.

These records are DEVICE OBSERVATIONS, not source extractions. The distinction is
the point: a protection level read off a running device says nothing about which
AOSP release declared it, and nothing here may be labelled source_verified.

The earlier Phase 0 attempt used `pm list permissions -d -g`, which filters to the
dangerous group and is why only two car permissions were seen. `-f` is what makes
protection levels visible; omitting it yields names without levels.

Never invokes adb. Feed it output captured separately.

Usage:
  python python/extract_device_calibration.py --pm-output saved.txt \
      --device-facts device.json --out calibration/permissions.jsonl
  python python/extract_device_calibration.py --pm-output saved.txt \
      --device-facts device.json --prefix android.permission. \
      --names android.permission.RECORD_AUDIO --out calibration/general.jsonl
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

GROUP_RE = re.compile(r"^\+ group:(\S+)\s*$")
PERM_RE = re.compile(r"^\s*\+ permission:(\S+)\s*$")
ATTR_RE = re.compile(r"^\s+([A-Za-z_]+):(.*)$")
ATTRS = ("package", "label", "description", "protectionLevel")


def parse(text: str) -> list[dict]:
    """Walk the grouped, indented pm output. Group attributes precede any permission."""
    records: list[dict] = []
    group: str | None = None
    current: dict | None = None

    for raw in text.splitlines():
        line = raw.rstrip("\r")
        if not line.strip():
            continue
        match = GROUP_RE.match(line)
        if match:
            group, current = match.group(1), None
            continue
        match = PERM_RE.match(line)
        if match:
            current = {"permission_name": match.group(1), "permission_group": group}
            records.append(current)
            continue
        match = ATTR_RE.match(line)
        if match and current is not None:
            key, value = match.group(1), match.group(2)
            if key in ATTRS:
                current[key] = None if value == "null" else value
    return records


def sha256_of(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def collect(pm_output: Path, device_facts: Path | None, prefix: str,
            names: tuple[str, ...] = ()) -> tuple[list[dict], dict]:
    text = pm_output.read_text(encoding="utf-8-sig")
    parsed = parse(text)
    if not parsed:
        raise ValueError("No permission blocks parsed; check the saved output format")

    device = json.loads(device_facts.read_text(encoding="utf-8")) if device_facts else {}
    provenance = {
        "source": "adb shell pm list permissions -f -g",
        "source_file_sha256": sha256_of(pm_output),
        "extraction": "device_observation",
        "device": device,
    }

    selected = [r for r in parsed if r["permission_name"].startswith(prefix)
                and (not names or r["permission_name"] in names)]
    if names:
        missing = sorted(set(names) - {r["permission_name"] for r in selected})
        if missing:
            raise ValueError("Requested permissions not found: " + ", ".join(missing))
    seen: dict[str, dict] = {}
    conflicts: list[dict] = []
    for record in selected:
        name = record["permission_name"]
        if name in seen:
            # Two definitions of one name is a real finding, not something to
            # silently collapse - keep both and report it.
            if seen[name].get("protectionLevel") != record.get("protectionLevel"):
                conflicts.append({
                    "permission_name": name,
                    "first": seen[name].get("protectionLevel"),
                    "second": record.get("protectionLevel"),
                })
            continue
        seen[name] = record

    facts = []
    for name in sorted(seen):
        record = seen[name]
        facts.append({
            "permission_name": name,
            "protection_level_raw": record.get("protectionLevel"),
            "permission_group": record.get("permission_group"),
            "label": record.get("label"),
            "description": record.get("description"),
            "defining_package": record.get("package"),
            "definition_status": "pending",
            "provenance": provenance,
        })

    summary = {
        "parsed_blocks": len(parsed),
        "selected": len(facts),
        "prefix": prefix,
        "names": sorted(names),
        "without_protection_level": sorted(
            f["permission_name"] for f in facts if not f["protection_level_raw"]
        ),
        "conflicts": conflicts,
        "provenance": provenance,
    }
    return facts, summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pm-output", type=Path, required=True)
    parser.add_argument("--device-facts", type=Path)
    parser.add_argument("--prefix", default="android.car.")
    parser.add_argument("--names", default="",
                        help="逗号分隔的精确权限名；留空则按 --prefix 前缀选择")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--summary", type=Path, required=True)
    args = parser.parse_args()

    for target in (args.out, args.summary):
        if target.exists():
            print(json.dumps({"status": "failed", "message": f"Refusing to overwrite {target}"}),
                  file=sys.stderr)
            return 1
    names = tuple(n.strip() for n in args.names.split(",") if n.strip())
    try:
        facts, summary = collect(args.pm_output, args.device_facts, args.prefix, names)
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        print(json.dumps({"status": "failed", "error_type": type(exc).__name__,
                          "message": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 1

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("x", encoding="utf-8") as handle:
        for fact in facts:
            handle.write(json.dumps(fact, ensure_ascii=False, sort_keys=True) + "\n")
    args.summary.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n",
                            encoding="utf-8")

    print(json.dumps({
        "status": "ok",
        "records": len(facts),
        "without_protection_level": len(summary["without_protection_level"]),
        "conflicts": len(summary["conflicts"]),
    }, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
