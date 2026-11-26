#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""静态侧 SDK 库指纹**侧车**：从已有 dexfacts.json 派生 SDK 候选，不改默认结论。

仅用于授权测试（自有设备与自有 APK）/ For authorized testing on owned devices and APKs only.

设计约束（DECISIONS D712 / VEHICLE_ONLY §4 第二三阶段）：
- 这是 sidecar：默认静态分析不调用它，结论层不读它。它只把"APK 里有哪些 SDK 类"
  落成一个可复核的伴随文件，供人工/后续拼接使用。
- 复用 core/evidence/sdk_registry.SDK_PACKAGES 作为**唯一**前缀依据，不另建名单。
- 前缀命中只是候选;不证明 SDK 本轮采集,也不证明版本。R8 重命名/裁剪会漏认,
  `gaps` 非空时不得写成"没有 SDK"。
- 指纹是"该类集合的确定性摘要",不是 LibScout 式版本指纹——没有 profile 库时
  绝不臆造版本。
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

from core.evidence.sdk_registry import SDK_PACKAGES

SCHEMA = 1
NOTE = ("包含 SDK ≠ SDK 在本次调用链出现 ≠ SDK 采集；本侧车不改变默认结论。")
LIMITATION = ("前缀匹配不是版本指纹；R8 重命名/裁剪/内联时召回不足，"
              "不据此断言不存在 SDK；无 profile 库时不产出版本。")


def _sorted_prefixes():
    return tuple(sorted(SDK_PACKAGES.items(), key=lambda kv: len(kv[0]), reverse=True))


def _digest_of(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _bytes_digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def build_sidecar(static_dir: Path, *, apk_digest: str | None = None) -> dict:
    """从 static 目录的 dexfacts.json（+可选 summary.json）生成侧车 dict。

    不修改任何输入文件；纯函数式，输出确定（相同输入 → 相同字节）。
    """
    static_dir = Path(static_dir)
    dexfacts_path = static_dir / "dexfacts.json"
    if not dexfacts_path.is_file():
        raise FileNotFoundError(f"dexfacts.json 不存在：{dexfacts_path}")
    raw_bytes = dexfacts_path.read_bytes()
    facts = json.loads(raw_bytes)
    classes = sorted({c for c in facts.get("classes", []) if isinstance(c, str)})
    dex_gaps = facts.get("gaps") or []

    if apk_digest is None:
        summary = static_dir / "summary.json"
        apk_digest = (json.loads(summary.read_text(encoding="utf-8")).get("digest")
                      if summary.is_file() else None)

    prefixes = _sorted_prefixes()
    buckets: dict[str, dict] = {}
    attributed = 0
    for cls in classes:
        low = cls.lower()
        matched = None
        for prefix, (name, source) in prefixes:
            if low == prefix or low.startswith(prefix + "."):
                matched = (name, source, prefix)
                break
        if matched is None:
            continue
        name, source, prefix = matched
        entry = buckets.setdefault(name, {"name": name, "maven": source,
            "matched_prefixes": set(), "classes": []})
        entry["matched_prefixes"].add(prefix)
        entry["classes"].append(cls)
        attributed += 1
    candidates = []
    for name in sorted(buckets):
        entry = buckets[name]
        cls_sorted = sorted(entry["classes"])
        fingerprint = _digest_of("\n".join(cls_sorted))
        candidates.append({
            "name": name,
            "source": entry["maven"],
            "matched_prefixes": sorted(entry["matched_prefixes"]),
            "class_count": len(cls_sorted),
            "sample_classes": cls_sorted[:8],
            "fingerprint_sha256": fingerprint,
            "confidence": "prefix_only",
            "gaps": [],
        })

    return {
        "schema": SCHEMA,
        "apk_digest": apk_digest,
        "source": {"dexfacts": dexfacts_path.name,
                   "dexfacts_sha256": _bytes_digest(raw_bytes)},
        "sdk_candidates": candidates,
        "attributed_class_count": attributed,
        "total_class_count": len(classes),
        "unattributed_class_count": len(classes) - attributed,
        "dex_gaps": dex_gaps,
        "note": NOTE,
        "limitation": LIMITATION,
    }


def write_sidecar(static_dir: Path, out: Path | None = None, *,
                  apk_digest: str | None = None) -> tuple[dict, Path]:
    static_dir = Path(static_dir)
    dest = Path(out) if out else static_dir / "sdk-fingerprint.json"
    sidecar = build_sidecar(static_dir, apk_digest=apk_digest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(sidecar, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8")
    return sidecar, dest


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="SDK 库指纹侧车（授权测试专用）")
    parser.add_argument("--static-dir", required=True, help="含 dexfacts.json 的静态产物目录")
    parser.add_argument("--out", help="输出路径，默认 <static-dir>/sdk-fingerprint.json")
    parser.add_argument("--apk-digest", help="显式 APK sha256；缺省时从 summary.json 读取")
    args = parser.parse_args(argv)
    try:
        sidecar, dest = write_sidecar(Path(args.static_dir),
            Path(args.out) if args.out else None, apk_digest=args.apk_digest)
    except (FileNotFoundError, ValueError) as error:
        print(f"sdk-fingerprint: {error}", file=sys.stderr)
        return 2
    print(f"写入 {dest}：{len(sidecar['sdk_candidates'])} 个 SDK 候选，"
          f"{sidecar['attributed_class_count']}/{sidecar['total_class_count']} 类归属候选，"
          f"{len(sidecar['dex_gaps'])} 个 dex 缺口")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
