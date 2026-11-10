#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""L2 `observed_surface` 的批量汇总（只读统计，不出结论）。

仅用于授权测试（自有设备 / 公开第三方样本的授权评估）。

两种用法：
  1) 现扫一批 APK：`--apk-dir output/xxx/apk --out output/_surface-batch`；
  2) 汇总已有产物：`--from output/thirdparty-round2-20260909`（递归找 `observed_surface.json`，
     不重扫、不重新裁决，只把既有事实摊平）。

三条硬约束（对应"不许把统计讲成结论"）：
  * **每行都能追回单样本**：`file` 是那一份 `observed_surface.json` 的绝对路径，
    `apk_sha256` 是样本身份；行里不放任何跨样本量。
  * **汇总层不做平均、不做加权**：池级只有「逐样本分母相加」一种算法，
    比例一律由相加后的分母现算，并标注"相加的是分母不是比例"。
  * 同一 APK（sha256 相同）只计一次，重复的记在 `duplicates` 里，不静默吞掉。

池级数字与 `MOBILE_SAMPLE_POOL_STRUCTURE_20261110.md` §8.1 的 719 **不是同一口径**：
§8.1 是跨样本去重并集（同一签名只算一次），本文件是逐样本分母之和（同一签名在 N 个
样本出现就计 N 次）。两者都成立，但不能互相比较大小——输出里写死了这条。
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from mobile.tools import observed_surface  # noqa: E402
from mobile.tools.dex_callgraph import apk_sha256  # noqa: E402

FILE = "observed_surface.json"
SUMMARY = "surface-batch.json"
LIMITATIONS = [
    "池级分母是逐样本分母相加，不是跨样本去重并集；不能与 §8.1 的 719 / 11,778 比较大小。",
    "每样本的分母只含它自己调到的敏感签名，样本少了某一类 API 不代表该类不在 Android 里。",
    "不可用样本（no_dex / 目标集校验失败）不进分母，但会单列在 unavailable 里，不静默丢弃。",
    "本统计不出结论：不进四桶、不产候选、不折算检出率。",
]


def _denoms(surf: dict) -> tuple[dict, dict]:
    dens = surf.get("denominators") or {}
    sig, call = dens.get("signature_surface") or {}, dens.get("call_points") or {}
    return sig, call


def row_from_doc(doc: dict, file: Path, apk: str | None = None) -> dict:
    """把一份 observed_surface.json 摊平成汇总表的一行（单样本口径）。"""
    surf = doc.get("observed_surface") or {}
    sample = doc.get("sample") or {}
    ts = doc.get("target_set") or {}
    sig, call = _denoms(surf)
    inv = surf.get("invisible") or {}
    row = {
        "apk": apk or sample.get("apk"),
        "apk_sha256": sample.get("apk_sha256"),
        "file": str(file),
        "status": surf.get("status"),
        "reason": surf.get("error"),
        "target_set_sha256": ts.get("sha256"),
        "signature_surface": {k: sig.get(k) for k in ("total", "registered", "unregistered")},
        "call_points": {k: call.get(k) for k in ("total", "registered", "unregistered")},
        # 单样本比例：这是该样本自己的数，不是跨样本平均，允许出现在行里
        "invisible_share": {"signature": inv.get("signature_share"),
                            "call_point": inv.get("call_point_share")},
    }
    if row["status"] != "ok":
        row["signature_surface"] = None
        row["call_points"] = None
        row["invisible_share"] = None
    return row


def aggregate(rows: list[dict]) -> dict:
    """纯函数：只把逐样本**分母**相加，比例由相加后的分母现算。不做平均/加权。"""
    seen: dict[str, str] = {}
    rows_out, duplicates = [], []
    for row in rows:
        sha = row.get("apk_sha256")
        if sha and sha in seen:
            duplicates.append({"apk_sha256": sha, "kept": seen[sha], "dropped": row.get("file")})
            continue
        if sha:
            seen[sha] = row.get("file") or ""
        rows_out.append(row)
    ok = [r for r in rows_out if r.get("status") == "ok"]
    sig_t = sum(r["signature_surface"]["total"] for r in ok)
    sig_r = sum(r["signature_surface"]["registered"] for r in ok)
    call_t = sum(r["call_points"]["total"] for r in ok)
    call_r = sum(r["call_points"]["registered"] for r in ok)
    return {
        "samples_total": len(rows_out),
        "samples_counted": len(ok),
        "samples_unavailable": [
            {"apk": r.get("apk"), "apk_sha256": r.get("apk_sha256"),
             "status": r.get("status"), "reason": r.get("reason")} for r in rows_out
            if r.get("status") != "ok"],
        "rows": rows_out,
        "duplicates": duplicates,
        "pool": {
            "method": "sum_of_per_sample_denominators",
            "summed_denominators": {
                "signature_surface": {"total": sig_t, "registered": sig_r,
                                      "unregistered": sig_t - sig_r},
                "call_points": {"total": call_t, "registered": call_r,
                                "unregistered": call_t - call_r},
            },
            "invisible_share_from_summed": {
                "signature": round((sig_t - sig_r) / sig_t, 4) if sig_t else None,
                "call_point": round((call_t - call_r) / call_t, 4) if call_t else None,
            },
            "note": "相加的是**分母**不是比例：池级比例 = 相加后的登记 / 相加后的分母，"
                    "不是逐样本比例的平均，也没有任何加权。",
        },
    }


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def scan_one(apk: Path, out_root: Path, rules_db: Path, version: str,
             reuse: bool) -> dict:
    """扫一个 APK（或复用已有产物），返回汇总行。"""
    sample_out = out_root / apk.stem
    target = sample_out / FILE
    if reuse and target.exists():
        return row_from_doc(_load(target), target, apk.name)
    doc = observed_surface.run(apk, sample_out, rules_db, version)
    return row_from_doc(doc, target, apk.name)


def _print_table(rows: list[dict]) -> None:
    print(f"{'status':<12}{'签名面 登记/总':>20}{'调用点 登记/总':>20}  apk")
    for r in rows:
        sig, call = r.get("signature_surface"), r.get("call_points")
        left = f"{sig['registered']}/{sig['total']}" if sig else "-"
        right = f"{call['registered']}/{call['total']}" if call else "-"
        print(f"{str(r['status']):<12}{left:>20}{right:>20}  {r['apk']}")


def main() -> int:
    ap = argparse.ArgumentParser(description="L2 observed_surface 批量汇总（只读）")
    ap.add_argument("--apk", action="append", default=[], help="可重复")
    ap.add_argument("--apk-dir", help="递归扫描该目录下的 *.apk")
    ap.add_argument("--from", dest="from_dir",
                    help="只汇总已有 observed_surface.json（不重扫）")
    ap.add_argument("--out", required=True, help="输出目录")
    ap.add_argument("--rules-db", default=str(observed_surface.RULES_DB))
    ap.add_argument("--version", default=observed_surface.DEFAULT_VERSION)
    ap.add_argument("--reuse", action="store_true", help="已有单样本产物时直接复用")
    args = ap.parse_args()

    out = Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    rules_db = Path(args.rules_db)
    rows: list[dict] = []
    if args.from_dir:
        root = Path(args.from_dir).resolve()
        for f in sorted(root.rglob(FILE)):
            rows.append(row_from_doc(_load(f), f))
        mode = "from_existing"
    else:
        apks = [Path(p) for p in args.apk]
        if args.apk_dir:
            apks += sorted(Path(args.apk_dir).resolve().rglob("*.apk"))
        if not apks:
            print("[fatal] 需要 --apk / --apk-dir / --from 三者之一", file=sys.stderr)
            return 2
        for apk in apks:
            rows.append(scan_one(apk, out, rules_db, args.version, args.reuse))
        mode = "scan"

    summary = {"generated_by": "mobile/tools/surface_batch.py", "mode": mode,
               "scope": "每样本各自口径；池级只相加分母", "not_merged_with":
               "四桶统计（reachability）与 L1 结论：并列输出，不合并、不加权",
               "limitations": LIMITATIONS, **aggregate(rows)}
    (out / SUMMARY).write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n",
                               encoding="utf-8")
    _print_table(summary["rows"])
    pool = summary["pool"]["summed_denominators"]
    print(f"\n样本 {summary['samples_counted']}/{summary['samples_total']} 有数；"
          f"池级分母之和：签名面 {pool['signature_surface']['registered']}/"
          f"{pool['signature_surface']['total']}，调用点 {pool['call_points']['registered']}/"
          f"{pool['call_points']['total']}")
    print("相加的是分母不是比例；不可用样本 "
          f"{len(summary['samples_unavailable'])} 个已单列。汇总见 {out / SUMMARY}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
