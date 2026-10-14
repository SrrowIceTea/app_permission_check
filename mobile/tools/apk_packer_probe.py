#!/usr/bin/env python3
"""APK 加固（壳）特征探测 —— 只需标准库，不依赖 APKiD / apktool。

仅用于授权测试（已获授权的样本与设备）。

为什么需要它：本工程的能力边界里写着「加固壳不在覆盖内」，但**报告不会因此提示读者**。
一个加壳样本的自解密 dex、运行时动态加载，会让静态结论与 Hook 观察同时失真，
而报告看起来和干净样本一模一样——这违反「失败可诊断」。

本工具不是 APKiD 的替代品，也不给「已加壳」这种定性结论：它只在 zip 条目名里匹配
**公开的加固厂商特征**（native 库名 / 资产名），命中即标 `suspected_packed`，
交由报告以「受限」措辞如实标注。未命中不等于未加壳（自研壳、字符串混淆的壳都测不到）——
这条边界写进返回值的 note，不允许下游当成「干净」。

用法：
    python apk_packer_probe.py --apk path/to/app.apk [--out probe.json]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import zipfile
from pathlib import Path

# 特征表：子串匹配 zip 条目路径。来源 = 各加固厂商公开的 so/资产命名（社区与安全厂商报告通用）。
# 只写**足够独特**的名字（如 libjiagu / libDexHelper），通用名（libexec.so 之类）单独标注，
# 因为它们也可能是 App 自己的库，误报代价由 suspected（而非 confirmed）承担。
PACKER_MARKERS: list[tuple[str, str]] = [
    ("libjiagu", "360加固"),
    ("libjiagu_art", "360加固"),        # 更细的子串先列出，便于报告定位
    ("libshella", "腾讯乐固"),
    ("libshellx", "腾讯乐固"),
    ("libtup.so", "腾讯乐固"),
    ("libtosprotection", "腾讯乐固"),
    ("libDexHelper", "梆梆安全"),
    ("libSecShell", "梆梆安全"),
    ("libsecpreload", "梆梆安全"),
    ("libmobisec", "阿里聚安全"),
    ("libsgmain", "阿里聚安全"),
    ("libsgsecuritybody", "阿里聚安全"),
    ("libijiami", "爱加密"),
    ("libexecmain.so", "加固通用（壳主逻辑）"),
    ("libchaosvmp", "娜迦"),
    ("libprotectClass", "娜迦"),
    ("libnesec", "网易易盾"),
    ("libnqshield", "网秦"),
    ("libapkprotect", "APKProtect"),
    ("ijiami.dat", "爱加密"),
    ("libexec.so", "加固通用（可能是普通 so，低置信）"),
]


def probe(apk: Path) -> dict:
    """只读 zip 目录，不解压、不执行任何样本代码。"""
    data = apk.read_bytes()
    with zipfile.ZipFile(apk) as z:
        names = z.namelist()

    lower = [(n, n.lower()) for n in names]
    hits = []
    for needle, vendor in PACKER_MARKERS:
        key = needle.lower()
        for raw, low in lower:
            if key in low:
                hits.append({"marker": needle, "packer": vendor, "entry": raw})
                break

    native_libs = sorted({n for n in names if n.startswith("lib/") and n.endswith(".so")})
    dex = sorted(n for n in names if n.endswith(".dex") and "/" not in n)
    return {
        "apk": str(apk),
        "apk_sha256": hashlib.sha256(data).hexdigest(),
        "apk_bytes": len(data),
        "entry_count": len(names),
        "top_level_dex_count": len(dex),
        "native_lib_count": len(native_libs),
        "native_libs_sample": native_libs[:20],
        "matched_markers": hits,
        "packer_suspected": bool(hits),
        "note": ("命中加固厂商特征，样本疑似加壳：自解密 dex / 运行时动态加载会让静态结论与"
                 "Hook 观察同时失真，结论须标注受限。" if hits else
                 "未命中任何已知加固特征。**这不等于未加壳**——自研壳与字符串混淆的壳测不到；"
                 "本探测只作诚实性提示，不作定性依据。"),
    }


def gap_note(result: dict) -> str | None:
    """给证据包 gaps 用的一句话（未命中时返回 None，不制造噪音）。"""
    if not result.get("packer_suspected"):
        return None
    marks = "、".join(sorted({f"{h['packer']}({h['entry']})" for h in result["matched_markers"]}))
    return (f"样本疑似加壳：命中加固特征 {marks}。加固样本会自解密 dex / 运行时动态加载，"
            "**静态结论与运行时 Hook 观察均可能受限**；不得据此断言「未收集」。"
            f"（apk sha256={result['apk_sha256'][:16]}）")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--apk", required=True)
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    apk = Path(args.apk)
    if not apk.is_file():
        sys.exit(f"[fatal] APK 不存在: {apk}")
    try:
        result = probe(apk)
    except zipfile.BadZipFile:
        sys.exit(f"[fatal] 不是合法 zip/APK: {apk}")

    if args.out:
        Path(args.out).write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n",
                                  encoding="utf-8")
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
