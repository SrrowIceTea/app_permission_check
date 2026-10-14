#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""V-Scanner Phase 5 — 用 APK 自己的 dex 核对违规行号。

仅用于授权测试（自有设备与自有 APK）/ For authorized testing on owned devices and APKs only.

**为什么需要这一步**：`codeloc.py` 报出的 `VhalReader.kt:128` 来自运行时栈，
它**看起来**可信，但没有任何东西证明这个行号在真正装到设备上的那个 APK 里成立。
APK 一旦重新构建、代码一改，栈里的行号就是陈的——而陈行号**不会报错**，
它只会指到一个可能完全不相干的位置，让审计结论看起来有据可查。

所以这里把 dex 的 LineNumberTable 读出来，逐条核对：
「这个方法里真的有第 128 行吗？」核对不过就如实说不通过，不替它圆场。

**核对结果的四种状态**（都必须能区分——"查不到"和"查到了但不符"是两回事）：

  VERIFIED            类、方法、行号都在，且源文件名也对得上
  LINE_NOT_IN_METHOD  类与方法都在，但该方法没有这一行（最常见于 APK 已过期，或 R8 内联改写了归属）
  METHOD_NOT_FOUND    类在，方法名不在
  CLASS_NOT_FOUND     连类都没有（多半是 dex 取错了，或代码被混淆改名）
  DEX_UNAVAILABLE     根本没提供 APK/dex，未做核对——**不等于通过**

用法:
  python dexlines.py --apk ../phase2/target-app/app/build/outputs/apk/debug/app-debug.apk \\
      --verify logs/findings-located.jsonl --out logs/codeloc-verify.json --cache logs/dexlines.json
"""
from __future__ import annotations

import argparse
import hashlib
import os
import json
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

# 本机的 build-tools 好几个版本都带 dexdump，取版本号最大的那个。
# 路径解析统一走 core/sdk_paths（VSCAN_SDK → ANDROID_SDK_ROOT/ANDROID_HOME → PATH →
# 历史候选），不再在这里写死本机绝对路径（§8.2 B-4）。build_delivery.py 会显式传入。
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from core import sdk_paths  # noqa: E402

SDK_BUILD_TOOLS = sdk_paths.sdk_dir("build-tools")

CLASS_RE = re.compile(r"^  Class descriptor  : '(?P<desc>L[^;]+;)'")
SECTION_RE = re.compile(r"^  (?P<name>Static fields|Instance fields|Direct methods|Virtual methods)")
MEMBER_RE = re.compile(r"^    #\d+\s+: \(in ")
NAME_RE = re.compile(r"^      name\s+: '(?P<name>.*)'$")
TYPE_RE = re.compile(r"^      type\s+: '(?P<type>.*)'$")
POS_RE = re.compile(r"^\s+0x[0-9a-f]+ line=(?P<line>\d+)")
SRCFILE_RE = re.compile(r"^  source_file_idx\s+: \d+ \((?P<file>.*)\)$")


def find_dexdump() -> str:
    candidates = sorted(
        (d for d in SDK_BUILD_TOOLS.glob("*/dexdump.exe")),
        key=lambda p: [int(x) for x in re.findall(r"\d+", p.parent.name)] or [0],
    ) if SDK_BUILD_TOOLS.exists() else []
    if candidates:
        return str(candidates[-1])
    found = shutil.which("dexdump")
    if found:
        return found
    raise SystemExit(f"找不到 dexdump：{SDK_BUILD_TOOLS} 下没有，PATH 上也没有")


def parse_dexdump(text: str, index: dict) -> None:
    """把一个 dexdump 输出文件解析进 index。

    **必须跟踪 section**：dexdump 里字段和方法用的是同一种 `name : 'x'` 行，
    不区分 section 的话 `context`、`specs` 这些**字段名会被当成方法名**收录，
    于是核对时报"方法不存在"，看起来像 APK 对不上，实际是解析器认错了。
    """
    cls = None
    in_methods = False
    cur = None
    for raw in text.splitlines():
        match = CLASS_RE.match(raw)
        if match:
            cls = match.group("desc")[1:-1].replace("/", ".")
            index.setdefault(cls, {"file": None, "methods": {}})
            cur = None
            continue
        if cls is None:
            continue
        section = SECTION_RE.match(raw)
        if section:
            in_methods = section.group("name").endswith("methods")
            cur = None
            continue
        if MEMBER_RE.match(raw) and in_methods:
            cur = None
            continue
        name = NAME_RE.match(raw)
        if name and in_methods:
            cur = {"name": name.group("name"), "type": "", "lines": []}
            index[cls]["methods"].setdefault(name.group("name"), []).append(cur)
            continue
        if cur is not None:
            mtype = TYPE_RE.match(raw)
            if mtype:
                cur["type"] = mtype.group("type")
                continue
            pos = POS_RE.match(raw)
            if pos:
                cur["lines"].append(int(pos.group("line")))
                continue
        src = SRCFILE_RE.match(raw)
        if src:
            index[cls]["file"] = src.group("file")
    return


def build_index(apk: Path) -> dict:
    """从 APK 里抽出所有 classes*.dex 并建索引。"""
    dexdump = find_dexdump()
    index: dict = {}
    with tempfile.TemporaryDirectory() as tmp:
        tmpdir = Path(tmp)
        with zipfile.ZipFile(apk) as zf:
            dexes = sorted(n for n in zf.namelist()
                           if re.match(r"classes\d*\.dex$", n))
            if not dexes:
                raise SystemExit(f"{apk} 里没有 classes*.dex")
            zf.extractall(tmpdir, members=dexes)
        for dex in dexes:
            proc = subprocess.run([dexdump, "-d", str(tmpdir / dex)],
                                  capture_output=True, text=True,
                                  encoding="utf-8", errors="replace")
            if proc.returncode != 0 or "Opened" not in proc.stdout:
                raise SystemExit(f"dexdump 失败（{dex}）: {proc.stderr[:400]}")
            parse_dexdump(proc.stdout, index)
    return {c: {"file": v["file"],
                "methods": {m: [{"type": o["type"], "lines": sorted(set(o["lines"]))}
                                for o in ov] for m, ov in v["methods"].items()}}
            for c, v in index.items()}


def verify(index: dict | None, cls: str | None, method: str | None,
           file: str | None, line: int | None) -> dict:
    """核对一条代码位置。**信息不全就说不全，不判通过。**"""
    if index is None:
        return {"status": "DEX_UNAVAILABLE", "detail": "未提供 APK/dex，本行号**未经核对**"}
    if not cls or not method or not line:
        return {"status": "INCOMPLETE", "detail": "该位置本身就没有类/方法/行号可取"}
    entry = index.get(cls)
    if entry is None:
        return {"status": "CLASS_NOT_FOUND",
                "detail": f"dex 里没有 {cls}（代码被改名，或 APK 与抓包时不是同一个）"}
    overloads = entry["methods"].get(method)
    if not overloads:
        return {"status": "METHOD_NOT_FOUND",
                "detail": f"{cls} 里没有名为 {method} 的方法"}
    hits = [o for o in overloads if line in o["lines"]]
    if not hits:
        all_lines = sorted({n for o in overloads for n in o["lines"]})
        return {"status": "LINE_NOT_IN_METHOD",
                "detail": f"{cls}.{method} 的行号表里没有第 {line} 行"
                          f"（该方法现有行 {all_lines[0]}–{all_lines[-1]}，共 {len(all_lines)} 个位置）"}
    file_ok = entry["file"] is None or file is None or entry["file"] == file
    if not file_ok:
        return {"status": "LINE_NOT_IN_METHOD",
                "detail": f"行号对上了，但源文件名不符：栈里是 {file}，dex 里是 {entry['file']}"}
    return {"status": "VERIFIED", "overloads": len(overloads), "matched": hits[0]["type"],
            "detail": f"{cls}.{method} 的行号表含第 {line} 行，源文件 {entry['file']}"}


def verify_findings(index: dict | None, findings: list[dict], package: str) -> dict:
    results, counts = [], {}
    for finding in findings:
        for loc in finding.get("code_locs") or []:
            verdict = verify(index, loc.get("class"), loc.get("method"),
                             loc.get("file"), loc.get("line"))
            verdict.update({"rule_id": finding.get("rule_id"), "role": loc.get("role"),
                            "event_id": loc.get("event_id"), "frame": loc.get("frame")})
            counts[verdict["status"]] = counts.get(verdict["status"], 0) + 1
            results.append(verdict)
    unverified = [v for v in results if v["status"] != "VERIFIED"]
    return {
        "package": package,
        "dex_index_available": index is not None,
        "checks_total": len(results),
        "by_status": counts,
        "all_verified": bool(results) and not unverified,
        "caveat": "本核对证明的是「该行号存在于该方法的 dex 行号表中」，"
                  "不证明该行号就是违规行为的语义所在——R8 内联会改变行号归属。"
                  "结论仍需人工复核。",
        "details": results,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--apk", type=Path)
    parser.add_argument("--verify", type=Path, required=True, help="带 code_locs 的结论文件")
    parser.add_argument("--package", default=None,
                        help="受检包名（必填：不再默认填车载夹具包名，见 §8.2 B-1）")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--cache", type=Path, help="dex 索引缓存（dexdump 较慢，建议给）")
    args = parser.parse_args()

    if not args.package:
        parser.error("--package 必填：dex 核对应按包名定位 dex 里的类，"
                     "内核不再默认假定 com.vscanner.targetapp。")

    if args.out.exists():
        print(json.dumps({"status": "failed", "message": f"拒绝覆盖 {args.out}"}),
              file=sys.stderr)
        return 1

    index = None
    apk_sha256 = hashlib.sha256(args.apk.read_bytes()).hexdigest() if args.apk else None
    if args.apk:
        if args.cache and args.cache.exists():
            saved = json.loads(args.cache.read_text(encoding="utf-8"))
            if saved.get("apk_sha256") == apk_sha256:
                index = saved.get("index")
            else:
                print("[dexlines] 缓存无 APK 摘要或与当前 APK 不符，重新建索引", file=sys.stderr)
        if index is None:
            index = build_index(args.apk)
            if args.cache:
                args.cache.parent.mkdir(parents=True, exist_ok=True)
                args.cache.write_text(json.dumps({"apk_sha256": apk_sha256, "index": index},
                                                ensure_ascii=False), encoding="utf-8")
    else:
        print("[dexlines] 未给 APK，DEX_UNAVAILABLE", file=sys.stderr)

    findings = [json.loads(l) for l in args.verify.read_text(encoding="utf-8").splitlines()
                if l.strip()]
    report = verify_findings(index, findings, args.package)
    report["apk_sha256"] = apk_sha256
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n",
                        encoding="utf-8")
    print(json.dumps({k: v for k, v in report.items() if k != "details"},
                     ensure_ascii=False))
    return 0 if report["all_verified"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
