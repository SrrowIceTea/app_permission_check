#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""`output/` 的**只读**盘点：顶层目录体积 / mtime / 是否 reparse point / 能否重建。

仅用于授权测试（自有设备与已授权的公开第三方样本）。

**只读**：本脚本不删除、不移动、不重命名任何文件（`AGENTS.md`「待办」段 明确禁止
按历史条目清理 `output/` 现存内容）。它只回答三个问题：
  1. 哪一层目录在占体积（顶层逐项，不做递归删除建议）；
  2. 哪些条目是 junction/reparse point——遍历时必须跳过，否则会重复计体积，甚至外溢出工作区。
     本机 10 个链接**都指向仓内** `output/_TRASH_20261110/<同名目录>`（实测，不是外部路径）；
     真正的风险是删掉 `_TRASH_20261110` 会让这 10 个链接悬空（`.workbuddy/memory/2026-11-10.md`
     「归档与 junction」段：删除前必须先 mv 回原位或保留副本）；
  3. 哪些体积是"离线回归重跑就能再生成"的，哪些是一次性快照（重跑结论会变）。

为什么要有时间上限（默认 50 秒）：`output/` 已 37.7 GB / 26 万文件，全量 stat 在机械盘上能跑
几分钟；盘点是给人看现场的，不该变成一次性能事故。超时就标 `partial=true` 并如实报告已扫到的部分。

用法：
    python tools/inspect_output.py                    # 打印表格 + 写 output/output-inventory-*.json
    python tools/inspect_output.py --max-seconds 40 --top 30
"""
from __future__ import annotations

import argparse
import json
import os
import stat
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = "output-inventory/1"

sys.path.insert(0, str(ROOT))
from core.regression_output import atomic_write_text  # noqa: E402

# 顶层目录名前缀 → (rebuildable, 依据)。只登记**能说出重跑入口**的；不确定一律 unknown，
# 不把"看着像临时目录"当成可删（删错就是证据丢失，而且本脚本也不删）。
REBUILD_RULES: tuple[tuple[tuple[str, ...], str, str], ...] = (
    (("regression-", "mobile-branch-", "ci-", "regression"),
     "yes", "离线回归产物：tools/run_regressions.py 或 tools/check_mobile_branch.py 重跑即得"),
    (("mobile-checks-", "mobile-checks"),
     "yes", "移动侧 63 项检查产物：mobile/tools/run_mobile_checks.py 重跑即得"),
    (("assess-",), "no", "一次性评估快照：口径固定但产物不会原样复现"),
    (("audit-", "vehicle-", "mobile-", "review-", "thirdparty-", "week-", "method-",
      "frontend-", "rules-", "jenkins"),
     "no", "采集/验收/交付产物：依赖当时设备与样本，重跑结论会变"),
    (("tmp", "tmpo", "tmpe", "tmpk", "tmpm"),
     "unknown", "临时目录：内容未登记，需人工确认来源后才能判断"),
)


def classify(name: str) -> tuple[str, str]:
    for prefixes, verdict, basis in REBUILD_RULES:
        if name.startswith(prefixes):
            return verdict, basis
    return "unknown", "未登记前缀：需人工确认来源"


def is_reparse(entry: os.DirEntry) -> bool:
    """junction / 符号链接都算（不进入）。

    三条判据取"或"：`is_symlink()`、NTFS 的 FILE_ATTRIBUTE_REPARSE_POINT 属性位、
    Python 3.12+ 的 `is_junction()`。属性位那条不依赖解释器版本，是主判据。
    **读不清时返回 True（fail-closed）**：宁可少扫一个目录，也不要把 junction 当普通目录
    钻进去——那是遍历外溢/重复计数的唯一入口。
    """
    try:
        if entry.is_symlink():
            return True
        attrs = getattr(entry.stat(follow_symlinks=False), "st_file_attributes", 0)
        flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
        if flag and attrs & flag:
            return True
        guard = getattr(entry, "is_junction", None)   # Python 3.12+
        return bool(guard and guard())
    except OSError:
        return True


def read_target(path: Path) -> str | None:
    try:
        return os.readlink(path)
    except OSError:
        return None


def walk_size(top: Path, deadline: float) -> tuple[int, int, float, bool, bool, int]:
    """返回 (字节, 文件数, 最新 mtime, 是否被截止, 是否遇到嵌套 reparse point, 读失败次数)。

    `errors` 必须一路带到 JSON：`scandir`/`stat` 失败的目录与"空目录"在报告里
    长得一模一样，而前者是"没读到"、后者是"真的没有"——`AGENTS.md`「失败可诊断」
    要求这两者能被区分（2026-11-11 review 抓到的原始缺口）。
    """
    total = files = 0
    newest = 0.0
    cut = nested = False
    errors = 0
    stack = [top]
    seen = 0
    while stack:
        current = stack.pop()
        try:
            entries = list(os.scandir(current))
        except OSError:
            errors += 1                 # 读不到 ≠ 空目录：计数并让 partial 置位
            continue
        for entry in entries:
            seen += 1
            if seen % 256 == 0 and time.monotonic() > deadline:
                cut = True
                return total, files, newest, cut, nested, errors
            try:
                # 先判链接再判目录：符号链接指向目录时 is_dir(follow_symlinks=False) 是 False，
                # 会被当成 0 字节文件计进去（既不跳过也不计入 nested_reparse）。
                if is_reparse(entry):
                    nested = True
                    continue
                if entry.is_dir(follow_symlinks=False):
                    stack.append(Path(entry.path))
                    continue
                info = entry.stat(follow_symlinks=False)
            except OSError:
                errors += 1
                continue
            total += info.st_size
            files += 1
            newest = max(newest, info.st_mtime)
    return total, files, newest, cut, nested, errors


def stamp(epoch: float) -> str:
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(epoch)) if epoch else "—"


def human(num: int) -> str:
    value = float(num)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            return f"{value:.0f}{unit}" if unit == "B" else f"{value:.1f}{unit}"
        value /= 1024
    return f"{value:.1f}TB"


def inventory(root: Path, max_seconds: float) -> dict:
    started = time.monotonic()
    deadline = started + max_seconds
    rows: list[dict] = []
    junctions: list[dict] = []
    top_files: list[dict] = []
    partial = False
    with os.scandir(root) as scanner:
        entries_sorted = sorted(scanner, key=lambda e: e.name)
    for entry in entries_sorted:
        path = Path(entry.path)
        if is_reparse(entry):
            junctions.append({"name": entry.name, "target": read_target(path)})
            rows.append({"name": entry.name, "kind": "reparse_point", "bytes": 0,
                         "files": 0, "newest": None, "nested_reparse": False,
                         "rebuildable": "unknown",
                         "rebuildable_basis": "链接（junction/symlink）：不遍历，目标在别处"})
            continue
        if not entry.is_dir(follow_symlinks=False):
            try:
                info = entry.stat(follow_symlinks=False)
            except OSError:
                partial = True
                top_files.append({"name": entry.name, "bytes": None,
                                  "mtime": None, "error": "stat 失败"})
                continue
            top_files.append({"name": entry.name, "bytes": info.st_size,
                              "mtime": stamp(info.st_mtime)})
            continue
        size, files, newest, cut, nested, errors = walk_size(path, deadline)
        partial = partial or cut or bool(errors)
        verdict, basis = classify(entry.name)
        rows.append({"name": entry.name, "kind": "dir", "bytes": size, "files": files,
                     "newest": stamp(newest), "nested_reparse": nested,
                     "rebuildable": verdict, "rebuildable_basis": basis,
                     "truncated": cut, "errors": errors})
    rows.sort(key=lambda r: r["bytes"], reverse=True)
    return {
        "schema": SCHEMA,
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "root": str(root),
        "elapsed_seconds": round(time.monotonic() - started, 1),
        "max_seconds": max_seconds,
        "partial": partial,
        "totals": {
            "entries": len(rows) + len(top_files),
            "dirs": sum(1 for r in rows if r["kind"] == "dir"),
            "junctions": len(junctions),
            # 顶层文件（latest-*.txt 指针、本脚本自己的历史报告）也要计入，
            # 否则"output/ 体积"会少掉一块，且每次跑完自己 +1 却看不见。
            "bytes": sum(r["bytes"] or 0 for r in rows)
                     + sum(f["bytes"] or 0 for f in top_files),
            "files": sum(r["files"] for r in rows)
                     + sum(1 for f in top_files if f.get("bytes") is not None),
            "bytes_dirs": sum(r["bytes"] for r in rows),
            "bytes_top_files": sum(f["bytes"] or 0 for f in top_files),
            "unreadable": sum(r.get("errors", 0) for r in rows)
                          + sum(1 for f in top_files if f.get("bytes") is None),
        },
        "junctions": junctions,
        "top_level_files": top_files,
        "entries": rows,
        "notes": [
            "只读盘点：不删除/移动/重命名任何文件（AGENTS.md「待办」段）。",
            "rebuildable=yes 只表示「离线回归重跑即得」，不表示可以删——是否清理由人决定。",
            "junction 与符号链接不遍历，体积不计入 totals（避免重复计数与外溢）。",
            "partial=true 表示没扫完（超时）或有条目读不到；后者同时计入 totals.unreadable。",
            "报告自身写在 root 下，下一次盘点会把它算作一个顶层文件（属正常自污染）。",
        ],
    }


def _free_name(root: Path, stamp: str) -> Path:
    """`output-inventory-<stamp>.json`；同名已存在就加 `-2`/`-3`，**不覆盖历史报告**。"""
    candidate = root / f"output-inventory-{stamp}.json"
    serial = 1
    while candidate.exists():
        serial += 1
        candidate = root / f"output-inventory-{stamp}-{serial}.json"
    return candidate


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--root", type=Path, default=ROOT / "output")
    ap.add_argument("--out", type=Path, default=None, help="JSON 落盘路径（默认 output/output-inventory-*.json）")
    ap.add_argument("--max-seconds", type=float, default=50.0, help="扫描上限（默认 50 秒）")
    ap.add_argument("--top", type=int, default=20, help="表格显示前 N 项")
    args = ap.parse_args()

    root = args.root.resolve()
    if not root.is_dir():
        print(f"[output-inventory] 目录不存在：{root}")
        return 2
    data = inventory(root, args.max_seconds)
    out = args.out or _free_name(root, time.strftime("%Y%m%d-%H%M%S"))
    # 原子写：同一秒内连跑两次或写到一半被杀，都不会留下半截 JSON 覆盖掉上一份报告。
    atomic_write_text(out, json.dumps(data, ensure_ascii=False, indent=2) + "\n")

    total = data["totals"]
    print(f"[output-inventory] {total['entries']} 项 / {human(total['bytes'])} / "
          f"{total['files']} 文件 / {total['junctions']} 个链接 / {data['elapsed_seconds']}s"
          + ("（partial）" if data["partial"] else "")
          + (f" / 读不到 {total['unreadable']} 处" if total["unreadable"] else ""))
    print(f"{'体积':>9}  {'文件数':>8}  {'最新':>16}  重建  名称")
    for row in data["entries"][:max(1, args.top)]:
        print(f"{human(row['bytes']):>9}  {row['files']:>8}  {row['newest']:>16}  "
              f"{row['rebuildable']:<6} {row['name']}")
    if data["junctions"]:
        print(f"[output-inventory] 链接（不遍历）：{', '.join(j['name'] for j in data['junctions'])}")
    print(f"[output-inventory] 明细：{out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
