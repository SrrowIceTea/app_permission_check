#!/usr/bin/env python3
"""测试清单守卫：仓库里每个 test_* 文件必须"能被执行"，否则必须显式登记。

为什么需要它：仓库没有 pytest 配置、没有 conftest.py、没有 CI 自动发现；"有调用方"
只可能来自三个显式清单：
    tools/run_regressions.py / mobile/tools/run_mobile_checks.py / tools/check_mobile_branch.py
一份测试只要没被这三个文件引用，就永远不会在 PR / CI / 提交钩子里跑——这正是
2026-11-10 盘点（docs/ZOMBIE_TESTS_20261110.md）抓到的病。本守卫把它变成会响的警报。

引用判定（三类证据，全部来自 ast，注释与 docstring 不算引用）：
  1. 字符串常量里的 test_* token（含 f-string 的静态片段）；
  2. f-string 模板：`f"test_{name}_model.mjs"` → glob `test_*_model.mjs`，用文件名匹配；
  3. `-m unittest discover -s <dir> -p <pattern>`：该目录下匹配 pattern 的文件视为被引用
     （这是 check_mobile_branch 收集 mobile/workbench、mobile/policy、mobile/pipeline、
     mobile/repack、mobile/audit、mobile/lab 的方式；只按字面模块名匹配会把这 28 个文件
     误报成僵尸——2026-11-10 第一版盘点就是这么误判的）。

失败条件（任一即退出码 1）：
  1. 未被引用、且不在 tools/test_inventory_allowlist.json 里（新增僵尸，逐条打印路径）；
  2. 白名单条目 reason 为空/过短、category 非法、路径不存在（登记失真）；
  3. 白名单条目其实已被引用、或文件已不存在（白名单过期，会掩盖真实状态）。

用法：python tools/test_inventory_guard.py [--json]
"""
from __future__ import annotations

import argparse
import ast
import fnmatch
import json
import os
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RUNNERS = ["tools/run_regressions.py", "mobile/tools/run_mobile_checks.py",
           "tools/check_mobile_branch.py"]
ALLOWLIST = ROOT / "tools" / "test_inventory_allowlist.json"
EXCLUDE_DIRS = {"archive", "output", ".venv", "node_modules", ".git"}
CATEGORIES = {"not_a_test", "script_style", "needs_device", "pending_evaluation",
              "third_party_copy"}
TOKEN = re.compile(r"test_[A-Za-z0-9_]+")


def _ast(rel: str) -> ast.AST:
    return ast.parse((ROOT / rel).read_text(encoding="utf-8", errors="replace"))


def evidence() -> tuple[set[str], list[str], list[tuple[str, str]]]:
    """返回 (test_* token 集合, f-string 文件名 glob 列表, discover 规则)。"""
    tokens: set[str] = set()
    globs: list[str] = []
    rules: list[tuple[str, str]] = []
    for rel in RUNNERS:
        for node in ast.walk(_ast(rel)):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                tokens.update(TOKEN.findall(node.value))
            elif isinstance(node, ast.JoinedStr):
                parts = []
                for part in node.values:
                    if isinstance(part, ast.Constant) and isinstance(part.value, str):
                        parts.append(part.value)
                    else:
                        parts.append("*")
                template = "".join(parts)
                if template.startswith("test_"):
                    globs.append(template)
            elif isinstance(node, ast.List):
                vals = [e.value for e in node.elts
                        if isinstance(e, ast.Constant) and isinstance(e.value, str)]
                if "discover" in vals and "-s" in vals and "-p" in vals:
                    rules.append((vals[vals.index("-s") + 1], vals[vals.index("-p") + 1]))
    return tokens, globs, rules


def scanned_files() -> list[str]:
    """遍历仓库但**剪掉**排除目录的子树（rglob 会走完 output/ 与 .venv，实测慢 20 倍）。"""
    out = []
    for dirpath, dirnames, filenames in os.walk(ROOT):
        dirnames[:] = [d for d in dirnames if d not in EXCLUDE_DIRS]
        rel_dir = Path(dirpath).relative_to(ROOT)
        for name in filenames:
            if name.startswith("test_") and name.endswith((".py", ".mjs", ".js")):
                out.append(name if str(rel_dir) == "." else (rel_dir / name).as_posix())
    return sorted(set(out))


def is_referenced(rel: str, tokens: set[str], globs: list[str],
                  rules: list[tuple[str, str]]) -> bool:
    name = rel.rsplit("/", 1)[-1]
    if name in tokens or Path(rel).stem in {Path(t).stem for t in tokens}:
        return True
    if any(fnmatch.fnmatch(name, g) for g in globs):
        return True
    for start, pattern in rules:
        prefix = start.strip("./").rstrip("/")
        if prefix and rel.startswith(prefix + "/") and fnmatch.fnmatch(name, pattern):
            return True
    return False


def load_allowlist(problems: list[str]) -> dict[str, dict]:
    if not ALLOWLIST.is_file():
        problems.append(f"白名单缺失：{ALLOWLIST.relative_to(ROOT).as_posix()}")
        return {}
    try:
        data = json.loads(ALLOWLIST.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        problems.append(f"白名单不是合法 JSON：{exc}")
        return {}
    entries = data.get("entries")
    if not isinstance(entries, list):
        problems.append("白名单缺少 entries 数组")
        return {}
    out: dict[str, dict] = {}
    for i, item in enumerate(entries):
        item = item or {}
        path, category = item.get("path", ""), item.get("category", "")
        reason = item.get("reason", "")
        if not path:
            problems.append(f"entries[{i}] 缺少 path")
            continue
        if path in out:
            problems.append(f"白名单重复登记：{path}")
            continue
        if category not in CATEGORIES:
            problems.append(f"{path} 的 category 非法：{category!r}（允许 {sorted(CATEGORIES)}）")
        if not isinstance(reason, str) or len(reason.strip()) < 12:
            problems.append(f"{path} 的 reason 太短或为空（需具体到为什么不能进 runner）")
        if not (ROOT / path).is_file():
            problems.append(f"白名单路径不存在：{path}")
        out[path] = item
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--json", action="store_true", help="只输出 JSON 摘要")
    args = ap.parse_args()

    problems: list[str] = []
    tokens, globs, rules = evidence()
    files = scanned_files()
    allow = load_allowlist(problems)

    referenced = [f for f in files if is_referenced(f, tokens, globs, rules)]
    unreferenced = [f for f in files if f not in referenced]
    unregistered = [f for f in unreferenced if f not in allow]
    stale = [f for f in allow if f not in unreferenced]

    for f in unregistered:
        problems.append(f"未被任何 runner 引用，也未登记：{f}")
    for f in stale:
        problems.append(f"白名单过期（文件{'已被 runner 引用' if (ROOT / f).is_file() else '已不存在'}，"
                        f"请删除该条）：{f}")

    summary = {
        "passed": not problems,
        "scanned": len(files),
        "referenced": len(referenced),
        "allowlisted": len(allow) - len(stale),
        "unregistered": unregistered,
        "stale_allowlist": stale,
        "problems": problems,
    }
    if args.json:
        print(json.dumps(summary, ensure_ascii=False, indent=2))
        return 0 if not problems else 1
    print(f"[test-inventory] scanned={len(files)} referenced={len(referenced)} "
          f"allowlisted={summary['allowlisted']} unregistered={len(unregistered)} "
          f"stale={len(stale)}")
    if unregistered:
        print("[test-inventory] 未登记（本次新增的僵尸）：")
        for f in unregistered:
            print(f"  - {f}")
    for p in problems:
        if not p.startswith("未被任何 runner 引用"):
            print(f"[test-inventory] {p}")
    print("[test-inventory] PASS" if not problems
          else f"[test-inventory] FAIL（{len(problems)} 个问题）")
    return 0 if not problems else 1


if __name__ == "__main__":
    raise SystemExit(main())
