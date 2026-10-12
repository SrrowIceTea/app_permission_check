#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""V-Scanner Phase 4 — 多 App 并发归因的验收脚本。

仅用于授权测试（自有设备与自有 APK）/ For authorized testing on owned devices and APKs only.

**为什么需要它**：归因只有单 App 数据时看不出错。两个 App 同时外发，
"时间就近"才可能把 A 的流算到 B 头上。这个脚本拿**载荷自报的包名**当基准，
逐条比对 addon 的归因结果。

**比较必须是精确相等，不能是子串包含**。本项目的两个测试包名
`com.vscanner.targetapp` 与 `com.vscanner.targetapp2` 恰好构成前缀关系，
用 `'targetapp2' in preview` 之类的写法会把 A 判成 B——我上一轮就是这么误报了一次
（`*** CROSSED ***` 出现在一条实际归因正确的流上，delta 只有 2ms）。

**基准的局限**：`request_preview` 截断到 400 字符，自报包名落在开头所以拿得到。
万一截断点落在它之前，脚本报 `UNKNOWN` 而**不猜**——没有基准就不下结论。

用法:
  python verify_multi_app.py --flows logs/flows.jsonl --egress ../analyze/logs/egress-multi.jsonl
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

# 载荷自报的包名。target-app 的 JSON 把 "package" 放在靠前的位置，
# 因此能落在 400 字符的 preview 之内。
SELF_REPORTED = re.compile(r'"package"\s*:\s*"([^"]+)"')


def load_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


def self_reported(flow: dict) -> str | None:
    match = SELF_REPORTED.search(flow.get("request_preview") or "")
    return match.group(1) if match else None


def verdict(flow: dict) -> str:
    truth = self_reported(flow)
    got = flow.get("package")
    if truth is None:
        return "UNKNOWN"
    if got is None:
        return "UNRESOLVED"
    if flow.get("attribution_ambiguous"):
        return "AMBIGUOUS"
    # 精确相等。别改成 in / startswith —— 见模块开头。
    return "MATCH" if got == truth else "CROSSED"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--flows", type=Path, required=True)
    parser.add_argument("--egress", type=Path, action="append", default=[],
                        help="可重复；用于显示每条流最近的出站事件")
    args = parser.parse_args()

    flows = load_jsonl(args.flows)
    if not flows:
        print(f"没有读到任何流记录：{args.flows}", file=sys.stderr)
        return 2

    events = [e for path in args.egress for e in load_jsonl(path)
              if e.get("ev") == "EGRESS_CONNECT"]

    by_verdict: dict[str, int] = {}
    packages = set()
    bad = 0
    print(f"{'evt':>4}  {'attributed':<26} {'self-reported':<26} {'delta':>7}  verdict")
    print("-" * 92)
    for flow in sorted(flows, key=lambda f: f.get("ts", 0)):
        got = flow.get("package") or "-"
        truth = self_reported(flow) or "(preview 被截断)"
        result = verdict(flow)
        by_verdict[result] = by_verdict.get(result, 0) + 1
        if flow.get("package"):
            packages.add(flow["package"])
        delta = flow.get("attribution_delta_ms")
        mark = "" if result == "MATCH" else "  <<<"
        if result != "MATCH":
            bad += 1
        print(f"{flow.get('evt_id', 0):>4}  {got:<26} {truth:<26} "
              f"{delta if delta is not None else '-':>7}  {result}{mark}")

    print("-" * 92)
    print(f"流记录 {len(flows)} 条；出站事件 {len(events)} 条；"
          f"归因到 {len(packages)} 个包 {sorted(packages)}")
    print("判定分布：" + "  ".join(f"{k}={v}" for k, v in sorted(by_verdict.items())))

    if bad:
        print(f"\n有 {bad} 条不是 MATCH —— 多 App 归因未通过。", file=sys.stderr)
        return 1
    print("\n全部 MATCH —— 并发场景下未发生串包。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
