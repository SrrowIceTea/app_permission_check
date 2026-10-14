#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A1 分档扫描（H2 × H1 × H5）——一条命令跑完各档，产出"崩溃率 × 档位"表。

仅用于授权测试（已获授权的样本与设备）。

**为什么必须是"重复 N 次的崩溃率"，不是"跑一次没崩"**：A1 的崩溃是非确定的——
同一套 UI 动作序列一死一活（DEV_FIX_REPORT §5.1 的 M029/M030 取证）。所以单次结果
没有证据力。本脚本把 §5.1 落地步骤 2 的"每档归档 app-death.json 与 reads.jsonl"
自动化：每个 (档位 × 复次) 组合调一次 `fixture_selftest.py`（它就是"装夹具 → 挂钩 →
点按钮 → 断言 ≥1 条真实事件"的最小闭环），再按档位汇总成表。

档位沿用 H2 的二分计划，58 = 全量（`WATCH.length`）：

    1 → 3 → 8 → 16 → 32 → 58

两个正交开关用来隔离**到底是哪个变量导致崩**。它们只缩观测面、**不改判据**
（§8.6 第 1 条）：PRIVACY_READ 事件照样必须出现，缺的是值字段与栈字段，
不是"有没有收集"这个结论。

    --args-only   H5：事件期不碰返回值（不 String()、不哈希、不计数）
    --no-stack    H1：事件期不取线程名与栈

跑法：
    python mobile/tools/a1_tier_scan.py --out output/a1-scan --repeats 3
    python mobile/tools/a1_tier_scan.py --tiers 16,58 --repeats 5 --args-only

**耗时**：一格 ≈ 装 APK + 挂钩 8s + 触发 + 会话时长（默认 90s），约 2~3 分钟。
默认 6 档 × 3 复次 = 18 格 ≈ 45 分钟。用 `--tiers` / `--seconds` 缩短。

产出：
    <out>/scan.json         结构化账（每格一条，含原始自检结果）
    <out>/scan.md           "崩溃率 × 档位"表，可直接贴进报告
    <out>/tier-<n>/rep-<k>/ 每次自检的完整产物（result.json / app-death.json / …）

退出码：0=扫描完成（崩不崩都算完成，它是**测量**不是判据）；2=环境不满足
（设备守卫失败 / 夹具 APK 缺失）——那时一格有效测量都拿不到，继续跑只是浪费设备寿命。
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(HERE))
import thirdparty_env as env  # noqa: E402

PY = sys.executable
SELFTEST = HERE / "fixture_selftest.py"
APK = (ROOT / "mobile" / "fixture-app" / "app" / "build" / "outputs" / "apk" / "debug"
       / "app-debug.apk")
TIERS_DEFAULT = (1, 3, 8, 16, 32, 58)


def parse_tiers(text: str) -> tuple[int, ...]:
    """`--tiers 1,8,58` → (1, 8, 58)。0 合法（等价全不挂，当 attach 对照组）。"""
    try:
        values = tuple(int(x) for x in text.replace("，", ",").split(",") if x.strip())
    except ValueError:
        raise argparse.ArgumentTypeError(f"--tiers 必须是逗号分隔的整数：{text!r}")
    if not values or any(v < 0 for v in values):
        raise argparse.ArgumentTypeError("--tiers 不能为空，也不能含负数")
    return values


def run_cell(tier: int, rep: int, out: Path, seconds: int,
             args_only: bool, no_stack: bool) -> dict:
    """跑一格（一个档位的一次复次）。返回自检结果并补上档位账。

    档位与开关是经**环境变量**透传的：`thirdparty_env.start_hook` 用
    `dict(os.environ)` 起子进程，所以它们能一路走到 `core/frida_host/run.py`。
    """
    cell = out / f"tier-{tier}" / f"rep-{rep}"
    cell.mkdir(parents=True, exist_ok=True)
    child = dict(os.environ)
    child["VSCAN_WATCH_LIMIT"] = str(tier)
    if args_only:
        child["VSCAN_ARGS_ONLY"] = "1"
    if no_stack:
        child["VSCAN_NO_STACK"] = "1"
    with open(cell / "selftest.log", "w", encoding="utf-8") as handle:
        subprocess.run([PY, str(SELFTEST), "--out", str(cell), "--seconds", str(seconds)],
                       stdout=handle, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                       env=child)
    payload = cell / "result.json"
    result = (json.loads(payload.read_text(encoding="utf-8")) if payload.exists()
              else {"passed": False, "reason": "自检未产出 result.json（看 selftest.log）"})
    result["tier"] = tier
    result["rep"] = rep
    return result


def summarize(results: list[dict]) -> dict[int, dict]:
    """按档位汇总。**三态，不能压成两态**：

    * `valid`——自检真的跑到触发之后（有 `alive_at_end`）；
    * `env_failed`——APK 缺失 / 设备没起 / frida-server 不可用，整格无效。
      **绝不能算成"应用存活"**，否则把"没测到"记成"没崩"，正好是 A1 想要的假象；
    * `crashed` / `captured`——只看 `valid` 的格子。
    """
    tiers: dict[int, dict] = {}
    for item in results:
        bucket = tiers.setdefault(item["tier"], {
            "tier": item["tier"], "cells": 0, "valid": 0, "env_failed": 0,
            "crashed": 0, "captured": 0, "reads": [], "reasons": {}})
        bucket["cells"] += 1
        alive = item.get("alive_at_end")
        if alive is None:
            bucket["env_failed"] += 1
        else:
            bucket["valid"] += 1
            if not alive:
                bucket["crashed"] += 1
        if item.get("passed"):
            bucket["captured"] += 1
            bucket["reads"].append(item.get("privacy_reads", 0))
        reason = (item.get("reason") or "").strip()
        if reason:
            bucket["reasons"][reason] = bucket["reasons"].get(reason, 0) + 1
    for bucket in tiers.values():
        valid = bucket["valid"]
        bucket["crash_rate"] = round(bucket["crashed"] / valid, 3) if valid else None
        bucket["capture_rate"] = round(bucket["captured"] / valid, 3) if valid else None
    return tiers


def _verdict(tiers: dict[int, dict]) -> list[str]:
    """把表读成一句话：崩点从哪一档开始。"""
    crashing = [t for t in sorted(tiers) if tiers[t]["crashed"]]
    clean = [t for t in sorted(tiers) if tiers[t]["valid"] and not tiers[t]["crashed"]]
    if not crashing:
        return ["- 所有档位都没崩——**再跑一轮**：A1 是非确定的，单轮全活不足以排除它。"]
    low = min(crashing)
    lines = [f"- 崩点从 **{low}** 档起：{low} 以下的档位没崩，{low} 及以上出现崩溃。"]
    if clean:
        lines.append(f"- 未崩的最高档：**{max(clean)}**。"
                     f"崩点落在 {max(clean)} ~ {low} 之间，下一轮可只扫这一段。")
    else:
        lines.append("- 没有任何档位全身而退——连最小档也崩，问题更可能在 attach 方式"
                     "（H3 spawn）或 frida/设备组合（H4），而不是挂载规模。")
    return lines


def render_md(tiers: dict[int, dict], meta: dict) -> str:
    lines = ["# A1 分档扫描：崩溃率 × 钩子档位", "",
             f"- 开关：`args_only={meta['args_only']}` `no_stack={meta['no_stack']}`；"
             f"每档复次 {meta['repeats']}；会话 {meta['seconds']}s",
             "- 判据：`reads.jsonl` 出现 ≥1 条非 START/ARMED 的真实事件，且进程在窗口内存活"
             "（§8.1 A1 的验收判据本身）",
             "- **无效格**（环境没跑起来）不计入崩溃率分母——否则会把\"没测到\"记成\"没崩\"", "",
             "| 档位 | 有效格 | 崩溃 | 崩溃率 | 捕获到事件 | 捕获率 | 事件数中位 | 主要失败原因 |",
             "|---|---|---|---|---|---|---|---|"]
    for tier in sorted(tiers):
        bucket = tiers[tier]
        rate = "—" if bucket["crash_rate"] is None else f"{bucket['crash_rate']:.0%}"
        cap = "—" if bucket["capture_rate"] is None else f"{bucket['capture_rate']:.0%}"
        reads = sorted(bucket["reads"])
        median = "—" if not reads else str(reads[len(reads) // 2])
        top = ""
        if bucket["reasons"]:
            top = max(bucket["reasons"].items(), key=lambda kv: kv[1])[0]
            top = top if len(top) <= 30 else top[:29] + "…"
        lines.append(f"| {tier} | {bucket['valid']} | {bucket['crashed']} | {rate} | "
                     f"{bucket['captured']} | {cap} | {median} | {top} |")
    invalid = {t: tiers[t]["env_failed"] for t in sorted(tiers) if tiers[t]["env_failed"]}
    if invalid:
        lines += ["", "无效格（环境未就绪，需重跑）："
                  + "、".join(f"{t} 档 ×{n}" for t, n in invalid.items())]
    lines += ["", "## 读法", ""] + _verdict(tiers)
    return "\n".join(lines) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0],
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", required=True, type=Path, help="扫描产物目录")
    ap.add_argument("--tiers", type=parse_tiers, default=TIERS_DEFAULT,
                    help="逗号分隔的档位（默认 " + "/".join(map(str, TIERS_DEFAULT)) + "）")
    ap.add_argument("--repeats", type=int, default=3,
                    help="每档复次：非确定的崩溃必须取率，不能只看一次")
    ap.add_argument("--seconds", type=int, default=90, help="每次自检的钩子会话时长")
    ap.add_argument("--args-only", action="store_true", help="H5：事件不带返回值字段")
    ap.add_argument("--no-stack", action="store_true", help="H1：事件不带线程/栈字段")
    args = ap.parse_args()
    if args.repeats < 1:
        ap.error("--repeats 至少为 1")
    args.out.mkdir(parents=True, exist_ok=True)

    guard = env.device_guard()
    if guard:
        print(f"[a1-scan] 环境不满足，拒绝开跑：{guard}", file=sys.stderr, flush=True)
        return 2
    if not APK.exists():
        print(f"[a1-scan] 夹具 APK 不存在：{APK}\n"
              "          先 cd mobile/fixture-app && ./gradlew :app:assembleDebug",
              file=sys.stderr, flush=True)
        return 2

    results: list[dict] = []
    try:
        for tier in args.tiers:
            for rep in range(1, args.repeats + 1):
                print(f"[a1-scan] tier={tier} rep={rep}/{args.repeats} ...", flush=True)
                results.append(run_cell(tier, rep, args.out, args.seconds,
                                        args.args_only, args.no_stack))
                last = results[-1]
                print(f"[a1-scan]   passed={last.get('passed')} "
                      f"alive={last.get('alive_at_end')} "
                      f"reads={last.get('privacy_reads')} "
                      f"reason={last.get('reason', '')}", flush=True)
    except KeyboardInterrupt:
        print("[a1-scan] 收到中断：用已完成的格子出表（未跑完的档位会是空的）",
              file=sys.stderr, flush=True)

    if not results:
        print("[a1-scan] 一格都没跑完，无表可出", file=sys.stderr, flush=True)
        return 2
    tiers = summarize(results)
    meta = {"tiers": list(args.tiers), "repeats": args.repeats, "seconds": args.seconds,
            "args_only": args.args_only, "no_stack": args.no_stack}
    (args.out / "scan.json").write_text(
        json.dumps({"meta": meta, "tiers": [tiers[t] for t in sorted(tiers)],
                    "cells": results}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    report = render_md(tiers, meta)
    (args.out / "scan.md").write_text(report, encoding="utf-8")
    print(report, flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
