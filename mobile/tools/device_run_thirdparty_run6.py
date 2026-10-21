#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""device_run_thirdparty 阶段⑥：verification（从 device_run_thirdparty.py 拆出，
零行为改动）。写 verification.json、打印最终 status 并返回退出码。
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(HERE))
import thirdparty_env as env      # noqa: E402


def _stage_verify(ctx) -> int:
    """汇总判据：failed / optional_failed → verification.json + 终端 status + 退出码。"""
    args = ctx.args
    out = ctx.out
    session = ctx.session
    checks = ctx.checks

    failed = [c["name"] for c in checks if c.get("exit_code") and not c.get("optional")]
    optional_failed = [c["name"] for c in checks if c.get("exit_code") and c.get("optional")]
    (out / "verification.json").write_text(json.dumps(
        {"passed": not failed, "checks": checks, "failed": failed,
         "optional_failed": optional_failed, "session": session.name,
         "package": args.package, "apk_sha256": ctx.sha,
         # 覆盖账本（A4，2026-10-19）：passed 只代表"该跑的步骤都跑了"，
         # **不代表窗口被完整观测**。插桩下进程可能中途被打死，之后的阴性结论
         # 只能限定在 observed_s 内——报告与答辩引用时要连这个字段一起引。
         "coverage": ctx.coverage,
         # 一句话判据：窗口被截断 = 本次结果可用但打折（不是 failed，也不是 full）。
         "degraded": ctx.coverage["truncated"],
         "app_category": {"value": args.app_category, "source": "declared"},
         # serial 用 get-serialno（返回 `emulator-5554` 这种真序列号）。
         # 原先用的 get-state 只会返回字面量 "device"（不是序列号），且**同时接了多台设备时
         # 直接报错、字段落空**——2026-10-13 跑 Fossify Camera 时宿主机上第二次出现了
         # 另一台模拟器，"serial" 就写成了空串，事后无法看出检测跑在哪台设备上。
         # 多设备时裸 adb 命令一律报 "more than one device/emulator"，
         # 跑批次前须在环境里指定 ANDROID_SERIAL=<serial>（adb 会全局遵守它）。
         "device": {"serial": env.adb("get-serialno", timeout=30).stdout.strip(),
                    "fingerprint": env.adb("shell", "getprop", "ro.build.fingerprint",
                                           timeout=45).stdout.strip(),
                    "build_type": env.adb("shell", "getprop", "ro.build.type",
                                          timeout=45).stdout.strip()}},
        ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"status": "passed" if not failed else "failed", "out": str(out),
                      "checks": len(checks), "failed": failed,
                      "optional_failed": optional_failed,
                      "coverage": {"segments": ctx.coverage["segments"],
                                   "deaths": ctx.coverage["deaths"],
                                   "observed_s": ctx.coverage["observed_s"],
                                   "budget_s": ctx.coverage["budget_s"],
                                   "truncated": ctx.coverage["truncated"]}},
                     ensure_ascii=False, indent=2))
    return 0 if not failed else 1