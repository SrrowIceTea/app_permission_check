#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""批量跑第三方样本：`apk/mobile/` 下每个 APK → 静态分析 → 设备检测 → AI → PDF。

仅用于授权测试（自有设备 / 已授权的公开第三方样本）。

为什么要批处理：样本是**一批一批来的**，逐个手敲参数既慢又容易漏步骤
（漏 `--static-dir` 报告里就没有静态证据，漏 `--provenance` 就答不出"这份样本哪来的"）。
**单个样本失败不影响其余**——失败原因如实记进汇总。

**两段式（2026-10-19）**：静态阶段不碰设备，**并行**跑（`batch_static.py`）；
动态阶段必须单设备**串行**（8888 单端口 / 全局 http_proxy / 单前台 App / 固定 pcap 路径
——同一台设备并发两个包，归因必然 ambiguous，见 `mobile/DECISIONS.md` M020）。
样本判定与目录规划在 `batch_plan.py`，主循环只剩"静态并行 → 动态串行"。

每个样本的产物：output/thirdparty-<时间戳>/<包名>/
    static/     静态分析产物（实际落在 <批次>/_static/，由 device_run 拷进交付目录）
    session/    原始采集
    out/        findings / summary / bundle / 报告
    run.log     该样本的动态日志（静态日志在 <批次>/_static/_logs/）

汇总：output/thirdparty-<时间戳>/batch-summary.json（判据看这个）

用法：
    python batch_thirdparty.py                       # 跑 apk/mobile/ 下全部
    python batch_thirdparty.py --apk-dir D:/samples  # 换目录
    python batch_thirdparty.py --static-only         # 只做静态（不需要设备）
    python batch_thirdparty.py --static-workers 1    # 静态退回串行（内存吃紧时）
    python batch_thirdparty.py --skip-ai             # 不跑 AI 阶段

出批前会先跑一次夹具阳性对照自检（fixture_selftest.py，A3）：自检失败 =
采集链路故障，**拒绝出批**。A1 未修期间可 `--skip-fixture-selftest` 显式跳过，
跳过事实写进 batch-summary.json。
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
PY = sys.executable
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT))
from core import sdk_paths  # noqa: E402   SDK 路径统一解析（§8.2 B-4）

import batch_plan as bp  # noqa: E402
import batch_static as bs  # noqa: E402
from batch_dynamic import dynamic_step, run  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--apk-dir", default=str(ROOT / "apk" / "mobile"),
                    help="样本目录；默认 apk/mobile/（车载样本在 apk/vehicle/，用错平台会"
                         "表现为设备检测卡在 app_started，见 apk/README.md）")
    ap.add_argument("--out", default=None, help="批次输出目录（默认 output/thirdparty-<时间戳>）")
    ap.add_argument("--app-category", default="utility",
                    help="默认类目 key（39 类）；单个样本可用 --category 覆盖")
    ap.add_argument("--category", action="append", default=[], metavar="PKG=KEY",
                    help="逐样本指定类目，可重复。**类目决定「必要个人信息」范围**，"
                         "用错类目会让 over_collection 的判定整体偏移——"
                         "例：--category com.ximalaya.ting.android.car=online_video")
    ap.add_argument("--static-only", action="store_true")
    ap.add_argument("--static-workers", type=int, default=bs.DEFAULT_WORKERS,
                    help=f"静态分析并行数（默认 {bs.DEFAULT_WORKERS}，1 = 退回串行）。"
                         "静态不碰设备，但 jadx 吃内存；大 APK 批次建议 2")
    ap.add_argument("--static-threads", type=int, default=None,
                    help="每个 jadx 进程的线程数（默认按核数/worker 自动，封顶 4）")
    ap.add_argument("--resume", action="store_true",
                    help="断点续跑：已有「verification.json passed + 报告 PDF」的样本直接跳过；"
                         "本批次 _static/ 里已完成的反编译也直接复用，不重跑 jadx")
    ap.add_argument("--static-reuse", default=None,
                    help="已有逐包静态产物目录（<包名>/static-manifest.json）。命中则跳过"
                         "静态分析、直接用它当 --static-dir；未命中照常跑静态。")
    ap.add_argument("--skip-ai", action="store_true")
    ap.add_argument("--seconds", type=int, default=150)
    ap.add_argument("--build-tools",
                    default=str(sdk_paths.sdk_dir("build-tools", "36.1.0")))
    ap.add_argument("--only", nargs="*", default=None, help="只跑这些包名")
    ap.add_argument("--skip-fixture-selftest", action="store_true",
                    help="显式跳过批前夹具自检（A1 未修期间）。跳过事实会写进 batch-summary.json")
    ap.add_argument("--spawn-hook", action="store_true",
                    help="动态阶段用 Frida spawn 注入（钩子先于应用第一条指令）。"
                         "attach 太晚导致应用启动瞬间的联网全漏采、flows 归因 unresolved。")
    args = ap.parse_args()

    cat_map = {}
    for item in args.category:
        if "=" not in item:
            sys.exit(f"--category 需要 PKG=KEY 形式，收到: {item!r}")
        k, v = item.split("=", 1)
        cat_map[k.strip()] = v.strip()

    # 多设备未指定 ANDROID_SERIAL → 立刻停：裸 adb 命令会全部报错且失败形态是
    # 静默空结果。理由详见 thirdparty_env.device_guard 的注释。
    import thirdparty_env
    guard = thirdparty_env.device_guard()
    if guard:
        sys.exit("[fatal] " + guard)

    apk_dir = Path(args.apk_dir)
    if not apk_dir.is_dir():
        sys.exit(f"[fatal] APK 目录不存在: {apk_dir}")
    apks = sorted(p for p in apk_dir.glob("*.apk"))
    if args.only:
        apks = [p for p in apks if p.stem in set(args.only)]
    if not apks:
        sys.exit(f"[fatal] {apk_dir} 下没有 .apk。把下载到的样本放进去再跑。"
                 f"（下载说明见 mobile/README.md 的「拿样本」一节）")

    # **批次根目录刻意放在短路径下**：本工程根路径就有 67 字符（用户名非 ASCII +
    # 多层目录），而 jadx 解出的 Kotlin 源码里**单个文件名**最长见过 105 字符
    # （`Xxx$lambda$5$13$0$$inlined$itemsIndexed$default$1.java`）。
    # 两者相加必然越过 Windows 的 MAX_PATH 260，症状是 core/static/jadx.py
    # `path.stat()` 抛 FileNotFoundError —— jadx 写得进去、Python 读不出来。
    # 在 output/ 下留一个 junction 指向它，路径好找、字节仍然在短根上。
    stamp = time.strftime("%m%d%H%M")
    batch = Path(args.out) if args.out else Path(f"D:/vscanner-tp/tp-{stamp}")
    batch.mkdir(parents=True, exist_ok=True)
    link = ROOT / "output" / f"tp-{stamp}"
    if not args.out and not link.exists():
        # mklink /J 是目录联接，不需要管理员权限；失败也不影响本批次。
        # **必须显式声明 utf-8 + errors="replace"**：cmd.exe 的输出是 GBK，
        # 而本机 PYTHONUTF8=1 让 Python 处于 UTF-8 模式（子进程管道默认 UTF-8 解码）——
        # 缺了这行，Reader 线程会被 UnicodeDecodeError 打死、result.stderr 变成 None，
        # 实测崩过一次（2026-10-13 跑 Fossify Camera 时这条 mklink 就是崩溃点）。
        subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(batch)],
                       capture_output=True, text=True, encoding="utf-8",
                       errors="replace", timeout=60)
    print(f"[batch] {len(apks)} 个样本 -> {batch}")

    # A3 批前阳性对照（§5.2）：夹具自检不过 = 采集链路故障，拒绝出批——否则
    # "采不到"会被写成一堆"该应用未收集"。A1 未修期间允许显式 --skip，留痕到摘要。
    selftest = None
    if not args.static_only:
        st_dir = batch / "_fixture-selftest"
        st_cmd = [PY, str(HERE / "fixture_selftest.py"), "--out", str(st_dir),
                  "--seconds", str(args.seconds)]
        if args.skip_fixture_selftest:
            st_cmd += ["--skip"]
        run(st_cmd, batch / "fixture-selftest.log", timeout=1800)
        st_file = st_dir / "result.json"
        selftest = (json.loads(st_file.read_text(encoding="utf-8")) if st_file.exists() else
                    {"passed": False, "reason": "自检脚本未产出 result.json（看 "
                                                "fixture-selftest.log）"})
        if selftest.get("passed") is False:
            failed = {"status": "fixture_selftest_failed", "batch_dir": str(batch),
                      "samples": 0, "succeeded": 0, "results": [], "selftest": selftest}
            (batch / "batch-summary.json").write_text(
                json.dumps(failed, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            print(json.dumps({"status": "fixture_selftest_failed",
                              "reason": selftest.get("reason"),
                              "hint": selftest.get("hint")}, ensure_ascii=False, indent=2))
            return 1

    # ---- 1) 样本判定（串行、秒级、不碰设备）----
    plan = bp.collect(apks, batch, build_tools=args.build_tools, resume=args.resume,
                      static_reuse=Path(args.static_reuse) if args.static_reuse else None)
    for item in plan:
        status = item["rec"]["status"]
        if status == "unreadable_apk":
            print(f"  [不可读] {item['apk'].name}：{item['rec']['error']}")
        elif status == "resumed":
            print(f"  [已完成·跳过] {item['pkg']}  "
                  f"结论 {item['rec'].get('findings_total', '?')} 条")

    # ---- 2) 静态：并行（不碰设备，失败只影响该样本）----
    jobs = [item["job"] for item in plan if bp.needs_static(item)]
    rcs: dict[str, int] = {}
    if jobs:
        print(f"[static] {len(jobs)} 个样本，{min(args.static_workers, len(jobs))} 路并行")
        done = 0

        def progress(job, rc):
            nonlocal done
            done += 1
            label = "完成" if rc == 0 else f"失败 rc={rc}"
            print(f"  [静态{label}] {job.package}  ({done}/{len(jobs)})")

        rcs = bs.run_jobs(jobs, script=HERE / "static_scan_thirdparty.py", python=PY,
                          cwd=ROOT, workers=args.static_workers,
                          threads=args.static_threads, progress=progress)
    for item in plan:
        bp.apply_static(item, rcs)

    if args.static_only:
        for item in plan:
            rec = item["rec"]
            if rec["status"] is None:
                rec["status"] = "static_ok"
                rec["static_dir"] = str(item["static_dir"])
                print(f"  [静态完成] {item['pkg']}")
        return _summarize(plan, batch, selftest)

    # ---- 3) 动态：单设备串行（并发会串归因，不要改成并行）----
    for item in plan:
        rec = item["rec"]
        if rec["status"] is not None:      # 不可读 / 续跑 / 静态失败
            continue
        dynamic_step(item, args, cat_map, item["app_dir"])
        print(f"  [{rec['status']}] {item['pkg']}  结论 {rec.get('findings_total', '?')} 条"
              + ("  报告已生成" if rec.get("report") else ""))
    return _summarize(plan, batch, selftest)


def _summarize(plan: list[dict], batch: Path, selftest) -> int:
    """写 batch-summary.json + latest 指针，返回进程退出码。"""
    results = [item["rec"] for item in plan]
    ok = [r for r in results if r["status"] in ("ok", "static_ok", "resumed")]
    summary = {"status": "ok" if len(ok) == len(results) else "partial",
               "batch_dir": str(batch), "samples": len(results), "succeeded": len(ok),
               "results": results, "selftest": selftest,
               "note": "每个样本的判据在 <批次>/<包名>/verification.json；"
                       "本文件只是汇总，不能替代逐样本判据。"}
    (batch / "batch-summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (ROOT / "output" / "latest-thirdparty-batch.txt").write_text(str(batch), encoding="utf-8")
    print(json.dumps({"status": summary["status"], "batch_dir": str(batch),
                      "samples": len(results), "succeeded": len(ok),
                      "failed": [r["name"] for r in results if r not in ok]},
                     ensure_ascii=False, indent=2))
    return 0 if len(ok) == len(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
