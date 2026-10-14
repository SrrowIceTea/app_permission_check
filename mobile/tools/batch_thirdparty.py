#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""批量跑第三方样本：`apk/mobile/` 下每个 APK → 静态分析 → 设备检测 → AI → PDF。

仅用于授权测试（自有设备 / 已授权的公开第三方样本）。

为什么要批处理：样本是**一批一批来的**，逐个手敲参数既慢又容易漏步骤
（漏 `--static-dir` 报告里就没有静态证据，漏 `--provenance` 就答不出"这份样本哪来的"）。
批处理把顺序固定下来，并且**单个样本失败不影响其余**——失败原因如实记进汇总。

每个样本的产物：output/thirdparty-<时间戳>/<包名>/
    static/     静态分析（权限、dex 引用、反编译）
    session/    原始采集
    out/        findings / summary / bundle / 报告
    run.log     该样本的完整执行日志

汇总：output/thirdparty-<时间戳>/batch-summary.json（判据看这个）

用法：
    python batch_thirdparty.py                       # 跑 apk/mobile/ 下全部
    python batch_thirdparty.py --apk-dir D:/samples  # 换目录
    python batch_thirdparty.py --static-only         # 只做静态（不需要设备）
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
from apk_meta import badging, launchable_activity, short_slug  # noqa: E402


def run(cmd: list[str], log: Path, timeout: int) -> int:
    with log.open("a", encoding="utf-8") as fh:
        fh.write(f"\n$ {' '.join(cmd)}\n")
        fh.flush()
        proc = subprocess.run(cmd, cwd=ROOT, stdout=fh, stderr=subprocess.STDOUT,
                              text=True, encoding="utf-8", errors="replace", timeout=timeout)
    return proc.returncode


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
    ap.add_argument("--skip-ai", action="store_true")
    ap.add_argument("--seconds", type=int, default=150)
    ap.add_argument("--build-tools",
                    default=str(sdk_paths.sdk_dir("build-tools", "36.1.0")))
    ap.add_argument("--only", nargs="*", default=None, help="只跑这些包名")
    ap.add_argument("--skip-fixture-selftest", action="store_true",
                    help="显式跳过批前夹具自检（A1 未修期间）。跳过事实会写进 batch-summary.json")
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

    results: list[dict] = []
    for idx, apk in enumerate(apks, 1):
        rec: dict = {"apk": str(apk), "name": apk.name, "status": None, "steps": {}}
        ident = badging(apk, args.build_tools)
        rec["identity"] = ident
        pkg = ident.get("package")
        if not pkg:
            rec["status"] = "unreadable_apk"
            rec["error"] = ident.get("error") or "aapt2 未解出包名"
            results.append(rec)
            print(f"  [不可读] {apk.name}：{rec['error']}")
            continue
        if pkg != apk.stem:
            # 文件名与包名不一致不致命，但要说出来——报告里写错包名会让结论指向别的应用。
            rec["note"] = f"文件名 {apk.stem!r} 与包名 {pkg!r} 不一致（按包名建档）"

        app_dir = batch / f"{idx:02d}-{short_slug(pkg)}"
        app_dir.mkdir(parents=True, exist_ok=True)
        rec["dir"] = str(app_dir)
        log = app_dir / "run.log"
        log.write_text(f"样本: {apk}\n包名: {pkg}\n标签: {ident.get('app_label')}\n"
                       f"版本: {ident.get('version_name')} ({ident.get('version_code')})\n"
                       f"目录名是包名的短写（Windows 260 字符路径上限），"
                       f"对应完整包名见本行上面的「包名」。\n",
                       encoding="utf-8")

        # 1) 静态分析
        #
        # **静态产物必须放在 `--out` 之外**：device_run_thirdparty 会把
        # `--static-dir` 拷成 `<out>/static`，而拷贝前先 `rmtree(<out>/static)`。
        # 若 static_dir 就在 out 里面，它删掉的正是源，紧接着的 copytree 必然
        # 报 `FileNotFoundError`——看起来像"静态分析没产出"，实则是自己删了自己。
        static_dir = batch / "_static" / f"{idx:02d}-{short_slug(pkg)}"
        rc = run([PY, str(HERE / "static_scan_thirdparty.py"), "--apk", str(apk),
                  "--out", str(static_dir), "--version", "36"], log, timeout=1800)
        rec["steps"]["static"] = rc
        if rc != 0:
            rec["status"] = "static_failed"
            results.append(rec)
            print(f"  [静态失败 rc={rc}] {pkg}")
            continue
        if args.static_only:
            rec["status"] = "static_ok"
            rec["static_dir"] = str(static_dir)
            results.append(rec)
            print(f"  [静态完成] {pkg}")
            continue

        # 2) 设备检测（含 AI 与报告）
        activity, how = launchable_activity(apk, args.build_tools)
        rec["main_activity"] = activity
        rec["main_activity_basis"] = how
        if not activity:
            rec["status"] = "no_launcher_activity"
            rec["error"] = ("样本没有可启动的 Activity（可能是插件包/资源包）；"
                            "设备检测无法驱动它，静态结论仍有效")
            results.append(rec)
            print(f"  [无启动入口] {pkg}")
            continue
        prov = apk_dir / f"{pkg}.provenance.json"
        category = cat_map.get(pkg, args.app_category)
        rec["app_category"] = category
        if pkg not in cat_map:
            rec["note"] = ((rec.get("note", "") +
                            f" 类目未逐样本指定，按默认 {category!r}（可能不准确）").strip())
        cmd = [PY, str(HERE / "device_run_thirdparty.py"), "--apk", str(apk),
               "--package", pkg, "--main-activity", activity,
               "--out", str(app_dir), "--app-category", category,
               "--seconds", str(args.seconds),
               "--static-dir", str(static_dir), "--build-tools", args.build_tools]
        if prov.exists():
            cmd += ["--provenance", str(prov)]
        else:
            rec["note"] = (rec.get("note", "") +
                           " 无 provenance.json：报告里样本来源会标为未记录").strip()
        if args.skip_ai:
            cmd += ["--skip-ai"]
        rc = run(cmd, log, timeout=3600)
        rec["steps"]["device"] = rc
        rec["status"] = "ok" if rc == 0 else "device_failed"
        # 把该样本的结论规模摘进汇总，便于一眼看出哪个样本有东西
        summary_p = app_dir / "out" / "summary.json"
        if summary_p.exists():
            try:
                s = json.loads(summary_p.read_text(encoding="utf-8"))
                rec["findings_total"] = s.get("findings_total")
                rec["findings_by_type"] = s.get("findings_by_rule_type")
                rec["gaps"] = len(s.get("gaps") or [])
            except json.JSONDecodeError:
                pass
        rep = app_dir / "out" / "mobile-report.pdf"
        rec["report"] = str(rep) if rep.exists() else None
        results.append(rec)
        print(f"  [{rec['status']}] {pkg}  结论 {rec.get('findings_total', '?')} 条"
              + ("  报告已生成" if rec.get("report") else ""))

    ok = [r for r in results if r["status"] in ("ok", "static_ok")]
    (batch / "batch-summary.json").write_text(json.dumps(
        {"status": "ok" if len(ok) == len(results) else "partial",
         "batch_dir": str(batch), "samples": len(results), "succeeded": len(ok),
         "results": results, "selftest": selftest,
         "note": "每个样本的判据在 <批次>/<包名>/verification.json；"
                 "本文件只是汇总，不能替代逐样本判据。"},
        ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (ROOT / "output" / "latest-thirdparty-batch.txt").write_text(str(batch), encoding="utf-8")
    print(json.dumps({"status": "ok" if len(ok) == len(results) else "partial",
                      "batch_dir": str(batch), "samples": len(results),
                      "succeeded": len(ok),
                      "failed": [r["name"] for r in results if r not in ok]},
                     ensure_ascii=False, indent=2))
    return 0 if len(ok) == len(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
