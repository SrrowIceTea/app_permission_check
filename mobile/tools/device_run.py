#!/usr/bin/env python3
"""移动隐私检测的**设备端端到端**：装夹具 → 钩子 + 代理 → 触发 → 关联 → 证据包 → 报告。

仅用于授权测试（已获授权的样本与设备）。

每一步都有明确判据，失败保留现场（沿用本项目"失败运行同样保留"的规矩）：
    output/mobile-device-<时间戳>/
        verification.json   判据（passed 与逐项 exit_code）
        session/            原始采集（reads/consent/flows/egress.jsonl、logcat）
        out/                findings / summary / bundle / 报告

跑法：
    python mobile/tools/device_run.py                     # 全流程（AI 阶段有 key 才跑）
    python mobile/tools/device_run.py --skip-ai           # 只到证据包与工具报告
    python mobile/tools/device_run.py --user 10           # AAOS 上应用跑在 user 10

拆模块约定（P2，2026-10-21）：设备操作函数（adb 封装 / 启动检查 / 子进程 / UI 操作）
在 `device_run_helpers.py`；本文件只留编排（main）与判据。
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

from device_run_helpers import (  # noqa: E402
    ROOT, MOBILE, PY, PKG, APK, adb, run, wait_boot, wait_for_app, pick_free_port,
    ensure_frida_server, ensure_wifi, check_proxy_clean, start_collector, start_mitm,
    start_hook, clear_system_dialogs, trigger, try_answer_permission_dialog,
)
import thirdparty_env as tp_env  # noqa: E402   stop_hook 优雅停止哨兵


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--user", type=int, default=None)
    ap.add_argument("--seconds", type=int, default=150, help="钩子会话时长")
    ap.add_argument("--skip-ai", action="store_true")
    ap.add_argument("--app-category", default="map_navigation")
    args = ap.parse_args()

    stamp = time.strftime("%Y%m%d-%H%M%S")
    out = ROOT / "output" / f"mobile-device-{stamp}"
    session = out / "session"
    session.mkdir(parents=True, exist_ok=True)
    checks: list[dict] = []

    def check(name: str, code: int, optional: bool = False) -> int:
        """optional=True 的项失败**不判整轮失败**，但仍如实记进 verification.json——
        "可选"不等于"不记"，否则缺了隐私政策会看不出是没提取到还是本轮没做。"""
        entry = {"name": name, "exit_code": code}
        if optional:
            entry["optional"] = True
        checks.append(entry)
        return code

    if not APK.exists():
        sys.exit(f"[fatal] 夹具 APK 不存在：{APK}\n先在 mobile/fixture-app 跑 ./gradlew :app:assembleDebug")
    if not wait_boot():
        sys.exit("[fatal] 设备未在超时内启动完成（adb devices 看一眼）")

    check("frida_server", 0 if ensure_frida_server(out / "frida-check.log") else 1)
    check("network_up", 0 if ensure_wifi(out / "wifi-check.log") else 1)
    check("proxy_clean", 0 if check_proxy_clean(out / "proxy-check.log") else 1)

    install = adb("install", "-r", "-g", str(APK), timeout=300)
    (out / "install.log").write_text(install.stdout + install.stderr, encoding="utf-8")
    check("install", 0 if "Success" in install.stdout else 1)

    adb("shell", "logcat", "-c", timeout=30)

    # **先启动应用、等到进程真的出现，再挂钩子。**
    # 钩子是 attach 模式（core/frida_host/run.py 用 pidof 找进程）；顺序反了会得到
    # CalledProcessError: pidof 退出码 1 —— 与"应用装机失败"看起来一样。
    start_cmd = ["shell", "am", "start"]
    if args.user is not None:
        start_cmd += ["--user", str(args.user)]
    start_cmd += ["-W", "-n", f"{PKG}/.MainActivity"]
    adb(*start_cmd, timeout=120)
    pid = wait_for_app(PKG)
    checks.append({"name": "app_started", "exit_code": 0 if pid else 1,
                   "note": f"pid={pid}" if pid else
                           "应用未在 40s 内出现：冷启动竞争或装到了别的用户（--user）"})
    if not pid:
        (out / "verification.json").write_text(json.dumps(
            {"passed": False, "checks": checks, "failed": ["app_started"]},
            ensure_ascii=False, indent=2), encoding="utf-8")
        print(json.dumps({"status": "failed", "out": str(out), "reason": "app_started"},
                         ensure_ascii=False))
        return 1

    upstream_port = pick_free_port()
    collector = start_collector(out / "collector.log", upstream_port)
    mitm = start_mitm(session, out / "mitm.log", upstream_port)
    # **单 agent 合并 bundle**（2026-10-16 A1 修复）：privacy/consent/egress_tp/
    # ssl_pinning_tp 四模块在同一个 JS 上下文里装配——frida-java-bridge 不支持
    # "多脚本各自替换方法"（实测双脚本 ~50% 触发 ART 的 GetOatQuickMethodHeader
    # FATAL，单脚本 5/5 稳定；见 mobile/hooks/build.mjs 注释）。vehicle 版
    # egress/pinning 一并退役（观测面被 tp 版覆盖；vehicle 版 TLS 含已实证会炸 ART
    # 的 HttpsURLConnection 手法）。夹具不做证书固定，但目标 SDK 不信任用户证书，
    # tp 版 TLS 绕过同样覆盖 conscrypt 信任链（实测 SSLHandshakeException:
    # Trust anchor not found 由它解决）。
    hooks = [
        start_hook(MOBILE / "hooks" / "dist" / "hook_all.bundle.js", session,
                   "reads.jsonl", out / "hook-all.log", args.seconds),
    ]
    time.sleep(8)   # 等钩子挂上；D309：钩子掉线与"应用没动作"长得一样

    # 顺序刻意如此：**先读、后弹政策**——这正是「同意前收集」的典型形态
    # （实测：把 btnPolicy 放第一个，同意代理信号早于所有读取，no_consent_read
    # 一条都不会命中，看起来像"规则没生效"）。
    sequence = ["btnDeviceId", "btnLocation", "btnContacts", "btnApps", "btnClipboard",
                "btnSms", "btnPerm", "btnDeviceId", "btnLocation",
                "btnEgressHttp", "btnEgressHttps", "btnPolicy"]
    for i, name in enumerate(sequence):
        clear_system_dialogs(out / f"dialogs-{i:02d}.xml")
        code = trigger(name, out / f"trigger-{i:02d}-{name}.log", args.user)
        check(f"trigger_{name}_{i:02d}", code)
        if name == "btnPolicy":
            # 政策弹窗会盖住界面（实测：不关掉，后面 11 个按钮全部"找不到控件"）。
            # 夹具侧 8 秒自动关；这里再补一个 BACK 立刻回到主界面。
            time.sleep(1.0)
            adb("shell", "input", "keyevent", "4", timeout=30)
            time.sleep(1.0)
        if name == "btnPerm":
            handled, how = try_answer_permission_dialog(out / "perm-dialog.log")
            checks.append({"name": "perm_dialog_answered", "exit_code": 0 if handled else 1,
                           "note": f"处理方式={how}" + ("" if handled else
                                    "（没有弹窗或形状不认识；两者都会让后续按钮被遮挡，"
                                    "脚本会在下一轮先滚回顶部再找）")})
            time.sleep(2)
        time.sleep(1.2)

    logcat = adb("shell", "logcat", "-d", "-s", "VSPrivacyDemo:I", timeout=60).stdout
    (out / "logcat.txt").write_text(logcat, encoding="utf-8")
    checks.append({"name": "app_logged_actions", "exit_code": 0 if "按下按钮" in logcat else 1})

    # **钩子必须证明自己挂上了。** 实测：钩子在 main() 里抛 TypeError 时，
    # 采集文件里只有一条 SCRIPT_ERROR，而所有按钮触发都"成功"——
    # 整个运行看起来正常，实际一条读取都没观测到（D309 同类）。
    for name, fname in (("privacy", "reads.jsonl"), ("consent", "consent.jsonl")):
        events = []
        p = session / fname
        if p.exists():
            for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
                if line.strip():
                    try:
                        events.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
        armed = any(e.get("ev") == "ARMED" for e in events)
        script_error = any(e.get("ev") == "SCRIPT_ERROR" for e in events)
        checks.append({"name": f"hook_{name}_armed", "exit_code": 0 if armed else 1,
                       "note": None if armed else
                       ("钩子脚本抛错，未挂载" if script_error else "没有 ARMED 事件：钩子没跑起来")})

    # hooks 走**优雅停止**（哨兵 → 正常 detach），替代 proc.terminate()（Windows 上
    # 即强杀，会触发 CheckJNI 的 DeleteGlobalRef teardown abort——2026-10-16 实测，
    # 见 thirdparty_env.stop_hook）；mitm/collector 维持原强杀 + 排空。
    for i, handle in enumerate(hooks):
        tp_env.stop_hook(handle, out / f"hooks-stop-{i}.log")
    for proc in [mitm, collector]:
        try:
            proc.terminate()
            proc.wait(timeout=30)
        except Exception:  # noqa: BLE001
            proc.kill()
    time.sleep(3)   # 给 mitmproxy 的 done() 排空挂起队列

    # 合并产物分流（2026-10-16）：单 agent 合并 bundle 的事件全落 reads.jsonl，
    # 这里按 src 分流回 consent/egress/tls 独立文件——下游（correlate/evidence_bundle/
    # build_delivery）零改动。独立脚本模式下为 no-op。见 mobile/tools/split_events.py。
    check("split_events", run([PY, str(MOBILE / "tools" / "split_events.py"),
                               "--session", str(session)], out / "split.log"),
          optional=True)

    # ---- 关联 / 证据包 / 报告 ----
    o = out / "out"
    o.mkdir(exist_ok=True)
    perm_file = o / "requested-permissions.txt"
    dump = adb("shell", "dumpsys", "package", PKG, timeout=90).stdout
    perms = sorted({m.split(":")[1].strip() for m in dump.splitlines()
                    if "permission" in m and ":" in m and m.strip().startswith("android.permission")})
    perm_file.write_text("\n".join(perms) + "\n", encoding="utf-8")
    checks.append({"name": "requested_permissions_nonempty", "exit_code": 0 if perms else 1})

    # 隐私政策：**直接从被检 APK 内部提取**（assets 里的政策页）——
    # 这条路径离线、可复现，且不依赖应用商店页面的结构。
    policy_store = o / "policy"
    check("policy_from_apk", run([PY, str(MOBILE / "policy" / "policy_fetch.py"),
                                  "--from-apk", str(APK), "--store", str(policy_store),
                                  "--tag", "apk"], out / "policy.log", timeout=300),
          optional=True)

    check("correlate", run([PY, str(MOBILE / "analyze" / "correlate_mobile.py"),
                            "--session", str(session), "--package", PKG,
                            "--permissions", str(perm_file),
                            "--app-category", args.app_category,
                            "--policy-store", str(policy_store),
                            "--out", str(o / "findings.jsonl"),
                            "--summary", str(o / "summary.json")], out / "correlate.log"))
    check("bundle", run([PY, str(MOBILE / "ai" / "evidence_bundle.py"),
                         "--session", str(session), "--findings", str(o / "findings.jsonl"),
                         "--package", PKG, "--app-category", args.app_category,
                         "--policy-store", str(policy_store),
                         "--apk-sha256", __import__("hashlib").sha256(APK.read_bytes()).hexdigest(),
                         "--apk", str(APK),
                         "--device", adb("shell", "getprop", "ro.build.fingerprint",
                                         timeout=30).stdout.strip(),
                         "--out", str(o / "bundle.json")], out / "bundle.log"))

    ai_dir = o / "ai"
    if not args.skip_ai:
        code = run([PY, str(MOBILE / "ai" / "ai_review.py"),
                    "--bundle", str(o / "bundle.json"), "--out-dir", str(ai_dir)],
                   out / "ai.log", timeout=1800)
        checks.append({"name": "ai_review", "exit_code": code,
                       "note": None if code == 0 else
                       "AI 阶段未完成（未配 key / 网络 / 校验未过）；报告会如实声明缺失"})

    rep_cmd = [PY, str(MOBILE / "report" / "report_mobile.py"),
               "--bundle", str(o / "bundle.json"), "--session", session.name,
               "--out", str(o / "mobile-report.pdf")]
    if ai_dir.exists() and (ai_dir / "stage3.json").exists():
        rep_cmd += ["--ai-out-dir", str(ai_dir)]
    check("report", run(rep_cmd, out / "report.log"))

    failed = [c["name"] for c in checks
              if c.get("exit_code") not in (0,) and not c.get("optional")]
    optional_failed = [c["name"] for c in checks
                       if c.get("exit_code") not in (0,) and c.get("optional")]
    passed = not failed
    if optional_failed:
        print(json.dumps({"可选步骤未完成": optional_failed}, ensure_ascii=False))
    (out / "verification.json").write_text(json.dumps(
        {"passed": passed, "checks": checks, "failed": failed,
         "optional_failed": optional_failed,
         "session": session.name, "package": PKG}, ensure_ascii=False, indent=2),
        encoding="utf-8")
    (ROOT / "output" / "latest-mobile-device.txt").write_text(str(out), encoding="utf-8")
    print(json.dumps({"status": "passed" if passed else "failed", "out": str(out),
                      "checks": len(checks), "failed": failed}, ensure_ascii=False, indent=2))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())