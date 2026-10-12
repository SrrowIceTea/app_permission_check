#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""第三方 APK 的**设备端端到端**：装样本 → 钩子 + 代理 → UI 驱动 → 关联 → 证据包 → 报告。
仅用于授权测试（自有设备 / 已授权的公开第三方样本）。

为什么另写而不改 `mobile/tools/device_run.py`：夹具版把包名、按钮 resource-id、logcat
tag 全写死，第三方样本没有这些；改它会破坏已交付的夹具链路。第三方路径"跑不通必须新写"
的三处：
  1) **触发层**：`trigger.py` 依赖夹具的 `btnDeviceId`；改用 `ui_trigger.py` 的
     `uiautomator dump` 驱动，不写死坐标、每次点击留点击前/后两份 XML。
  2) **白名单**：不显式传 `--allow-package` + `VSCAN_PACKAGES` 会**钩子全不挂且不报错**。
  3) **流量路径**：夹具走 reverse 模式固定指向宿主上游；第三方样本要访问自己的服务端，
     改用**常规代理模式** + 设备全局代理。

判据与失败都写 `verification.json`；失败运行同样保留现场。
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(HERE))
import thirdparty_env as env      # noqa: E402
import thirdparty_ui_flow as flow  # noqa: E402  UI 探索（dump 驱动，不写死坐标）

MOBILE = ROOT / "mobile"
PY = sys.executable


def apk_permissions(apk: Path, build_tools: str) -> list[str]:
    import subprocess
    aapt2 = str(Path(build_tools) / "aapt2.exe")
    # 必须给超时：无超时的 subprocess.run 一卡住就是整条链停摆，报错里还毫无线索。
    out = subprocess.run([aapt2, "dump", "permissions", str(apk)],
                         capture_output=True, text=True, encoding="utf-8",
                         errors="replace", timeout=180).stdout
    return sorted({m.group(1) for m in re.finditer(r"uses-permission: name='([^']+)'", out)})


def has_api_key() -> bool:
    """是否已配置可用的 LLM key（环境变量优先，其次 config.local.json）。

    与 `ai/llm_client.py` 的判定口径保持一致：占位符等于没配。
    """
    import os
    placeholders = {"", "PUT-YOUR-KEY-HERE", "sk-xxx", "YOUR_API_KEY"}
    key = (os.environ.get("VSCAN_LLM_API_KEY") or "").strip()
    if not key:
        cfg = MOBILE / "ai" / "config.local.json"
        if cfg.exists():
            try:
                key = str(json.loads(cfg.read_text(encoding="utf-8")).get("api_key") or "").strip()
            except (json.JSONDecodeError, OSError):
                key = ""
    return key not in placeholders


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--apk", required=True)
    ap.add_argument("--package", required=True)
    ap.add_argument("--main-activity", required=True)
    ap.add_argument("--out", required=True, help="交付目录（已存在则沿用）")
    ap.add_argument("--app-category", default="utility")
    ap.add_argument("--seconds", type=int, default=150, help="钩子会话时长")
    ap.add_argument("--max-rounds", type=int, default=16)
    ap.add_argument("--frida-server", default=str(ROOT / "output" / "_frida" / "frida-server"))
    ap.add_argument("--geo", default="116.397,39.909", help="模拟器坐标注入 lon,lat；空串关闭")
    ap.add_argument("--build-tools", default="D:/Anroid/SDK/build-tools/36.1.0")
    ap.add_argument("--provenance", default=None, help="样本溯源 JSON，拷入交付目录")
    ap.add_argument("--static-dir", default=None, help="静态分析产物目录，拷入交付目录 static/")
    ap.add_argument("--skip-ai", action="store_true")
    args = ap.parse_args()

    apk = Path(args.apk).resolve()
    out = Path(args.out).resolve()
    session = out / "session"
    session.mkdir(parents=True, exist_ok=True)
    o = out / "out"
    o.mkdir(exist_ok=True)
    checks: list[dict] = []

    def check(name: str, code: int, optional: bool = False, note: str | None = None) -> int:
        e = {"name": name, "exit_code": code}
        if optional:
            e["optional"] = True
        if note:
            e["note"] = note
        checks.append(e)
        return code

    if not apk.exists():
        sys.exit(f"[fatal] 样本不存在：{apk}")
    # 溯源与静态产物按**样本同一性**（APK sha256）绑定，与动态运行无关；拷进交付目录使交付自洽，
    # 原文不在此重算，避免"看起来是这轮做的"。
    if args.provenance and Path(args.provenance).exists():
        shutil.copy2(args.provenance, out / "sample-provenance.json")
        check("provenance_copied", 0, note=Path(args.provenance).name)
    if args.static_dir and Path(args.static_dir).is_dir():
        dst = out / "static"
        if dst.exists():
            shutil.rmtree(dst)
        shutil.copytree(args.static_dir, dst)
        check("static_copied", 0, note=f"{Path(args.static_dir).name} -> static/")
    if not env.wait_boot():
        sys.exit("[fatal] 设备未在超时内启动完成")

    ok, state = env.ensure_frida_server(out / "frida-check.log", Path(args.frida_server))
    check("frida_server", 0 if ok else 1, note=f"state={state}")
    check("network_up", 0 if env.ensure_wifi(out / "wifi-check.log") else 1,
          note="设备侧实测 TCP（多目标任一可连即通过）。不查路由表：Android 走策略路由，"
               "default 在 per-network 表里，`ip route` 看不到")

    prev_proxy = env.get_proxy()
    setattr(main, "_prev_proxy", prev_proxy)

    # 先卸载再装：`install -r` 保留应用数据，应用带着旧缓存/旧定位进场，首次取数会被
    # 自己的限流吃掉（实测：不干净装时窗口内零外发，干净装则启动即连 open-meteo:443）。
    # 隐私扫描要的本来就是**首次运行**状态。
    env.adb("uninstall", args.package, timeout=120)
    install = env.adb("install", "-r", "-g", str(apk), timeout=300)
    (out / "install.log").write_text(install.stdout + install.stderr, encoding="utf-8")
    check("install", 0 if "Success" in install.stdout else 1)

    # 坐标注入（仅模拟器有 `emu`）。实测该 AVD 无 Google 连通性，应用的 GMS 定位路径会报
    # "Something went wrong"；注入坐标后系统 LocationManager 才给得出位置，应用才走得到网络请求。
    if args.geo:
        lon, lat = args.geo.split(",")
        r = env.adb("emu", "geo", "fix", lon, lat, timeout=60)
        (out / "geo-fix.log").write_text(f"{r.stdout}\n{r.stderr}\n", encoding="utf-8")
        check("geo_injected", 0 if "OK" in r.stdout else 1, optional=True,
              note=f"geo fix {lon},{lat} (模拟器专用；真机无此路径)")

    env.adb("shell", "logcat", "-c", timeout=30)

    # 设备侧连接采样：不经过任何被挂钩的 Java 层，直接看内核有没有外发。
    # 它回答的是钩子回答不了的问题——"零事件"到底是没外发，还是外层栈没被覆盖。
    # **必须在 `am start` 之前就开**：应用的外发就发生在启动那一刻（实测 logcat 里
    # 启动当秒就有 uid=10236 的 NetworkRequest，而晚 8s 才起的采样一条都没采到）。
    # 按**包名**采（不是按 uid 读 /proc/net/tcp）：Android 隔离了应用网络命名空间；
    # 且应用会在窗口内崩溃重启（实测 pid 10658→14037），只有让设备端每轮重解 pid，
    # 才不会在那之后整段失明。也不过滤 uid——过滤等于静默丢数据，丢了补不回来。
    uid = env.app_uid(args.package)
    collector = env.start_conn_probe(session, out / "conn-probe.log",
                                     args.package, args.seconds)
    check("conn_probe_started", 0, optional=True,
          note=f"package={args.package} app_uid={uid}（设备端每轮重解 pid，不过滤 uid）")

    # 冷启动竞争：先 am start，等到 pid 再挂钩子（钩子是 attach 模式）
    env.adb("shell", "am", "start", "-W", "-n",
            f"{args.package}/{args.main_activity}", timeout=150)
    pid = env.wait_for_app(args.package)
    check("app_started", 0 if pid else 1,
          note=f"pid={pid}" if pid else "应用未在超时内出现（冷启动竞争或启动崩溃）")
    if not pid:
        env.kill_tree(collector, out / "kill-conn.log")   # 早退也不能留孤儿
        (out / "verification.json").write_text(json.dumps(
            {"passed": False, "checks": checks, "failed": ["app_started"],
             "package": args.package}, ensure_ascii=False, indent=2), encoding="utf-8")
        print(json.dumps({"status": "failed", "reason": "app_started"}, ensure_ascii=False))
        return 1

    # 代理：常规模式下让设备把 HTTP(S) 交给宿主 mitmproxy
    mitm = env.start_mitm(session, out / "mitm.log", args.package)
    env.set_proxy(f"{env.GUEST_HOST}:{env.MITM_PORT}", out / "proxy-set.log")
    proxy_now = env.get_proxy()
    check("proxy_set_for_capture", 0 if str(env.MITM_PORT) in proxy_now else 1,
          note=f"http_proxy={proxy_now!r} (原值 {prev_proxy!r})")

    hooks = [
        env.start_hook(MOBILE / "hooks" / "dist" / "hook_privacy.bundle.js", session,
                       "reads.jsonl", out / "hook-privacy.log", args.seconds, args.package),
        env.start_hook(MOBILE / "hooks" / "dist" / "hook_consent.bundle.js", session,
                       "consent.jsonl", out / "hook-consent.log", args.seconds, args.package),
        # egress / TLS 绕过直接复用 phase3 成品：Socket.connect 与证书校验与"车载"无关
        env.start_hook(ROOT / "phase3" / "dist" / "hook_egress.bundle.js", session,
                       "egress.jsonl", out / "hook-egress.log", args.seconds, args.package),
        # **第三方专用**出站钩子：phase3 版只挂 `java.net.Socket.connect`，而真实样本的
        # HTTPS 走 Apache HttpClient，connect() 在 conscrypt 子类里被重写，钩子一条抓不到。
        # 这一版挂到 libcore 汇聚点 + URI/URL 构造，见 mobile/hooks/hook_egress_tp.js。
        env.start_hook(MOBILE / "hooks" / "dist" / "hook_egress_tp.bundle.js", session,
                       "egress_tp.jsonl", out / "hook-egress-tp.log", args.seconds, args.package),
        # **第三方专用** TLS 绕过：裁掉了 phase3 版里会触发 ART abort 的
        # HttpsURLConnection 主机名钩子（证据见 mobile/hooks/tls_bypasses_tp.js 头部）。
        env.start_hook(MOBILE / "hooks" / "dist" / "ssl_pinning_tp.bundle.js", session,
                       "tls.jsonl", out / "hook-tls.log", args.seconds, args.package),
    ]
    time.sleep(9)   # 等钩子挂上：钩子掉线与"应用没动作"长得一样（D309）

    actions = flow.explore(out / "ui", args.seconds, args.max_rounds, args.package,
                           args.main_activity)
    (out / "ui-actions.json").write_text(json.dumps(
        {"actions": actions, "note": "每次点击的点击前/后 XML 见 ui/ 目录，可回溯"},
        ensure_ascii=False, indent=2), encoding="utf-8")
    taps = [a for a in actions if a["action"] == "tap"]
    check("ui_taps_made", 0 if taps else 1, note=f"完成 {len(taps)} 次点击")

    env.set_proxy(prev_proxy if prev_proxy not in ("", "null") else ":0", out / "proxy-restore.log")
    # 收**整棵进程树**，不是只收直接子进程。孤儿会攥住句柄，让编排层之后每一次
    # subprocess.run 都阻塞（实测：policy_fetch 卡满 300s 超时、correlate 不返回；
    # 杀掉孤儿后整条尾段立刻跑完）。详见 thirdparty_env.kill_tree 的注释。
    for i, proc in enumerate(hooks + [mitm] + ([collector] if collector else [])):
        env.kill_tree(proc, out / f"kill-{i}.log")
    time.sleep(3)   # 给 mitmproxy 的 done() 排空挂起队列

    # 应用是否在窗口内死亡，以及死于什么。"窗口后半段没事件"有两种含义：应用没做，
    # 还是应用已经死了——只看事件文件分不出来，所以必须单独取证。
    death = env.app_death_reason(args.package)
    (out / "app-death.json").write_text(json.dumps(death, ensure_ascii=False, indent=2) + "\n",
                                        encoding="utf-8")
    check("app_alive_at_window_end", 0 if death["alive_at_end"] else 1, optional=True,
          note="应用在窗口结束时仍存活" if death["alive_at_end"] else
          "应用在窗口内死亡：" + str(death.get("cause") or (death["fatal_lines"] or ["原因未记录"])[0]))

    # 钩子必须自证挂载（M016）：没有 ARMED 就是没挂上，不是"应用没动作"
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
        script_error = any(e.get("ev") in ("SCRIPT_ERROR", "ERROR") for e in events)
        check(f"hook_{name}_armed", 0 if armed else 1,
              note=None if armed else ("钩子脚本抛错，未挂载" if script_error
                                       else "没有 ARMED 事件：钩子没跑起来"))

    # ---- 关联 / 证据包 / 报告 ----
    perms = apk_permissions(apk, args.build_tools)
    (o / "requested-permissions.txt").write_text("\n".join(perms) + "\n", encoding="utf-8")
    check("requested_permissions_nonempty", 0 if perms else 1, note=f"{len(perms)} 条")

    policy_store = o / "policy"
    check("policy_from_apk", env.run(
        [PY, str(MOBILE / "policy" / "policy_fetch.py"), "--from-apk", str(apk),
         "--store", str(policy_store), "--tag", "apk"], out / "policy.log", timeout=300),
        optional=True, note="APK 内可能不含隐私政策页；缺失会写进 summary.gaps")

    check("correlate", env.run(
        [PY, str(MOBILE / "analyze" / "correlate_mobile.py"),
         "--session", str(session), "--package", args.package,
         "--permissions", str(o / "requested-permissions.txt"),
         "--app-category", args.app_category,
         "--policy-store", str(policy_store),
         "--out", str(o / "findings.jsonl"), "--summary", str(o / "summary.json")],
        out / "correlate.log"))

    sha = hashlib.sha256(apk.read_bytes()).hexdigest()
    bundle_cmd = [PY, str(MOBILE / "ai" / "evidence_bundle.py"),
                  "--session", str(session), "--findings", str(o / "findings.jsonl"),
                  "--package", args.package, "--app-category", args.app_category,
                  "--policy-store", str(policy_store), "--apk-sha256", sha,
                  "--device", env.adb("shell", "getprop", "ro.build.fingerprint",
                                      timeout=45).stdout.strip(),
                  "--out", str(o / "bundle.json")]
    # 编排层知道、而工具无法从数据里推出来的缺口，逐条写进 bundle.gaps（前缀 [orch]）。
    for note in env.orchestrator_notes(death):
        bundle_cmd += ["--note", note]
    check("bundle", env.run(bundle_cmd, out / "bundle.log"))

    # 旁路证据索引：egress_tp / tls / conns / ui-actions 不进 bundle、不参与规则求值，
    # 不单独成文就等于在报告里不存在。原始 JSONL 仍是证据本体，这里只是索引与计数。
    check("supplementary_index", env.run(
        [PY, str(HERE / "supplementary_evidence.py"), "--session", str(session),
         "--out-dir", str(out), "--package", args.package, "--app-uid", str(uid),
         "--out", str(o / "supplementary-evidence.json")],
        out / "supplementary.log"), optional=True, note="旁路证据索引（不进 bundle）")

    ai_dir = o / "ai"
    if not args.skip_ai:
        # **配了 key 就真跑，没配才 dry-run。** 原先这里是无条件 `--dry-run`，
        # 理由是"未配 key"——但 key 一旦配上（config.local.json / VSCAN_LLM_API_KEY），
        # 这一步会**静默跳过整个 AI 研判**：报告生成、验收照常通过，
        # 第五至八章写着"本轮未生成 AI 研判"，看起来像"没跑"，实则是"跑了但没联网"。
        ai_cmd = [PY, str(MOBILE / "ai" / "ai_review.py"),
                  "--bundle", str(o / "bundle.json"), "--out-dir", str(ai_dir)]
        if has_api_key():
            check("ai_review", env.run(ai_cmd, out / "ai.log", timeout=1800),
                  note="已配置 API key：真实调用")
        else:
            check("ai_review_dry_run",
                  env.run(ai_cmd + ["--dry-run"], out / "ai.log", timeout=600),
                  note="未配置 API key：仅渲染提示词、不联网")

    rep = [PY, str(MOBILE / "report" / "report_mobile.py"),
           "--bundle", str(o / "bundle.json"), "--session", session.name,
           "--out", str(o / "mobile-report.pdf")]
    # 只要 AI 目录存在就交给报告：dry-run（未配 key）也往 out/ai/prompts/ 写提示词，
    # 旧条件（要求 stage3.json）会让它们变孤儿文件、报告只能印硬编码的错误路径。
    if ai_dir.exists():
        rep += ["--ai-out-dir", str(ai_dir)]
    check("report", env.run(rep, out / "report.log"))

    failed = [c["name"] for c in checks if c.get("exit_code") and not c.get("optional")]
    optional_failed = [c["name"] for c in checks if c.get("exit_code") and c.get("optional")]
    (out / "verification.json").write_text(json.dumps(
        {"passed": not failed, "checks": checks, "failed": failed,
         "optional_failed": optional_failed, "session": session.name,
         "package": args.package, "apk_sha256": sha,
         "app_category": {"value": args.app_category, "source": "declared"},
         "device": {"serial": env.adb("get-state", timeout=30).stdout.strip(),
                    "fingerprint": env.adb("shell", "getprop", "ro.build.fingerprint",
                                           timeout=45).stdout.strip(),
                    "build_type": env.adb("shell", "getprop", "ro.build.type",
                                          timeout=45).stdout.strip()}},
        ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"status": "passed" if not failed else "failed", "out": str(out),
                      "checks": len(checks), "failed": failed,
                      "optional_failed": optional_failed}, ensure_ascii=False, indent=2))
    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
