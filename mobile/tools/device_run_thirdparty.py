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
import pcap_capture               # noqa: E402  设备端抓包（P0，2026-10-18）
import pcap_http                  # noqa: E402  pcap → 完整 HTTP 报文（复用 tshark）
sys.path.insert(0, str(ROOT))
from core import sdk_paths  # noqa: E402   SDK 路径统一解析（§8.2 B-4）

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


def _emit_events(events: Path | None, stage: str, status: str, message: str = "") -> None:
    """把阶段事件追加到 events.jsonl，供编排层（pipeline server）的 SSE 实时读取。

    只追加、只 flush；**绝不失败主流程**——事件上报是旁路，不能因为它把检测搞挂。
    status 取值：running（进入阶段）/ done（成功）/ failed（失败）/ skipped（跳过）。
    """
    if events is None:
        return
    try:
        with events.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps({"ts": time.time(), "stage": stage, "status": status,
                                 "message": message}, ensure_ascii=False) + "\n")
            fh.flush()
    except OSError:
        pass


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
    ap.add_argument("--build-tools",
                    default=str(sdk_paths.sdk_dir("build-tools", "36.1.0")))
    ap.add_argument("--provenance", default=None, help="样本溯源 JSON，拷入交付目录")
    ap.add_argument("--static-dir", default=None, help="静态分析产物目录，拷入交付目录 static/")
    ap.add_argument("--skip-ai", action="store_true")
    ap.add_argument("--no-hooks", action="store_true",
                    help="对照实验：不挂任何 Frida 钩子。用于回答「应用在窗口内死亡是不是"
                         "插桩引起的」——同一 App、同一流程，只少钩子这一项（2026-10-13 "
                         "待办的控制实验，见 mobile/DECISIONS.md）。")
    ap.add_argument("--events", default=None,
                    help="阶段事件落盘路径（JSONL，供编排层 SSE 实时读取）")
    ap.add_argument("--reuse-mitm", action="store_true",
                    help="复用编排层预启动的 mitmproxy（端口已监听则直接用；未监听则"
                         "回退为自行启动）。冷启动前置的原因见 pipeline/runner 的 "
                         "_start_early_mitm 注释")
    ap.add_argument("--no-pcap", action="store_true",
                    help="关闭设备端 pcap 采集（默认开）。关掉后不再产出完整 HTTP 报文，"
                         "只有 hook 的 SSL_read/write 分片——gzip/chunked/h2 都读不到，"
                         "报告会把这条记成缺口")
    ap.add_argument("--spawn-hook", action="store_true",
                    help="用 Frida spawn 注入（钩子在应用第一条指令前就位）替代 attach。"
                         "attach 模式的应用启动那一刻的联网（egress 事件）全在钩子装上之前，"
                         "导致 egress 0 事件、flows 归因 unresolved（2026-10-19 实测定性）。"
                         "spawn 模式下跳过 am start，由 run.py --spawn 启动应用并挂钩后 resume。")
    args = ap.parse_args()

    # 多设备且未指定 ANDROID_SERIAL → 启动前就停。理由见 thirdparty_env.device_guard：
    # 裸 adb 命令在多设备下全部报错，且失败形态是静默空结果（假"已恢复"、假"原因未记录"）。
    guard = env.device_guard()
    if guard:
        sys.exit("[fatal] " + guard)

    apk = Path(args.apk).resolve()
    out = Path(args.out).resolve()
    session = out / "session"
    session.mkdir(parents=True, exist_ok=True)
    o = out / "out"
    o.mkdir(exist_ok=True)
    checks: list[dict] = []

    events_path = Path(args.events) if args.events else None

    def emit(stage: str, status: str, message: str = "") -> None:
        _emit_events(events_path, stage, status, message)

    def check(name: str, code: int, optional: bool = False, note: str | None = None) -> int:
        e = {"name": name, "exit_code": code}
        if optional:
            e["optional"] = True
        if note:
            e["note"] = note
        checks.append(e)
        return code

    if not apk.exists():
        emit("prepare", "failed", f"样本不存在：{apk}")
        sys.exit(f"[fatal] 样本不存在：{apk}")
    emit("prepare", "running", f"目标 {args.package}，会话 {args.seconds}s")
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
    emit("boot", "running", "确认设备启动完成")
    if not env.wait_boot():
        emit("boot", "failed", "设备未在超时内启动完成")
        sys.exit("[fatal] 设备未在超时内启动完成")
    emit("boot", "done", "设备已启动")

    emit("frida_server", "running", "确保 frida-server 以 root 运行")
    ok, state = env.ensure_frida_server(out / "frida-check.log", Path(args.frida_server))
    check("frida_server", 0 if ok else 1, note=f"state={state}")
    emit("frida_server", "done" if ok else "failed", f"state={state}")
    emit("network", "running", "确认设备外网连通")
    net_ok = env.ensure_wifi(out / "wifi-check.log")
    check("network_up", 0 if net_ok else 1,
          note="设备侧实测 TCP（多目标任一可连即通过）。不查路由表：Android 走策略路由，"
               "default 在 per-network 表里，`ip route` 看不到")
    emit("network", "done" if net_ok else "failed", "外网连通" if net_ok else "外网不通")

    # QUIC 压制（2026-10-18 起）：代理只接管 TCP，客户端一旦协商到 HTTP/3 就整条
    # 绕过 mitmproxy。在设备内核层丢弃 UDP/443，逼它按规范回退 TCP/443。
    # **必须在 am start 之前**：外发就发生在启动那一刻（见 conn_probe 注释）。
    # 失败不阻断：只记成缺口——"没拦住"不能写成"没流量"。
    emit("quic", "running", "压制 QUIC（设备侧 DROP UDP/443，逼 HTTP/3 回退 TCP）")
    quic_blocked = env.block_quic(out / "quic-block.log")
    check("quic_blocked", 0 if quic_blocked else 1, optional=True,
          note=("设备 OUTPUT 链首条为 `-p udp --dport 443 -j DROP`，QUIC 将回退 TCP"
                if quic_blocked else
                "未能插入规则（无 root / 内核缺 netfilter）——QUIC 流量仍绕过代理，"
                "报告须按「QUIC 不在覆盖内」标注"))
    emit("quic", "done" if quic_blocked else "failed",
         "UDP/443 已丢弃" if quic_blocked else "QUIC 压制失败，回落为声明边界")

    prev_proxy = env.get_proxy()
    setattr(main, "_prev_proxy", prev_proxy)

    # 先卸载再装：`install -r` 保留应用数据，应用带着旧缓存/旧定位进场，首次取数会被
    # 自己的限流吃掉（实测：不干净装时窗口内零外发，干净装则启动即连 open-meteo:443）。
    # 隐私扫描要的本来就是**首次运行**状态。
    emit("install", "running", f"安装样本 {args.package}")
    env.adb("uninstall", args.package, timeout=120)
    install = env.adb("install", "-r", "-g", str(apk), timeout=300)
    (out / "install.log").write_text(install.stdout + install.stderr, encoding="utf-8")
    check("install", 0 if "Success" in install.stdout else 1)
    emit("install", "done" if "Success" in install.stdout else "failed",
         "安装成功" if "Success" in install.stdout else "安装失败，见 install.log")

    # 坐标注入（仅模拟器有 `emu`）。实测该 AVD 无 Google 连通性，应用的 GMS 定位路径会报
    # "Something went wrong"；注入坐标后系统 LocationManager 才给得出位置，应用才走得到网络请求。
    if args.geo:
        lon, lat = args.geo.split(",")
        r = env.adb("emu", "geo", "fix", lon, lat, timeout=60)
        (out / "geo-fix.log").write_text(f"{r.stdout}\n{r.stderr}\n", encoding="utf-8")
        check("geo_injected", 0 if "OK" in r.stdout else 1, optional=True,
              note=f"geo fix {lon},{lat} (模拟器专用；真机无此路径)")

    # 启动 Activity 以**设备解析**为准，badging 只做回退：
    # aapt2 的 launchable-activity 给的是"第一个 LAUNCHER"，而第一个未必能启动——
    # 实测 F-Droid 的 panic.CalculatorActivity 在 manifest 里挂着 LAUNCHER，但类的 dex
    # 已被 R8 裁掉，`am start` 报 "Activity class does not exist"，整段设备检测死在
    # app_started。设备解析是系统对"点桌面图标"的权威回答（含 activity-alias）。
    resolved_activity = env.device_main_activity(args.package)
    main_activity = resolved_activity or args.main_activity
    (out / "main-activity.log").write_text(json.dumps(
        {"from_batch": args.main_activity, "from_device": resolved_activity,
         "used": main_activity}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    env.adb("shell", "logcat", "-c", timeout=30)

    # 设备侧连接采样：不经过任何被挂钩的 Java 层，直接看内核有没有外发。
    # 它回答的是钩子回答不了的问题——"零事件"到底是没外发，还是外层栈没被覆盖。
    # **必须在 `am start` 之前就开**：应用的外发就发生在启动那一刻（实测 logcat 里
    # 启动当秒就有 uid=10236 的 NetworkRequest，而晚 8s 才起的采样一条都没采到）。
    # 按**包名**采（不是按 uid 读 /proc/net/tcp）：Android 隔离了应用网络命名空间；
    # 且应用会在窗口内崩溃重启（实测 pid 10658→14037），只有让设备端每轮重解 pid，
    # 才不会在那之后整段失明。也不过滤 uid——过滤等于静默丢数据，丢了补不回来。
    uid = env.app_uid(args.package)
    emit("conn_probe", "running", f"开启设备侧连接采样（package={args.package}）")
    collector = env.start_conn_probe(session, out / "conn-probe.log",
                                     args.package, args.seconds, uid=uid)
    check("conn_probe_started", 0, optional=True,
          note=f"package={args.package} app_uid={uid}（设备端每轮重解 pid，不过滤 uid）")
    emit("conn_probe", "done", f"app_uid={uid}")

    # 设备端 pcap（P0，2026-10-18）：**必须在 am start 之前**起，和 conn_probe 同一个
    # 理由——外发就在启动那一刻。它解决的是 hook 结构性给不出的东西：hook 拿到的是
    # SSL_read/write 的分片（无连接标识、无边界），而 pcap 里 TCP 流 + TLS 记录层 +
    # HTTP 分帧齐全，交给 tshark 一条命令就能解出**完整报文并自动解 gzip/chunked**。
    # 失败不阻断采集：只记缺口——"没抓到"和"没有流量"必须能区分。
    pcap_rec = None
    if args.no_pcap:
        check("pcap_captured", 0, optional=True, note="--no-pcap：本轮不做 pcap 采集")
        emit("pcap", "skipped", "--no-pcap：不抓包，完整报文不可得")
    else:
        emit("pcap", "running", "设备端 pcap 采集（tcpdump）")
        pcap_rec = pcap_capture.PcapRecorder()
        pcap_ok, pcap_note = pcap_rec.start(out / "pcap-start.log", args.seconds + 120)
        check("pcap_started", 0 if pcap_ok else 1, optional=True, note=pcap_note)
        emit("pcap", "done" if pcap_ok else "failed", pcap_note)

    # 代理：常规模式下让设备把 HTTP(S) 交给宿主 mitmproxy。
    # **--reuse-mitm**（编排层路径）：模拟器冷启动前编排层已把代理拉起来——必须
    # 先于模拟器，因为 emulator 37.x 启动时探测代理可达性，不可达会把 SLIRP 强制
    # 重定向整条关掉（2026-10-16 实测 "Proxy will be ignored!"）。这里先探端口：
    # 活着直接复用；死了回退自行启动，不把"代理没了"静默带进采集。
    #
    # **2026-10-19：整块挪到 am start 之前**。原顺序是"先启动应用、再起代理、
    # 再设 http_proxy"，而应用启动那一秒就在发请求（实测 02-asmat-foggymaps：
    # 01:08:11 已经 GET /planet，代理 01:08:1x 才就绪）——首启流量整段落在覆盖外，
    # 报告里表现为"应用没有任何外发"，实际是采集窗口比应用晚开。
    emit("mitm", "running", "启动 mitmproxy 中间人代理（常规模式）")
    mitm = None
    mitm_error = None
    if args.reuse_mitm and env.tcp_open("127.0.0.1", env.MITM_PORT):
        emit("mitm", "running", "复用编排层预启动的 mitmproxy（端口已监听）")
    else:
        if args.reuse_mitm:
            emit("mitm", "running", "编排层预启动的代理不在（端口未监听），回退为自行启动")
        try:
            mitm = env.start_mitm(session, out / "mitm.log", args.package)
        except RuntimeError as exc:
            mitm_error = str(exc)
    check("mitm_ready", 0 if mitm_error is None else 1,
          note=mitm_error or f"port={env.MITM_PORT}（{'复用' if mitm is None else '本轮启动'}）")
    env.set_proxy(f"{env.GUEST_HOST}:{env.MITM_PORT}", out / "proxy-set.log")
    proxy_now = env.get_proxy()
    check("proxy_set_for_capture", 0 if str(env.MITM_PORT) in proxy_now else 1,
          note=f"http_proxy={proxy_now!r} (原值 {prev_proxy!r})；在 am start 之前设置")
    emit("mitm", "done", f"代理已就绪，设备 http_proxy={proxy_now!r}（早于启动应用）")

    # 冷启动竞争：attach 模式先 am start、等到 pid 再挂钩子；
    # spawn 模式反过来——钩子进程 spawn 应用（在第一条指令前挂上），应用由 resume 启动。
    # spawn 的根因（2026-10-19 实测定性）：attach 太晚，应用启动那一刻的联网/egress
    # 全落在钩子覆盖外，flows 归因恒 unresolved（24/24），egress 事件 0 条。
    if args.spawn_hook:
        pid = None  # spawn 模式下由 hook 进程启动，这里只做占位，不等 am start
        emit("launch", "running", f"spawn 模式：应用由 Frida spawn 启动（{main_activity}）")
    else:
        emit("launch", "running", f"启动应用 {main_activity}")
        env.adb("shell", "am", "start", "-W", "-n",
                f"{args.package}/{main_activity}", timeout=150)
        pid = env.wait_for_app(args.package)
        check("app_started", 0 if pid else 1,
              note=(f"pid={pid}" if pid else "应用未在超时内出现（冷启动竞争或启动崩溃）")
                   + f"；activity={main_activity}"
                   + ("" if resolved_activity else "（回退值：设备解析为空）"))
        emit("launch", "done" if pid else "failed", f"pid={pid}" if pid else "应用未启动")
        if not pid:
            env.kill_tree(collector, out / "kill-conn.log")   # 早退也不能留孤儿
            env.unblock_quic(out / "quic-unblock.log")        # 同理：不能把 DROP 规则留在设备上
            if pcap_rec is not None:                          # 抓包进程同样不能留在设备上
                pcap_rec.stop(out / "capture.pcap", out / "pcap-stop.log")
            (out / "verification.json").write_text(json.dumps(
                {"passed": False, "checks": checks, "failed": ["app_started"],
                 "package": args.package}, ensure_ascii=False, indent=2), encoding="utf-8")
            print(json.dumps({"status": "failed", "reason": "app_started"}, ensure_ascii=False))
            return 1

    # （代理已在 am start 之前就绪并设置，见上面 "启动 mitmproxy" 一段。）

    if args.no_hooks:
        # 对照实验：同一 App、同一流程，只少"挂钩子"这一项。用于判定应用死亡
        # （SIGABRT/SIGSEGV）是否由插桩引起——挂钩与不挂钩各跑一轮比对。
        hooks = []
        emit("hooks", "skipped", "对照实验：--no-hooks，本轮不挂任何钩子")
        check("hooks_armed", 0, optional=True,
              note="对照实验：--no-hooks，本轮不挂任何钩子（其余流程不变）")
    else:
        # **单 agent 合并 bundle**（2026-10-16 A1 修复）：privacy/consent/egress_tp/
        # ssl_pinning_tp 四模块在同一个 JS 上下文里装配。原"5 个脚本各起一个 run.py"
        # 的实现被 frida-java-bridge 的已知限制击穿——"多脚本各自替换方法"不受支持
        # （bridge 源码注释原文 "we don't support replacing methods from multiple
        # scripts"；实测双脚本 ~50% 触发 ART 的 GetOatQuickMethodHeader FATAL
        # 【主线程 abort】，单脚本 5/5 稳定）。vehicle 版 hook_egress/ssl_pinning_bypass
        # 一并退役：观测面被 tp 版覆盖（tp 是"同源加强版"，见各自文件头），且 vehicle
        # 版 TLS 含"已实证会炸 ART 的 HttpsURLConnection 主机名钩子"（tls_bypasses_tp.js
        # 头部有记录）。事件全落 reads.jsonl，收尾阶段由 split_events.py 按 src 分流回
        # consent/egress/tls 独立文件（下游 correlate/evidence_bundle 零改动）。
        emit("hooks", "running", "挂载 Frida 钩子（单 agent 合并 bundle：隐私/同意/出站/TLS）")
        hooks = [
            env.start_hook(MOBILE / "hooks" / "dist" / "hook_all.bundle.js", session,
                           "reads.jsonl", out / "hook-all.log", args.seconds, args.package,
                           spawn=args.spawn_hook),
        ]
        if args.spawn_hook:
            # spawn 模式下应用由 run.py 的 device.spawn + resume 启动。等待应用 pid
            # 出现（spawn 是异步的，run.py 里 spawn→attach→load→resume 需要几秒），
            # 并确认进程没在窗口内崩溃重启——否则 UI 驱动对着一个已死的进程空点。
            spawn_pid = env.wait_for_app(args.package, timeout_s=40)
            # spawn 注入对部分应用会导致 SIGSEGV（实测 openmensa：RenderThread
            # 在 spawn 后 3s 崩溃，frida 早期注入 + 部分 native 渲染线程初始化冲突）。
            # 检测到 spawn 的 pid 很快消失时，回退到 attach：停掉 spawn 钩子，用
            # am start 冷启动应用（此时应用已脱离 frida 早期注入，能正常跑），
            # 再 attach 重挂——牺牲启动瞬间的流量，换稳定性（2026-10-19）。
            spawn_died = False
            if spawn_pid:
                time.sleep(6)   # 给 spawn 的应用一个崩溃观察窗
                alive = env.adb("shell",
                                f"if test -d /proc/{spawn_pid}; then echo y; else echo n; fi",
                                timeout=30).stdout.strip() == "y"
                spawn_died = not alive
            if spawn_died:
                emit("launch", "running",
                     f"spawn pid={spawn_pid} 已消失（spawn 注入崩溃），回退 attach 重启")
                for h in hooks:
                    env.stop_hook(h, out / "hook-all.log")
                env.adb("shell", "am", "start", "-W", "-n",
                        f"{args.package}/{main_activity}", timeout=150)
                attach_pid = env.wait_for_app(args.package, timeout_s=40)
                check("app_started", 0 if attach_pid else 1,
                      note=(f"回退 attach pid={attach_pid}" if attach_pid else
                            "spawn 崩溃后回退 attach 也未能启动")
                           + f"；activity={main_activity}")
                if attach_pid:
                    hooks = [
                        env.start_hook(MOBILE / "hooks" / "dist" / "hook_all.bundle.js",
                                       session, "reads.jsonl", out / "hook-all.log",
                                       args.seconds, args.package, spawn=False),
                    ]
                    emit("launch", "done", f"回退 attach pid={attach_pid}")
                else:
                    emit("launch", "failed", "spawn 崩溃且回退 attach 失败")
            else:
                check("app_started", 0 if spawn_pid else 1,
                      note=(f"spawn pid={spawn_pid}" if spawn_pid else
                            "spawn 后应用未出现（可能被 Frida 挂起或启动崩溃）")
                           + f"；activity={main_activity}")
                emit("launch", "done" if spawn_pid else "failed",
                     f"spawn pid={spawn_pid}" if spawn_pid else "spawn 后应用未出现")
            if not spawn_pid and not spawn_died:
                for h in hooks:
                    env.stop_hook(h, out / "hook-all.log")
                env.kill_tree(collector, out / "kill-conn.log")
                env.unblock_quic(out / "quic-unblock.log")
                if pcap_rec is not None:
                    pcap_rec.stop(out / "capture.pcap", out / "pcap-stop.log")
                (out / "verification.json").write_text(json.dumps(
                    {"passed": False, "checks": checks, "failed": ["app_started"],
                     "package": args.package}, ensure_ascii=False, indent=2), encoding="utf-8")
                print(json.dumps({"status": "failed", "reason": "app_started"},
                                 ensure_ascii=False))
                return 1
        time.sleep(9)   # 等钩子挂上：钩子掉线与"应用没动作"长得一样（D309）
        emit("hooks", "done", "钩子已发起挂载（单 agent 合并 bundle）")

    emit("explore", "running", f"UI 交互驱动（最多 {args.max_rounds} 轮）")
    actions = flow.explore(out / "ui", args.seconds, args.max_rounds, args.package,
                           main_activity)
    (out / "ui-actions.json").write_text(json.dumps(
        {"actions": actions, "note": "每次点击的点击前/后 XML 见 ui/ 目录，可回溯"},
        ensure_ascii=False, indent=2), encoding="utf-8")
    taps = [a for a in actions if a["action"] == "tap"]
    check("ui_taps_made", 0 if taps else 1, note=f"完成 {len(taps)} 次点击")
    emit("explore", "done", f"完成 {len(taps)} 次点击")

    # 采集窗口结束就停抓包（放在改回代理之前：代理切换本身也会产生流量，
    # 混进来只会让"哪些是被测应用发的"更难判）。
    pcap_path = None
    if pcap_rec is not None:
        pcap_path = pcap_rec.stop(out / "capture.pcap", out / "pcap-stop.log")
        check("pcap_captured", 0 if pcap_path else 1, optional=True,
              note=(f"{pcap_path.name} ({pcap_path.stat().st_size} bytes)" if pcap_path
                    else f"未产出 pcap：{pcap_rec.error or '未知'}"))
        emit("pcap", "done" if pcap_path else "failed",
             "已产出 capture.pcap" if pcap_path else "未产出 pcap")

    env.set_proxy(prev_proxy if prev_proxy not in ("", "null") else ":0", out / "proxy-restore.log")
    # 采集窗口结束立刻撤规则：DROP 留在设备上会污染后续轮次（尤其 --reuse-mitm
    # 的编排层多轮跑同一台模拟器时），排查别的网络问题也会被它误导。
    env.unblock_quic(out / "quic-unblock.log")
    # 应用是否在窗口内死亡，以及死于什么。"窗口后半段没事件"有两种含义：应用没做，
    # 还是应用已经死了——只看事件文件分不出来，所以必须单独取证。
    # **必须在拆钩之前取证**（2026-10-16）：拆钩动作（无论优雅 detach 还是强杀）
    # 会让 frida agent 在应用里做一次未清理的 JNI 调用（Thread-N 的 DeleteGlobalRef
    # "without being attached"，CheckJNI 上必 abort）——那是**工具拆钩噪声**，
    # 不是应用在采集窗口内的行为；若在拆钩后取证，记录到的就是"我们拆钩的结果"。
    emit("death_probe", "running", "窗口结束，取证应用存活状态")
    death = env.app_death_reason(args.package)
    # **对齐"被挂钩的 pid"**（2026-10-16）：pidof 只查"包名有进程"——应用崩溃后
    # 自动重启的新进程（不同 pid）会把"死亡"伪装成"存活"（实测踩过：fix 轮
    # alive=True 实为"检查太早 + 新进程"的假象）。/proc/<挂钩 pid> 是"同一个
    # 进程还活着"的唯一可信判据；取不到时退化为包名判据（旧行为）。
    hooked_pid_alive = None
    if pid:
        probe = env.adb("shell", f"if test -d /proc/{pid}; then echo y; else echo n; fi",
                        timeout=30)
        hooked_pid_alive = (probe.stdout or "").strip() == "y"
    death["hooked_pid"] = pid
    death["hooked_pid_alive"] = hooked_pid_alive
    (out / "app-death.json").write_text(json.dumps(death, ensure_ascii=False, indent=2) + "\n",
                                        encoding="utf-8")
    # 死亡结论按优先级合成：被挂钩 pid > 包名 pidof；两者皆缺（None）不能写成
    # "窗口内死亡"——那是把"查不到"说成结论。
    if hooked_pid_alive is not None:
        window_alive = hooked_pid_alive
        if hooked_pid_alive:
            death_note = "应用（被挂钩进程）在窗口结束时仍存活"
        elif death["alive_at_end"]:
            death_note = (f"被挂钩进程 pid={pid} 在窗口内消失，包名另有新进程（崩溃后重启）；"
                          + str(death.get("cause") or (death["fatal_lines"] or ["原因未记录"])[0]))
        else:
            death_note = "被挂钩进程在窗口内死亡：" + str(
                death.get("cause") or (death["fatal_lines"] or ["原因未记录"])[0])
    else:
        window_alive = death["alive_at_end"]
        if window_alive is None:
            death_note = "无法判定：" + str(death.get("error") or "adb 报错")
        elif window_alive:
            death_note = "应用在窗口结束时仍存活"
        else:
            death_note = "应用在窗口内死亡：" + str(
                death.get("cause") or (death["fatal_lines"] or ["原因未记录"])[0])
    death["window_alive"] = window_alive
    check("app_alive_at_window_end", 0 if window_alive else 1, optional=True, note=death_note)
    emit("death_probe", "done", death_note)

    # 收尾：hooks 走**优雅停止**（哨兵 → run.py 正常 detach），替代强杀。
    # 注意：拆钩噪声（见上）本轮到这里才会发生——双脚本场景仍会触发一次拆钩 abort，
    # 但取证已在前、不受影响。见 thirdparty_env.stop_hook。
    for i, handle in enumerate(hooks):
        env.stop_hook(handle, out / f"hooks-stop-{i}.log")
    # mitm/collector 不是 hook 进程：维持**整棵进程树强杀**，不是只收直接子进程。
    # 孤儿会攥住句柄，让编排层之后每一次 subprocess.run 都阻塞（实测：policy_fetch
    # 卡满 300s 超时、correlate 不返回；杀掉孤儿后整条尾段立刻跑完）。
    # 详见 thirdparty_env.kill_tree 的注释。
    # mitm 为 None = 复用了编排层预启动的代理（生命周期归编排层，这里不动它）。
    for i, proc in enumerate(([mitm] if mitm is not None else [])
                             + ([collector] if collector else [])):
        env.kill_tree(proc, out / f"kill-{i}.log")
    time.sleep(3)   # 给 mitmproxy 的 done() 排空挂起队列

    # 合并产物分流（2026-10-16）：单 agent 合并 bundle 把所有事件落进 reads.jsonl，
    # 这里按 src 分流回 consent/egress/tls 独立文件——下游（correlate/evidence_bundle/
    # build_delivery）零改动。独立脚本模式下为 no-op（幂等）。见 mobile/tools/split_events.py。
    emit("split", "running", "事件分流（合并产物 → 独立文件）")
    check("split_events", env.run(
        [PY, str(MOBILE / "tools" / "split_events.py"), "--session", str(session)],
        out / "split.log"), optional=True,
        note="reads.jsonl 按 src 分流回 consent/egress/tls（合并模式分流；独立模式 no-op）")
    emit("split", "done", "分流完成")

    # ---- pcap → 完整 HTTP 报文（P0，2026-10-18）----
    # 这一步是"gzip body 读不到"那个缺口的正解：重组/解压/分帧全部交给 tshark，
    # 我们只负责把 keylog 从事件里抽出来喂给它（`hook_tls_meta.js` 已经在装回调）。
    # 必须在 split 之后跑：keylog 事件分流到 tls_meta.jsonl，这里两份都读。
    if pcap_path is not None:
        emit("http_msgs", "running", "pcap → 完整 HTTP 报文（tshark 解密 + 重组）")
        keys = out / "keys.log"
        nk, labels = pcap_http.keylog_from_events(session, keys)
        stats = pcap_http.decode(pcap_path, out / "http_messages.jsonl",
                                 out / "bodies", keys if nk else None)
        stats["keylog_labels"] = labels
        (out / "http-stats.json").write_text(
            json.dumps(stats, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        undecoded = stats.get("tls_undecrypted_app_data") or 0
        note = (f"{stats['messages']} 条报文（req={stats['requests']} resp={stats['responses']}）"
                f"，h1={stats.get('h1_messages', 0)} h2={stats.get('h2_messages', 0)}"
                f"，body={stats['bodies']}（截断 {stats.get('bodies_truncated', 0)}）"
                f"，keylog={nk} 行") if stats["ok"] else \
               f"0 条报文：{stats.get('error') or '未知'}"
        if nk == 0 and undecoded:
            # "只有明文那几条"和"没流量"在计数上长得一样。App 的 TLS 连接若在
            # tls_meta 装钩子之前就建好（实测整轮 HTTPS 全是这种），SSL_CTX_new /
            # SSL_new 都已经错过，keylog 一行也拿不到——此时 pcap 里的 TLS
            # 解不开，报文明细必然只剩零头。这种情况**不能判通过**。
            note += (f"；⚠ 有 {undecoded} 帧 TLS 应用数据未解密（keylog 未装上），"
                     f"上面这些不是全部外发内容")
            check("http_messages_extracted", 1, optional=True, note=note)
            emit("http_msgs", "partial", note)
        else:
            check("http_messages_extracted", 0 if stats["ok"] else 1, optional=True, note=note)
            emit("http_msgs", "done" if stats["ok"] else "failed", note)

    # 收尾：把样本强制停掉。**必须放在死亡取证之后**（在跑就杀会让 alive 永远为 false，
    # 那是自己制造假结论）；不停掉的话，样本会带着残留状态活到下一样本的窗口里——
    # 实测：一轮 camera 跑完后它的 MainActivity 一直留在前台，下一轮开跑时机器人
    # 先从别人家的界面上做 overlay 清理。停止样本只影响我们安装的测试副本。
    env.adb("shell", "am", "force-stop", args.package, timeout=60)

    # 钩子必须自证挂载（M016）：没有 ARMED 就是没挂上，不是"应用没动作"
    hook_events: dict[str, list[dict]] = {}
    for name, fname in (("privacy", "reads.jsonl"), ("consent", "consent.jsonl")):
        if args.no_hooks:
            # 对照实验：本来就没挂钩子，"没 ARMED"是设计使然，不是失败
            check(f"hook_{name}_armed", 0, optional=True,
                  note="对照实验：--no-hooks，本项按设计不适用")
            continue
        events = []
        p = session / fname
        if p.exists():
            for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
                if line.strip():
                    try:
                        events.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
        hook_events[fname] = events
        armed = any(e.get("ev") == "ARMED" for e in events)
        script_error = any(e.get("ev") in ("SCRIPT_ERROR", "ERROR") for e in events)
        check(f"hook_{name}_armed", 0 if armed else 1,
              note=None if armed else ("钩子脚本抛错，未挂载" if script_error
                                       else "没有 ARMED 事件：钩子没跑起来"))

    # ---- A2（§8.1）：`armed` 之外必须有**真实事件**，且这是**强制**判据 ----
    # `armed` 只证明钩子挂上了，不证明捕得到：夹具与 5 个第三方样本实测都是
    # "58/58 armed; failed=0" 而 reads.jsonl 只有 START/ARMED 两行。
    # 零事件时这里必须判失败并写进 gaps——不许为了让判据变绿而把它改回 optional（§8.6 第 1 条）。
    real_reads = []
    if args.no_hooks:
        check("runtime_events_captured", 0, optional=True,
              note="对照实验：--no-hooks，本项按设计不适用")
    else:
        real_reads = [e for e in hook_events.get("reads.jsonl", [])
                      if e.get("ev") not in ("START", "ARMED")]
        check("runtime_events_captured", 0 if real_reads else 1,
              note=(f"reads.jsonl 有 {len(real_reads)} 条 START/ARMED 之外的真实事件"
                    if real_reads else
                    "reads.jsonl 只有 START/ARMED：钩子挂上了，但一条运行时事件都没捕到。"
                    "armed ≠ 能捕到（§8.1 A2）——据此**不得**写「该应用未收集」；"
                    "先按 A1 排查插桩是否把应用打死，或本轮 UI 未触碰被监视 API"))

    # ---- 关联 / 证据包 / 报告 ----
    perms = apk_permissions(apk, args.build_tools)
    (o / "requested-permissions.txt").write_text("\n".join(perms) + "\n", encoding="utf-8")
    check("requested_permissions_nonempty", 0 if perms else 1, note=f"{len(perms)} 条")

    policy_store = o / "policy"
    check("policy_from_apk", env.run(
        [PY, str(MOBILE / "policy" / "policy_fetch.py"), "--from-apk", str(apk),
         "--store", str(policy_store), "--tag", "apk"], out / "policy.log", timeout=300),
        optional=True, note="APK 内可能不含隐私政策页；缺失会写进 summary.gaps")

    emit("correlate", "running", "关联引擎：运行时事件 × 权限 × 政策")
    check("correlate", env.run(
        [PY, str(MOBILE / "analyze" / "correlate_mobile.py"),
         "--session", str(session), "--package", args.package,
         "--permissions", str(o / "requested-permissions.txt"),
         "--app-category", args.app_category,
         "--policy-store", str(policy_store),
         "--out", str(o / "findings.jsonl"), "--summary", str(o / "summary.json")],
        out / "correlate.log"))
    emit("correlate", "done", "关联完成，结论写入 findings.jsonl")

    sha = hashlib.sha256(apk.read_bytes()).hexdigest()
    bundle_cmd = [PY, str(MOBILE / "ai" / "evidence_bundle.py"),
                  "--session", str(session), "--findings", str(o / "findings.jsonl"),
                  "--package", args.package, "--app-category", args.app_category,
                  "--policy-store", str(policy_store), "--apk-sha256", sha,
                  "--apk", str(apk),
                  "--device", env.adb("shell", "getprop", "ro.build.fingerprint",
                                      timeout=45).stdout.strip(),
                  "--out", str(o / "bundle.json")]
    # 编排层知道、而工具无法从数据里推出来的缺口，逐条写进 bundle.gaps（前缀 [orch]）。
    for note in env.orchestrator_notes(death):
        bundle_cmd += ["--note", note]
    if not args.no_hooks and not real_reads:
        # 零运行时事件是**采集链路的事实**，必须以 [orch] 缺口进证据包与报告，
        # 而不是让报告看起来"本轮没有发现"。
        bundle_cmd += ["--note", "本轮 reads.jsonl 只有 START/ARMED，零运行时事件："
                                 "钩子已挂载但不能据此判定「应用未收集」（§8.1 A1/A2）"]
    emit("bundle", "running", "证据封装（含加固探测与 [orch] 缺口）")
    check("bundle", env.run(bundle_cmd, out / "bundle.log"))
    emit("bundle", "done", "bundle.json 已生成")

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
            emit("ai_review", "running", "AI 研判（真实调用）")
            check("ai_review", env.run(ai_cmd, out / "ai.log", timeout=1800),
                  note="已配置 API key：真实调用")
            emit("ai_review", "done", "AI 三阶段研判完成")
        else:
            emit("ai_review", "running", "AI 研判（未配 key，dry-run 渲染提示词）")
            check("ai_review_dry_run",
                  env.run(ai_cmd + ["--dry-run"], out / "ai.log", timeout=600),
                  note="未配置 API key：仅渲染提示词、不联网")
            emit("ai_review", "done", "dry-run：仅渲染提示词，未联网")
    else:
        emit("ai_review", "skipped", "--skip-ai：本轮不跑 AI 研判")

    rep = [PY, str(MOBILE / "report" / "report_mobile.py"),
           "--bundle", str(o / "bundle.json"), "--session", session.name,
           "--out", str(o / "mobile-report.pdf")]
    # 只要 AI 目录存在就交给报告：dry-run（未配 key）也往 out/ai/prompts/ 写提示词，
    # 旧条件（要求 stage3.json）会让它们变孤儿文件、报告只能印硬编码的错误路径。
    if ai_dir.exists():
        rep += ["--ai-out-dir", str(ai_dir)]
    emit("report", "running", "生成 PDF 报告（工具结论 + AI 研判）")
    check("report", env.run(rep, out / "report.log"))
    emit("report", "done", "mobile-report.pdf 已生成")

    failed = [c["name"] for c in checks if c.get("exit_code") and not c.get("optional")]
    optional_failed = [c["name"] for c in checks if c.get("exit_code") and c.get("optional")]
    (out / "verification.json").write_text(json.dumps(
        {"passed": not failed, "checks": checks, "failed": failed,
         "optional_failed": optional_failed, "session": session.name,
         "package": args.package, "apk_sha256": sha,
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
                      "optional_failed": optional_failed}, ensure_ascii=False, indent=2))
    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
