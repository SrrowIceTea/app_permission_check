#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""device_run_thirdparty 阶段①：prepare→mitm 头段（从 device_run_thirdparty.py 拆出，
零行为改动）。装样本 / frida-server / wifi / QUIC 压制 / 代理 / CA / conn_probe / pcap。
"""
from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(HERE))
import thirdparty_env as env      # noqa: E402
import pcap_capture               # noqa: E402
sys.path.insert(0, str(ROOT))


def _stage_head(ctx) -> None:
    """prepare→mitm 头段：多设备守卫 / 溯源与静态拷贝 / boot / frida / wifi / QUIC /
    代理 / 干净安装 / 坐标注入 / 主 Activity 解析 / conn_probe / pcap / 系统 CA / mitm。
    """
    args = ctx.args
    apk = ctx.apk
    out = ctx.out
    session = ctx.session
    o = ctx.o
    checks = ctx.checks
    emit = ctx.emit
    check = ctx.check

    # 多设备且未指定 ANDROID_SERIAL → 启动前就停。理由见 thirdparty_env.device_guard：
    # 裸 adb 命令在多设备下全部报错，且失败形态是静默空结果（假"已恢复"、假"原因未记录"）。
    guard = env.device_guard()
    if guard:
        sys.exit("[fatal] " + guard)

    events_path = ctx.events_path

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
    setattr(sys.modules["device_run_thirdparty"].main, "_prev_proxy", prev_proxy)
    ctx.prev_proxy = prev_proxy

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
    # 跨包 Activity 留证（2026-10-20）：解析出来的绝对类名可能不属于被测包 ——
    # 实测 04-zachy-pulse 与 15-gadgetbridge-bangl 都解析到
    # nodomain.freeyourgadget.gadgetbridge.activities.ControlCenterv2。
    # 派生应用共用上游代码库时这**是合法的**（Pulse 基于 Gadgetbridge），所以
    # 不判失败、也不擅自换启动方式（当前行为实测能起来且产生了业务流）；
    # 但必须写清楚，否则审计者看到"使用了别的包的 Activity"只能靠猜。
    cross_pkg = bool(main_activity and not main_activity.startswith(".")
                     and not main_activity.startswith(args.package))
    if cross_pkg:
        print(f"[main-activity] 注意：解析到的 Activity 不属于被测包 "
              f"{args.package}（{main_activity}）。若被测应用并非派生自该代码库，"
              f"这里就是起错组件，需人工确认。", flush=True)
    (out / "main-activity.log").write_text(json.dumps(
        {"from_batch": args.main_activity, "from_device": resolved_activity,
         "used": main_activity, "cross_package": cross_pkg,
         "note": ("Activity 包名前缀与被测包不一致；派生应用共用上游代码库时属预期，"
                  "否则意味着起错组件" if cross_pkg else None)},
        ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    ctx.main_activity = main_activity
    ctx.resolved_activity = resolved_activity  # launch 段的 app_started note 要据此判断"设备解析是否为空"

    env.adb("shell", "logcat", "-c", timeout=30)

    # 设备侧连接采样：不经过任何被挂钩的 Java 层，直接看内核有没有外发。
    # 它回答的是钩子回答不了的问题——"零事件"到底是没外发，还是外层栈没被覆盖。
    # **必须在 `am start` 之前就开**：应用的外发就发生在启动那一刻（实测 logcat 里
    # 启动当秒就有 uid=10236 的 NetworkRequest，而晚 8s 才起的采样一条都没采到）。
    # 按**包名**采（不是按 uid 读 /proc/net/tcp）：Android 隔离了应用网络命名空间；
    # 且应用会在窗口内崩溃重启（实测 pid 10658→14037），只有让设备端每轮重解 pid，
    # 才不会在那之后整段失明。也不过滤 uid——过滤等于静默丢数据，丢了补不回来。
    uid = env.app_uid(args.package)
    ctx.uid = uid
    emit("conn_probe", "running", f"开启设备侧连接采样（package={args.package}）")
    collector = env.start_conn_probe(session, out / "conn-probe.log",
                                     args.package, args.seconds, uid=uid)
    ctx.collector = collector
    check("conn_probe_started", 0, optional=True,
          note=f"package={args.package} app_uid={uid}（设备端每轮重解 pid，不过滤 uid）")
    emit("conn_probe", "done", f"app_uid={uid}")

    # 设备端 pcap（P0，2026-10-18）：**必须在 am start 之前**起，和 conn_probe 同一个
    # 理由——外发就在启动那一刻。它解决的是 hook 结构性给不出的东西：hook 拿到的是
    # SSL_read/write 的分片（无连接标识、无边界），而 pcap 里 TCP 流 + TLS 记录层 +
    # HTTP 分帧齐全，交给 tshark 一条命令就能解出**完整报文并自动解 gzip/chunked**。
    # 失败不阻断采集：只记缺口——"没抓到"和"没有流量"必须能区分。
    pcap_rec = None
    ctx.pcap_rec = None
    if args.no_pcap:
        check("pcap_captured", 0, optional=True, note="--no-pcap：本轮不做 pcap 采集")
        emit("pcap", "skipped", "--no-pcap：不抓包，完整报文不可得")
    else:
        emit("pcap", "running", "设备端 pcap 采集（tcpdump）")
        pcap_rec = pcap_capture.PcapRecorder()
        ctx.pcap_rec = pcap_rec
        pcap_ok, pcap_note = pcap_rec.start(out / "pcap-start.log", args.seconds + 120)
        check("pcap_started", 0 if pcap_ok else 1, optional=True, note=pcap_note)
        emit("pcap", "done" if pcap_ok else "failed", pcap_note)

    # 系统 CA（2026-10-19）：**不装就等于只采到 URL**。未受信时 HTTPS 在客户端
    # 证书校验处断开，mitmproxy 只留下 "client does not trust the proxy's
    # certificate"，addon 拿不到完整 flow → flows.jsonl 为空；pcap 里也只有
    # 未解密的 TLS 应用数据（本次 3 样本实测：6~9 帧 undecrypted，keylog 0 行）。
    # 仓库早有 mobile/traffic/transparent.py 做这件事（含 Android 14+ 的 conscrypt
    # APEX + zygote namespace），但第三方批处理从没调用过它——这就是"流量只到
    # URL 层"的直接原因。装失败不阻断采集，但必须留痕，不许让报告看起来"没有外发"。
    ca_rec: dict = {"installed": False, "skipped": True}
    ctx.ca_rec = ca_rec
    if args.no_system_ca:
        # 用非 0 退出码：只写 note 时 exit_code=0 在汇总里看起来是"通过"，
        # 而这一项其实代表"本轮 HTTPS 没解开"，必须出现在 optional_failed 里。
        check("system_ca", 1, optional=True,
              note="--no-system-ca：显式跳过；HTTPS 无法解密，flows.jsonl 预期为空")
        emit("system_ca", "skipped", "显式跳过系统 CA 安装")
    elif args.reuse_mitm and not Path.home().joinpath(".mitmproxy", "mitmproxy-ca-cert.pem").exists():
        check("system_ca", 1, optional=True, note="找不到 ~/.mitmproxy/mitmproxy-ca-cert.pem")
    else:
        emit("system_ca", "running", "安装 mitmproxy 系统 CA（/system + conscrypt APEX）")
        try:
            sys.path.insert(0, str(ctx.out.parent.parent / "traffic"))
            import transparent  # noqa: E402  仅用于授权测试设备
            ca_rec = transparent.install_system_ca(log=out / "ca-install.json")
        except Exception as exc:  # noqa: BLE001  CA 失败不阻断本轮采集
            ca_rec = {"installed": False, "error": f"{type(exc).__name__}: {exc}"}
        ctx.ca_rec = ca_rec
        check("system_ca", 0 if ca_rec.get("installed") else 1, optional=True,
              note=(f"CA={ca_rec.get('ca_name')}" if ca_rec.get("installed")
                    else (ca_rec.get("error") or "安装失败")))
        emit("system_ca", "done" if ca_rec.get("installed") else "failed",
             ca_rec.get("error") or "CA 已进入系统库与 APEX 的 zygote 命名空间")

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
    ctx.mitm = mitm
    ctx.mitm_error = mitm_error
    check("mitm_ready", 0 if mitm_error is None else 1,
          note=mitm_error or f"port={env.MITM_PORT}（{'复用' if mitm is None else '本轮启动'}）")
    env.set_proxy(f"{env.GUEST_HOST}:{env.MITM_PORT}", out / "proxy-set.log")

    proxy_now = env.get_proxy()
    check("proxy_set_for_capture", 0 if str(env.MITM_PORT) in proxy_now else 1,
          note=f"http_proxy={proxy_now!r} (原值 {prev_proxy!r})；在 am start 之前设置")
    emit("mitm", "done", f"代理已就绪，设备 http_proxy={proxy_now!r}（早于启动应用）")
