#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""现场复验：不走系统代理的 TCP 是否也被强制劫持进 mitmproxy（SLIRP 强制代理的回归工具）。

仅用于授权测试（自有设备 / 已授权的公开第三方样本）。

背景（2026-10-16，见 DECISIONS M032/M033）：SLIRP `-http-proxy` 曾因地址传 guest 侧
别名 10.0.2.2（宿主不可路由）导致**整条强制重定向静默失效**——"不读系统代理的直连流量
全部漏掉"，且启动日志里只有一行 "Proxy will be ignored" 很难发现。修复 = 宿主侧地址
127.0.0.1 + 冷启动前置 mitmproxy（缺一不可）。本工具复验该承诺：

  测试 A：guest raw socket 直连域名（系统代理已彻底禁用）→ 应被劫持进代理
  测试 B：guest raw socket 直连不可达 IP（203.0.113.7，TEST-NET-3，不带 Host）
          → 若收到 mitmproxy 自己的 400 报错页 = 铁证（该地址不可能有真实服务响应）
  测试 C：guest UDP 到宿主 listener → 预期直出（不经代理）——QUIC 盲区的边界确认，
          与 CLAUDE.md"能力边界：QUIC 不在覆盖内"一致。

**v1 的教训（已固化）**：boot 完成 ≠ 网络就绪。模拟器冷启动后 eth0 的 DHCP 还要
等几十秒（2026-10-16 实测 36s），过早测试一律 "Network is unreachable"（假阴性）。
本工具内置与 `thirdparty_env.ensure_wifi` 对齐的多目标 TCP 探测等待，就绪才开测。

判定读法（同时写进 <out>/verdict.json）：
  - A/B 看"代理侧 client connect 增量"（<out>/mitm.log）；B 的响应体必须含 mitmproxy 字样；
  - C 看宿主 UDP listener 是否收到（收到 = UDP 直出 = QUIC 类流量不经此代理，属已知边界）。

用法：
    python verify_force_proxy.py                      # 证据 → D:/vscanner-tp/verify-force-proxy/<时间戳>
    python verify_force_proxy.py --out D:/tmp/vfp     # 指定证据目录
    python verify_force_proxy.py --avd My_AVD --port 8888
"""
from __future__ import annotations

import argparse
import json
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(ROOT))
from core import sdk_paths  # noqa: E402

sys.path.insert(0, str(ROOT / "mobile" / "traffic"))
import transparent as tp  # noqa: E402

sys.path.insert(0, str(HERE))
import thirdparty_env as env  # noqa: E402  （start_mitm 含端口预检+监听校验）

EMULATOR = sdk_paths.sdk_tool("emulator", "emulator.exe")
BASE_ARGS = ["-no-boot-anim", "-gpu", "auto"]
UDP_PORT = 9999


def log(msg: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


def connect_count(mitm_log: Path) -> int:
    try:
        return mitm_log.read_text(encoding="utf-8", errors="replace").count("client connect")
    except OSError:
        return -1


def run_guest(cmd: str, timeout: int = 45) -> tuple[str, str]:
    r = env.adb("shell", cmd, timeout=timeout)
    return (r.stdout or ""), (r.stderr or "")


def wait_network(max_wait: float = 180) -> bool:
    """对齐 ensure_wifi：多目标 TCP 探测任一通过即可连（0=可连）。

    为什么不能跳过（v1 假阴性根因）：boot_completed=1 时 eth0 可能还没拿到 DHCP
    租约，TCP 层直接 "Network is unreachable"——测出来的是"网络没醒"，不是"代理没抓"。
    """
    t0 = time.time()
    attempt = 0
    while time.time() - t0 < max_wait:
        attempt += 1
        results: dict[str, str] = {}
        for tgt in env.PROBE_TARGETS:
            host, _, port = tgt.partition(":")
            r = env.adb("shell",
                        f"toybox nc -z -w 5 {host} {port} >/dev/null 2>&1; echo $?",
                        timeout=45)
            lines = (r.stdout or "").strip().splitlines()
            results[tgt] = lines[-1].strip() if lines else "?"
        ok = any(v == "0" for v in results.values())
        log(f"  网络探测 #{attempt}: " + ", ".join(f"{k}={v}" for k, v in results.items())
            + (f"  → 就绪（{time.time()-t0:.0f}s）" if ok else "  → 未就绪，10s 后重试"))
        if ok:
            return True
        if attempt == 2:   # 照流水线：探测连败时尝试拉起模拟器 WiFi
            log("  触发救援：cmd wifi connect-network AndroidWifi open")
            env.adb("shell", "cmd wifi connect-network AndroidWifi open", timeout=90)
        time.sleep(10)
    return False


def udp_listener(got: list, seconds: float = 70) -> None:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.bind(("0.0.0.0", UDP_PORT))
    except OSError as exc:
        log(f"UDP listener 绑定失败: {exc}")
        return
    s.settimeout(seconds)
    t0 = time.time()
    while time.time() - t0 < seconds:
        try:
            data, addr = s.recvfrom(4096)
            got.append((data, addr))
            log(f"  >> UDP listener 收到 {data!r} 来自 {addr}")
        except socket.timeout:
            break
    s.close()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--avd", default="VScan_Phone")
    ap.add_argument("--port", type=int, default=tp.MITM_PORT)
    ap.add_argument("--out", default=None,
                    help="证据目录（默认 D:/vscanner-tp/verify-force-proxy/<时间戳>）")
    ap.add_argument("--boot-timeout", type=int, default=300)
    args = ap.parse_args()

    out = Path(args.out) if args.out else \
        Path("D:/vscanner-tp/verify-force-proxy") / time.strftime("%Y%m%d-%H%M%S")
    out.mkdir(parents=True, exist_ok=True)
    mitm_log = out / "mitm.log"
    emu_log = out / "emulator.log"
    log(f"证据目录: {out}")

    mitm = emu = None
    verdict: dict[str, str] = {}
    try:
        # --- 0. 前置 mitmdump（必须先于模拟器：启动探测只做一次、失败不重试） ---
        if env.tcp_open("127.0.0.1", args.port):
            log(f"致命：端口 {args.port} 已被占用，先清理再重跑")
            return 2
        mitm = env.start_mitm(out / "session", mitm_log, "org.fossify.voicerecorder")
        log(f"mitmdump 已监听 {args.port}（前置就位）")

        # --- 1. 冷启动模拟器（启动参数与流水线同源：tp.emulator_capture_args） ---
        cmd = [EMULATOR, "-avd", args.avd, *BASE_ARGS,
               *tp.emulator_capture_args(port=args.port)]
        (out / "emulator-start.log").write_text(" ".join(cmd) + "\n", encoding="utf-8")
        log("启动模拟器: " + " ".join(cmd))
        emu_log_f = open(emu_log, "w", encoding="utf-8")
        emu = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=emu_log_f,
                               stderr=subprocess.STDOUT)
        time.sleep(6)
        if emu.poll() is not None:
            log(f"致命：模拟器进程立即退出 rc={emu.returncode}")
            return 2

        log("等待系统 boot 完成…")
        t0 = time.time()
        booted = False
        while time.time() - t0 < args.boot_timeout:
            r = env.adb("shell", "getprop sys.boot_completed", timeout=15)
            if (r.stdout or "").strip() == "1":
                booted = True
                break
            time.sleep(4)
        if not booted:
            log(f"致命：{args.boot_timeout}s 内未 boot 完成")
            return 2
        log(f"boot 完成（耗时 {time.time()-t0:.0f}s）")

        # --- 2. 等网络就绪（v1 教训：boot ≠ 网络可用） ---
        log("等待设备网络就绪…")
        net_ok = wait_network(max_wait=180)
        verdict["network_ready"] = "OK" if net_ok else "BAD(180s 未就绪)"
        if not net_ok:
            log("致命：网络未就绪，测试无意义，中止")
            return 3
        time.sleep(3)

        # --- 3. 模拟器启动时的代理探测结果（SLIRP 是否接受 -http-proxy） ---
        emu_txt = emu_log.read_text(encoding="utf-8", errors="replace")
        ignored = "Proxy will be ignored" in emu_txt
        log(f"模拟器日志 'Proxy will be ignored' : {'出现（坏！）' if ignored else '未出现（好）'}")
        verdict["emu_proxy_accepted"] = "BAD" if ignored else "OK"

        # --- 4. 彻底禁用系统代理（测"连系统代理都没有"的极端情况） ---
        env.adb("shell", "settings put global http_proxy :0", timeout=30)
        cur = env.adb("shell", "settings get global http_proxy", timeout=30).stdout.strip()
        log(f"系统代理已禁用？ settings get → {cur!r}（期望 ':0'）")
        verdict["sys_proxy_disabled"] = "OK" if cur == ":0" else f"BAD({cur!r})"
        time.sleep(1)

        got: list = []
        threading.Thread(target=udp_listener, args=(got,), daemon=True).start()
        time.sleep(0.5)

        # --- 测试 A：TCP raw socket 直连域名（强制 IPv4：模拟器 IPv6 不可靠） ---
        time.sleep(2)   # 网络探测自身的连接先落盘
        base = connect_count(mitm_log)
        log(f"== 测试 A：nc -4 直连 example.com:80（raw socket，系统代理已禁用）| 代理基线={base} ==")
        so, se = run_guest(
            "printf 'GET / HTTP/1.0\\r\\nHost: example.com\\r\\n\\r\\n' | "
            "timeout 12 nc -4 -w 8 example.com 80")
        log(f"  stdout:\n{so[:500]}")
        log(f"  stderr: {se[:300]!r}")
        time.sleep(3)
        cnt_a = connect_count(mitm_log)
        log(f"  代理侧 client connect: {base} → {cnt_a}（delta={cnt_a-base}）")
        if cnt_a > base:
            verdict["A_tcp_domain"] = ("captured(+%d)" % (cnt_a - base)) + \
                ("；拿到 HTTP 响应" if "HTTP/" in so else "；无 HTTP 响应")
        else:
            verdict["A_tcp_domain"] = "NOT-captured"

        # --- 测试 B：TCP raw socket 直连不可达 IP（TEST-NET-3） ---
        base_b = connect_count(mitm_log)
        log("== 测试 B：nc -4 直连 203.0.113.7:80（不可达 IP，不带 Host）==")
        so, se = run_guest(
            "printf 'GET / HTTP/1.0\\r\\n\\r\\n' | timeout 12 nc -4 -w 8 203.0.113.7 80")
        log(f"  stdout:\n{so[:500]}")
        log(f"  stderr: {se[:300]!r}")
        time.sleep(3)
        cnt_b = connect_count(mitm_log)
        log(f"  代理侧 client connect: {base_b} → {cnt_b}（delta={cnt_b-base_b}）")
        if cnt_b > base_b:
            verdict["B_tcp_dummy_ip"] = ("captured(+%d)" % (cnt_b - base_b)) + \
                ("；响应来自 mitmproxy" if "mitmproxy" in so.lower()
                 else "；响应不含 mitmproxy 字样")
        else:
            verdict["B_tcp_dummy_ip"] = "NOT-captured"

        # --- 测试 C：UDP 直出（QUIC 底层；-http-proxy 只管 TCP 的边界确认） ---
        log(f"== 测试 C：nc -4 -u 到宿主 UDP listener（10.0.2.2:{UDP_PORT}）==")
        so, se = run_guest(
            f"echo -n VSCAN_UDP_PROBE | timeout 8 nc -4 -u -w 4 10.0.2.2 {UDP_PORT}",
            timeout=30)
        log(f"  stdout: {so[:200]!r}  stderr: {se[:200]!r}")
        time.sleep(5)
        if got:
            verdict["C_udp_direct"] = f"宿主收到 {got[0][0]!r} —— UDP 直出（不经代理）"
        else:
            verdict["C_udp_direct"] = "宿主未收到"

        # --- 汇总 ---
        txt = mitm_log.read_text(encoding="utf-8", errors="replace")
        conns = [l for l in txt.splitlines() if "client connect" in l]
        verdict["proxy_client_connect_total"] = str(len(conns))
        log("========== 判定汇总 ==========")
        for k, v in verdict.items():
            log(f"  {k}: {v}")
        log(f"---- mitm.log 最后 12 条 client connect：")
        for l in conns[-12:]:
            log(f"  {l}")
        (out / "verdict.json").write_text(
            json.dumps(verdict, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        log(f"verdict 已写入 {out / 'verdict.json'}")
        return 0
    finally:
        log("收尾：杀模拟器…")
        try:
            if emu is not None:
                env.adb("emu", "kill", timeout=20)
                time.sleep(4)
                if emu.poll() is None:
                    emu.terminate()
                    try:
                        emu.wait(timeout=15)
                    except subprocess.TimeoutExpired:
                        emu.kill()
        except Exception as exc:  # noqa: BLE001
            log(f"  杀模拟器异常（忽略）: {exc}")
        log("收尾：停 mitmdump…")
        try:
            if mitm is not None:
                env.kill_tree(mitm, out / "kill-mitm.log")
        except Exception as exc:  # noqa: BLE001
            log(f"  停 mitmdump 异常（忽略）: {exc}")
        try:
            live = env.adb("devices", timeout=15).stdout
            log("收尾后 adb devices: " + live.replace("\n", " | "))
        except Exception:  # noqa: BLE001
            pass
        log("完成。")


if __name__ == "__main__":
    raise SystemExit(main())
