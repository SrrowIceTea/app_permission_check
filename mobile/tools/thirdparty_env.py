#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""第三方 APK 设备端链路的环境层：adb / frida-server / wifi / 代理 / mitm / 钩子进程。
仅用于授权测试（自有设备 / 已授权的公开第三方样本）。

这里是 `device_run_thirdparty.py` 的下半身；与夹具版 `mobile/tools/device_run.py`
的差异：包名 / APK / 入口 Activity 参数化、frida-server 自动推送、mitmproxy 走常规
代理模式（夹具版走 reverse）。其余已验证的坑位处理（root、端口 27043、wifi/路由、
代理残留、冷启动竞争）**照搬**。`device_run.py` 一行不改。
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
MOBILE = ROOT / "mobile"
PY = sys.executable
# SDK 路径解析统一走 core/sdk_paths（§8.2 B-4）：不再写死本机绝对路径。
sys.path.insert(0, str(ROOT))
from core import sdk_paths  # noqa: E402

ADB = sdk_paths.sdk_tool("platform-tools", "adb.exe")
FRIDA_PORT = 27043
MITM_PORT = 8888
GUEST_HOST = "10.0.2.2"          # 模拟器里指向宿主机

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ui_trigger as ui  # noqa: E402


def adb(*args: str, timeout: int = 60) -> subprocess.CompletedProcess:
    # 显式 utf-8 + errors="replace"：本机 PYTHONUTF8=1 时子进程管道默认 UTF-8 解码，
    # 而 adb.exe 可能混入 GBK 字节（中文系统）——缺 errors 会让 Reader 线程崩、
    # .stdout 变 None。同一约束见 mobile/tools/batch_thirdparty.py 的 mklink 注释。
    return subprocess.run([ADB, *args], capture_output=True, text=True,
                          encoding="utf-8", errors="replace", timeout=timeout)


def device_guard() -> str | None:
    """多设备且未指定 ANDROID_SERIAL 时，**在启动前明确失败**。

    为什么必须挡：本工具链所有 adb 调用都是裸命令（不带 -s）。挂上第二台设备后，
    它们一律报 `error: more than one device/emulator`——而失败形态是**静默空结果**：
    pidof 空 → app-death.json 写成"原因未记录"（真身可能是 crash 缓冲里一条
    SIGABRT）；proxy 恢复读回空串 → 看起来"已恢复"。实测 2026-10-13 跑 Fossify
    Camera 时宿主机上多出一台模拟器（Android Studio 启动的 Medium_Phone），
    收尾分钟内的取证就全部失真。宁可响亮失败，不要安静地写错。
    返回错误文案；环境正常（单设备，或已显式指定 ANDROID_SERIAL）返回 None。
    """
    if (os.environ.get("ANDROID_SERIAL") or "").strip():
        return None
    out = adb("devices").stdout or ""
    serials = [ln.split("\t", 1)[0].strip() for ln in out.splitlines()[1:]
               if "\tdevice" in ln]
    if len(serials) > 1:
        return (f"检测到多台设备 {serials} 且未设置 ANDROID_SERIAL；"
                "裸 adb 命令会全部报错，收尾取证会静默写空结果。"
                f"请显式指定目标设备后重跑，例如：ANDROID_SERIAL={serials[0]}")
    return None


def run(cmd: list[str], log: Path, timeout: int = 900, env: dict | None = None) -> int:
    e = dict(os.environ)
    if env:
        e.update(env)
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8",
                              errors="replace", timeout=timeout, env=e)
        rc, out, err = proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired as exc:
        rc, out, err = 124, (exc.stdout or ""), f"TIMEOUT after {timeout}s"
    log.write_text(f"$ {' '.join(cmd)}\n\n{out}\n--- stderr ---\n{err}", encoding="utf-8")
    return rc


def wait_boot(timeout_s: int = 300) -> bool:
    end = time.time() + timeout_s
    while time.time() < end:
        if adb("shell", "getprop", "sys.boot_completed", timeout=25).stdout.strip() == "1":
            return True
        time.sleep(5)
    return False


def wait_for_app(package: str, timeout_s: int = 60) -> str | None:
    """冷启动竞争：am start 投出 intent 就返回，进程几秒后才出现；
    立刻 pidof 的退出码 1 与"应用起不来"无法区分。钩子是 attach 模式，必须先等到 pid。"""
    end = time.time() + timeout_s
    while time.time() < end:
        pid = adb("shell", "pidof", package, timeout=25).stdout.strip()
        if pid:
            return pid.split()[0]
        time.sleep(1.5)
    return None


def ensure_frida_server(log: Path, local_binary: Path | None) -> tuple[bool, str]:
    """frida-server 必须以 root 跑（Android 10+ 禁止跨 uid 访问应用进程）。
    设备上没有就推一个（版本需与宿主 frida 一致）。"""
    adb("root", timeout=90)
    time.sleep(3)
    adb("wait-for-device", timeout=90)
    ps = adb("shell", "ps -A -o USER,NAME | grep frida-server", timeout=45).stdout
    pushed = "not_needed"
    if "frida-server" not in ps:
        have = adb("shell", "ls -l /data/local/tmp/frida-server", timeout=45).stdout
        if "No such file" in have or "not found" in have.lower():
            if local_binary is None or not Path(local_binary).exists():
                log.write_text(f"ps:\n{ps}\n{have}\n无本地 frida-server 可推送\n", encoding="utf-8")
                return False, "missing_local_binary"
            adb("push", str(local_binary), "/data/local/tmp/frida-server", timeout=600)
            adb("shell", "chmod", "755", "/data/local/tmp/frida-server", timeout=45)
            pushed = "pushed"
        else:
            pushed = "already_present"
        adb("shell", "killall frida-server", timeout=45)
        time.sleep(1)
        adb("shell", "nohup /data/local/tmp/frida-server -l 127.0.0.1:27043 "
                     ">/dev/null 2>&1 &", timeout=90)
        time.sleep(6)
        ps = adb("shell", "ps -A -o USER,NAME | grep frida-server", timeout=45).stdout
    adb("forward", f"tcp:{FRIDA_PORT}", f"tcp:{FRIDA_PORT}", timeout=45)
    log.write_text(f"ps:\n{ps}\npush_state: {pushed}\n", encoding="utf-8")
    ok = ("root" in ps) and ("frida-server" in ps)
    return ok, pushed if ok else "not_root"


PROBE_TARGETS = ("api.open-meteo.com:443", "www.baidu.com:443", "114.114.114.114:53")


def ensure_wifi(log: Path) -> bool:
    """确认设备**真的能建立外网 TCP 连接**——出口只认实测。

    别用 `"default" in ip route`（我加过，实测是错的）：Android 走**策略路由**，
    default 在 per-network 表里（`... dev eth0 table eth0`），`ip route` 只显示 main
    表，那里正常联网时就**没有** default → 网络完好却误判断网。也别写死 `wlan0`：
    本机走 `eth0`（10.0.2.15），wlan0 是 DOWN。多目标防单点被挡（8.8.8.8:53 不通）。"""
    def probe() -> dict:
        out = {}
        for tgt in PROBE_TARGETS:
            host, _, port = tgt.partition(":")
            r = adb("shell", f"toybox nc -z -w 5 {host} {port} >/dev/null 2>&1; echo $?",
                    timeout=45).stdout.strip().splitlines()
            out[tgt] = r[-1].strip() if r else "?"
        return out

    status = adb("shell", "cmd", "wifi", "status", timeout=45).stdout
    probes = probe()
    if not any(v == "0" for v in probes.values()):
        adb("shell", "cmd", "wifi", "connect-network", "AndroidWifi", "open", timeout=90)
        time.sleep(10)
        status = adb("shell", "cmd", "wifi", "status", timeout=45).stdout
        probes = probe()
    addr = adb("shell", "ip", "-brief", "addr", timeout=45).stdout
    route = adb("shell", "ip", "route", "show", "table", "all", timeout=45).stdout
    log.write_text(
        "wifi:\n" + status + "\naddr:\n" + addr + "\nroute(all tables):\n" + route
        + "\ntcp probes (0=可连):\n"
        + "\n".join(f"  {k} -> {v}" for k, v in probes.items()), encoding="utf-8")
    return any(v == "0" for v in probes.values())


def get_proxy() -> str:
    return adb("shell", "settings", "get", "global", "http_proxy", timeout=30).stdout.strip()


def set_proxy(value: str, log: Path) -> None:
    adb("shell", "settings", "put", "global", "http_proxy", value, timeout=45)
    time.sleep(2)
    log.write_text(f"http_proxy set -> {value!r}; now={get_proxy()!r}\n", encoding="utf-8")


# --- QUIC（HTTP/3，走 UDP/443）压制 ------------------------------------------
# 代理只接管 TCP：一旦客户端协商到 HTTP/3，整条业务就绕开 mitmproxy，flows 里
# 什么也看不到——这是「QUIC 不在覆盖内」的由来。但「覆盖外」不是物理限制：
# 设备的 netfilter **在模拟器上可用**（2026-10-18 实测：插入
# `-p udp --dport 443 -j DROP` 后，OUTPUT 链首条规则的 pkts 随发包增长）。
# 早先 verify_force_proxy 的"UDP 直出"只证明 `-http-proxy` 这个参数不管 UDP，
# **不等于**内核层丢不掉。丢掉 UDP/443 后客户端按 QUIC 规范回退 TCP/443
# （Alt-Svc 失效，Happy Eyeballs 走 TCP），流量就重新落回代理。
QUIC_RULE = ("-p", "udp", "--dport", "443", "-j", "DROP")


def block_quic(log: Path) -> bool:
    """丢弃设备发出的 UDP/443，逼 HTTP/3 回退到 TCP。返回**是否真的生效**。

    失败不抛：没有 root、内核缺 netfilter、ROM 禁用 iptables 都可能失败。
    这时采集照常跑，只是回到"QUIC 盲区"——由调用方记成能力缺口。
    **绝不能静默当成功**：报告里"没拦到"和"没流量"长得一模一样。
    """
    # 先去重：上一轮异常退出可能留下同名规则，重复插入会让 -D 只删掉一条。
    for _ in range(3):
        r = adb("shell", "iptables", "-D", "OUTPUT", *QUIC_RULE, timeout=30)
        if (r.stderr or "").strip() and "does a matching rule exist" not in (r.stderr or ""):
            break
    ins = adb("shell", "iptables", "-I", "OUTPUT", "1", *QUIC_RULE, timeout=30)
    listed = (adb("shell", "iptables", "-L", "OUTPUT", "1", "-n", timeout=30).stdout or "")
    # 三个词都要有：只判 "443" 会把已有的 tcp/443 规则当成我们这条（假阳性）。
    ok = all(tok in listed for tok in ("DROP", "udp", "443"))
    log.write_text(
        f"block_quic: insert rc={ins.returncode} out={(ins.stdout or '').strip()!r} "
        f"err={(ins.stderr or '').strip()!r}\n"
        f"rule#1: {listed.strip().splitlines()[-1] if listed.strip() else '(empty)'}\n"
        f"effective={ok}\n", encoding="utf-8")
    return ok


def unblock_quic(log: Path) -> None:
    """撤掉 block_quic 插的规则。多删几次以清理历史遗留的重复项。"""
    lines = []
    for _ in range(4):
        r = adb("shell", "iptables", "-D", "OUTPUT", *QUIC_RULE, timeout=30)
        lines.append(f"-D rc={r.returncode} err={(r.stderr or '').strip()!r}")
        if r.returncode != 0:
            break
    left = (adb("shell", "iptables", "-L", "OUTPUT", "-n", timeout=30).stdout or "")
    still = any("443" in ln and "DROP" in ln for ln in left.splitlines())
    log.write_text("\n".join(lines) + f"\nstill_present={still}\n", encoding="utf-8")


def kill_tree(proc: subprocess.Popen | None, log: Path | None = None) -> None:
    """终止**整棵进程树**，不是只杀直接子进程。

    Windows 上 `terminate()` 只结束直接子进程，它的子进程会**变成孤儿**。这里踩到的是
    conn_probe 起的 `adb shell`：conn_probe 被 terminate 后那个 adb 成了孤儿，而孤儿的
    句柄会让编排进程之后**每一次** `subprocess.run` 都阻塞（policy_fetch 卡满 300s、
    correlate 不返回；杀掉孤儿后整条尾段立刻跑完）。故用 `taskkill /T /F` 连树一起收。
    """
    if proc is None or proc.poll() is not None:
        return
    lines = []
    try:
        r = subprocess.run(["taskkill", "/PID", str(proc.pid), "/T", "/F"],
                           capture_output=True, text=True, encoding="utf-8",
                           errors="replace", timeout=30)
        lines.append(f"taskkill /T /F {proc.pid}: rc={r.returncode} "
                     f"{(r.stdout or '').strip()} {(r.stderr or '').strip()}")
    except Exception as exc:  # noqa: BLE001
        lines.append(f"taskkill failed: {exc!r}")
        try:
            proc.kill()
        except Exception as exc2:  # noqa: BLE001
            lines.append(f"kill failed: {exc2!r}")
    try:
        proc.wait(timeout=15)
        lines.append("reaped")
    except Exception:  # noqa: BLE001
        lines.append("wait timed out")
    if log:
        log.write_text("\n".join(lines) + "\n", encoding="utf-8")


def kill_pid_tree(pid: int) -> None:
    """按 PID 收整棵进程树——手里只有 pid、没有 Popen 句柄时用（回收残留代理）。

    与 `kill_tree` 同样必须 `/T`：mitmdump 的 launcher 会再起一个 python 子进程，
    只杀 launcher 的话端口照样被占着，等于没回收。
    """
    if not pid:
        return
    try:
        if sys.platform == "win32":
            subprocess.run(["taskkill", "/PID", str(pid), "/T", "/F"],
                           capture_output=True, text=True, errors="replace", timeout=30)
        else:
            subprocess.run(["kill", "-TERM", str(pid)], capture_output=True, timeout=30)
    except Exception:  # noqa: BLE001 —— 收不掉就让后面的端口探测去报错，不在这里炸
        pass


def orchestrator_notes(death: dict) -> list[str]:
    """编排层写给报告的缺口说明（会带 [orch] 前缀进 bundle.gaps）。

    这些限制**工具无法从数据里推出来**；不写就等于让读者把「没采集到」读成「没发生」。
    """
    notes = [
        "本样本的**天气客户端**是 loopj/AsyncHttpClient（重打包 Apache HttpClient），不读系统代理，"
        "天气 API 流量 mitmproxy 结构性抓不到；地图瓦片走 WebView、确实走代理，代理收到了 "
        "CONNECT tile.openstreetmap.org:443 但被网络阻断（502），故 flows.jsonl 为空——"
        "这是**覆盖缺口**不是「没有外发」；旁路证据见 out/supplementary-evidence.json。",
        "TLS 绕过用的是第三方裁剪版（ssl_pinning_tp）：裁掉了会触发 ART abort 的 "
        "HttpsURLConnection 主机名校验钩子；且因关键流量不走代理，本轮没有可读的 MITM 流量，"
        "放宽 TLS 校验对本样本不产生任何证据。",
        "静态侧证据全部封顶 candidate：规则库 dangerous_apis 只有 33 个 API，"
        "android_id/定位/通讯录/短信/相册/日历 等数据类别 lib=0，静态扫描看不到这些。",
        "APK 内未含隐私政策页（只有 OSS 许可文件），policy_from_apk 判 not_found。",
    ]
    if not death.get("alive_at_end"):
        notes.append(
            "应用在检测窗口内死亡：StartAutoLocationJob 启动 LocationUpdateService 后未在系统时限内调用 "
            "startForeground()，抛 ForegroundServiceDidNotStartInTimeException。"
            "这是样本自身在 Android 12+ 上的行为，与检测工具无关（只挂出站钩子、不挂 TLS 钩子时同样复现，"
            "见 output/_smoke/ab_tls_tp.log）；它导致窗口后半段没有任何事件。")
    return notes


def tcp_open(host: str, port: int, timeout: float = 1.5) -> bool:
    """宿主端口上是否有进程在听。用于代理前置/复用判定（2026-10-16）。

    为什么要有它：模拟器 37.x 启动时探测代理可达性，失败会把 SLIRP 强制代理
    整条关掉；编排层需在冷启动前确认"端口已有人在听"，device_run 也用它决定
    「复用编排层预启动的代理」还是「回退自行启动」。
    """
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def port_owner(port: int) -> tuple[int | None, str]:
    """谁在 LISTEN 这个端口 → (pid, 进程名)。取不到就给 (None, "")，不猜。"""
    try:
        if sys.platform == "win32":
            out = subprocess.run(["netstat", "-ano", "-p", "TCP"],
                                 capture_output=True, text=True, errors="replace",
                                 timeout=20).stdout
            pid = None
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 5 and parts[0] == "TCP" \
                        and parts[1].endswith(f":{port}") and parts[3] == "LISTENING":
                    pid = int(parts[4])
                    break
            if pid is None:
                return None, ""
            tl = subprocess.run(["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"],
                                capture_output=True, text=True, errors="replace",
                                timeout=20).stdout.strip()
            name = tl.split('","')[0].strip('"') if tl else ""
            return pid, name
        out = subprocess.run(["lsof", "-nP", f"-iTCP:{port}", "-sTCP:LISTEN", "-t"],
                             capture_output=True, text=True, errors="replace",
                             timeout=20).stdout.strip()
        if out.isdigit():
            return int(out), ""
    except Exception:  # noqa: BLE001 —— 探测失败不影响主流程，按"未知占用"处理
        pass
    return None, ""


STALE_MITM_NAMES = ("mitmdump", "mitmproxy")
# 真正 LISTEN 的往往不是 mitmdump.exe 本身，而是它拉起的 python.exe 子进程
# （实测：owner 报 python.exe，按进程名判断会把自家残留当成"别人的进程"而拒收）。
# 所以还要看命令行里有没有这些特征。
STALE_MITM_CMDLINE = ("mitmdump", "mitmproxy", "addon_mobile", "collector\\addon", "collector/addon")


def proc_cmdline(pid: int) -> str:
    """取进程命令行。取不到返回 ""，调用方据此保持"不动它"。

    **不能只靠 wmic**：Windows 11 起 wmic 默认已移除（本机实测 `wmic: command not found`），
    而且它的 FileNotFoundError 会直接把整个取值流程打断——所以两条路各自 try，
    前一条失败要继续走后面那条，不能让异常短路。
    """
    if sys.platform != "win32":
        try:
            raw = Path(f"/proc/{pid}/cmdline").read_bytes()
            return raw.replace(b"\x00", b" ").decode("utf-8", "replace").strip()
        except Exception:  # noqa: BLE001
            return ""
    try:
        r = subprocess.run(["wmic", "process", "where", f"processid={pid}",
                            "get", "commandline", "/format:list"],
                           capture_output=True, text=True, errors="replace", timeout=25)
        for line in (r.stdout or "").splitlines():
            if line.strip().startswith("CommandLine="):
                val = line.split("=", 1)[1].strip()
                if val:
                    return val
    except Exception:  # noqa: BLE001 —— 没有 wmic 是常态，继续走 PowerShell
        pass
    try:
        ps = f'(Get-CimInstance Win32_Process -Filter "ProcessId={pid}").CommandLine'
        r = subprocess.run(["powershell", "-NoProfile", "-Command", ps],
                           capture_output=True, text=True, errors="replace", timeout=30)
        return (r.stdout or "").strip()
    except Exception:  # noqa: BLE001
        return ""


def reclaim_port(port: int) -> tuple[bool, str]:
    """端口被占时，**只回收自己的残留 mitmproxy**，别人的进程一律不动。

    为什么需要（2026-10-19 实测）：长批次跑到中途，某一轮的 mitmdump 会变成孤儿
    （样本超时被杀、编排进程被回收都会留下）。此后**每一个**样本都在 `mitm_ready`
    上判红——批次看着还在跑，其实整段没有代理，样本全是零流量。
    实测已经发生过一次（批次第 1 个样本因端口占用判红）。
    原来只提示"先排查 netstat 再重跑"，那是把自动化的事推给人；几小时的批次里没人盯。

    判定"是不是自己的"必须看**命令行**：mitmdump.exe 是个 launcher，真正监听的是它
    拉起的 python.exe（实测 owner=python.exe）。只看进程名会把自家残留当外人。
    """
    if not tcp_open("127.0.0.1", port):
        return True, "free"
    pid, name = port_owner(port)
    if not pid:
        return False, "端口被占用，但取不到占用进程（权限不足？）——不动它"
    cmd = proc_cmdline(pid)
    ours = (name or "").lower().startswith(STALE_MITM_NAMES) or \
           any(tok in cmd.lower() for tok in STALE_MITM_CMDLINE)
    if not ours:
        return False, f"被其它进程占用（pid={pid} name={name or '未知'}）——不动它"
    kill_pid_tree(pid)
    for _ in range(20):
        if not tcp_open("127.0.0.1", port):
            return True, f"已回收残留 mitmproxy（pid={pid} {name}）"
        time.sleep(0.25)
    return False, f"残留 mitmproxy（pid={pid} {name}）回收后端口仍被占用"


def start_mitm(session: Path, log: Path, package: str) -> subprocess.Popen:
    """**常规代理模式**（不是 reverse）——第三方样本要访问它自己的服务端。

    启动前后各加一道校验（2026-10-16）：
      ① 端口被占 → 直接报错。原先 mitmdump 抢不到端口会**立刻退出**，而调用方
         睡 7 秒后照常返回——采集带着"没有代理"静默跑完，报告漏掉全部网络证据，
         事后完全看不出来。
      ② 启动后确认真的在监听；没监听就把死进程收了再报错（同上，防静默）。
    2026-10-19：① 之前先尝试回收**自己的**残留 mitmproxy（见 reclaim_port），
    别人的进程仍然拒绝启动，不误杀。
    """
    if tcp_open("127.0.0.1", MITM_PORT):
        ok, why = reclaim_port(MITM_PORT)
        if not ok:
            raise RuntimeError(
                f"端口 {MITM_PORT} {why}。先排查：netstat -ano | findstr :{MITM_PORT}，再重跑。")
        log.write_text(f"[start_mitm] 端口 {MITM_PORT}：{why}\n", encoding="utf-8")
    env = dict(os.environ)
    env.update({
        "VSCAN_FLOW_LOG": str(session / "flows.jsonl"),
        "VSCAN_UNANSWERED_LOG": str(session / "flows-unanswered.jsonl"),
        "VSCAN_UNATTRIBUTED_LOG": str(session / "flows-unattributed.jsonl"),
        "VSCAN_ATTRIB_SOURCES": os.pathsep.join([
            # **必须把 reads.jsonl 放第一位**（2026-10-19）：钩子边跑边写的就是它，
            # 而 egress.jsonl / egress_tp.jsonl 要到 split_events 收尾才存在。
            # 只读后两者 → 整场归因 unresolved → 代理流被当成"归因不到"丢弃，
            # 表现就是"代理明明拿到了 200，flows.jsonl 却是空的"。
            str(session / "reads.jsonl"),
            str(session / "egress.jsonl"), str(session / "egress_tp.jsonl")]),
        "VSCAN_PACKAGES": package,
        "VSCAN_SESSION": session.name,
        # 常规代理模式看得见真实目标 host:port，开目标校验把"别的 App 的流误认领给
        # 被审计包"这条静默错误路径关掉（见 core/collector/DECISIONS D413）。
        # **只在常规代理模式开**：reverse 模式所有 App 寻址同一代理端口，开了会把
        # 整场归因静默变 unresolved——reverse 路径（device_run.py）不设此变量。
        "VSCAN_ATTRIB_TARGET_CHECK": "1",
    })
    # 上游可达性（2026-10-19）：本机到 Google 系域名不通（IPv6 与直连都超时），
    # mitmproxy 会对每条 CONNECT 干等 ~20s 再回 502（`WinError 121 信号灯超时`），
    # 把采集窗口和 CPU 全耗在系统自检流量上。这些 host 不可能承载被测应用证据，
    # 直接按"不拦截、原样转发"处理；其余 host 照常解密。
    # 忽略表只放"与本应用数据外发无关的系统噪声"，**不要**往里塞业务域名：
    # 被忽略的主机不做中间人，报告里也就看不见它。2026-10-19 实机补了
    # `android.googleapis.com`——GMS 用它做检查，客户端不信任我们的 CA，
    # 每次都在日志里打一条 "client does not trust the proxy's certificate"，
    # 淹掉真正的失败信息；它对隐私结论没有价值。
    # 注意：ignore_hosts **不省掉上游连接**，只是不拦截。目标本身不可达时照样会失败，
    # 别指望它解决超时——超时的归类见 core/collector/addon.classify_upstream_failure。
    ignore = os.environ.get("VSCAN_MITM_IGNORE_HOSTS") or (
        r"connectivitycheck\.gstatic\.com|clients3\.google\.com|mtalk\.google\.com|"
        r"android\.clients\.google\.com|android\.googleapis\.com|play\.googleapis\.com|"
        r"firebaseinstallations\.googleapis\.com|www\.gstatic\.com|www\.google\.com")
    mitm_args = ["mitmdump", "-s", str(MOBILE / "traffic" / "addon_mobile.py"),
                 "--listen-host", "0.0.0.0", "--listen-port", str(MITM_PORT),
                 # lazy：先建客户端连接、真收到请求字节再连上游。eager 会在
                 # CONNECT 一到达就连上游，对不可达 host 白白阻塞。
                 "--set", "connection_strategy=lazy",
                 "--set", f"ignore_hosts={ignore}"]
    # **必须关掉子进程的 stdout 块缓冲**：管道/文件重定向下 Python 默认 8KB 块缓冲，
    # 而收尾一律 `taskkill /T /F`（见 kill_tree）——缓冲里没落盘的内容直接蒸发。
    # 实测：breezy 那一轮的 mitm.log 最终 0 字节（连启动横幅都没有），事后无法诊断
    # "代理到底起没起、见到了什么连接"。数据本身在 sqlite 里没丢，但人读的日志没了，
    # 违反"失败可诊断"。PYTHONUNBUFFERED 会被 mitmdump 的 console launcher 透传给
    # 真正干活的 python 子进程。
    env["PYTHONUNBUFFERED"] = "1"
    # stdin=DEVNULL：不让子进程继承标准句柄，否则下游攥住句柄会让编排层 subprocess.run 阻塞。
    proc = subprocess.Popen(
        mitm_args,
        stdin=subprocess.DEVNULL, stdout=open(log, "w", encoding="utf-8"),
        stderr=subprocess.STDOUT, env=env)
    # mitmproxy 启动要几秒；等不够会"应用连不上代理"而非"代理没起来"。
    # 轮询而不是死睡：就绪即返回；20s 内没监听 → 收掉死进程并报错（防静默）。
    for _ in range(40):
        if proc.poll() is not None:
            break
        if tcp_open("127.0.0.1", MITM_PORT):
            return proc
        time.sleep(0.5)
    try:
        if proc.poll() is None:
            proc.kill()
    except Exception:  # noqa: BLE001
        pass
    raise RuntimeError(f"mitmproxy 未能在 {MITM_PORT} 上监听（20s 超时）；"
                       f"启动日志见 {log}")


_FRIDA_PY_CACHE: str | None = None


def frida_python() -> str:
    """挑一个**确实装了 frida** 的解释器来跑 `core/frida_host/run.py`。

    为什么需要：`start_hook` 原先直接用 `sys.executable`。当前解释器若没装 frida，
    run.py 只在 hook 日志里印一行 `frida module missing` 就退出，**主流程照常往下跑**，
    最终表现是"整轮零事件"——和"应用什么都没做"完全一样，是最坏的一种静默失败。
    实测踩过：managed 3.13.12 没装 frida，而系统 Python313 装了（还带 reportlab）。

    探测顺序：当前解释器 → 环境变量 VSCAN_PY → 常见安装位置 → PATH 上的 python。
    都探不到就返回当前解释器（保持原行为，由下游的 `hook_*_armed` 判据把它判红）。
    """
    global _FRIDA_PY_CACHE
    if _FRIDA_PY_CACHE:
        return _FRIDA_PY_CACHE
    cands = [sys.executable]
    if os.environ.get("VSCAN_PY"):
        cands.append(os.environ["VSCAN_PY"])
    import glob
    local = os.environ.get("LOCALAPPDATA") or ""
    if local:
        cands += sorted(glob.glob(os.path.join(local, "Programs", "Python", "Python3*",
                                               "python.exe")), reverse=True)
    for c in (shutil.which("python"), shutil.which("python3")):
        if c:
            cands.append(c)
    seen = set()
    for c in cands:
        if not c or c in seen:
            continue
        seen.add(c)
        try:
            r = subprocess.run([c, "-c", "import frida"], capture_output=True, timeout=60)
        except (OSError, subprocess.SubprocessError):
            continue
        if r.returncode == 0:
            _FRIDA_PY_CACHE = c
            return c
    return sys.executable


def start_hook(script: Path, session: Path, out_name: str, log: Path,
               seconds: int, package: str, spawn: bool = False) -> subprocess.Popen:
    env = dict(os.environ)
    env["VSCAN_SESSION"] = session.name
    env["PYTHONUNBUFFERED"] = "1"   # 见 start_mitm 的注释：杀掉子进程时缓冲内容会丢
    # 优雅停止哨兵（2026-10-16）：run.py 每 tick 检查该文件，出现即正常 detach 退出。
    # 收尾必须走 stop_hook() 而不是 kill_tree——强杀会让 agent 在未清理状态下
    # 做 JNI 调用（DeleteGlobalRef），CheckJNI 的 userdebug 上必 aborts 被测应用，
    # 实测每轮一次、污染 app-death 取证。路径挂在返回的 Popen 上供 stop_hook 取用；
    # 启动前先删残留（否则上一轮的 .stop 会让新会话秒退）。
    stop_file = session / (out_name + ".stop")
    try:
        stop_file.unlink()
    except OSError:
        pass
    proc = subprocess.Popen(
        [frida_python(), str(ROOT / "core" / "frida_host" / "run.py"),
         "--package", package,
         "--script", str(script), "--seconds", str(seconds),
         "--allow-package", package, "--session", session.name,
         "--out", str(session / out_name), "--stop-file", str(stop_file)]
        + (["--spawn"] if spawn else []),
        stdin=subprocess.DEVNULL, stdout=open(log, "w", encoding="utf-8"),
        stderr=subprocess.STDOUT, env=env)
    proc.stop_file = stop_file  # type: ignore[attr-defined]
    return proc


def stop_hook(proc: subprocess.Popen | None, log: Path | None = None,
              timeout_s: float = 12.0) -> str:
    """优雅停止 hook 进程：写哨兵 → 等 run.py 正常 detach → 超时才强杀兜底。

    为什么不能一步 taskkill /F（2026-10-16 实测）：强杀让 frida agent 在未清理
    状态下收尾——userdebug（CheckJNI 强制开启）上必发
    "a thread is making JNI calls without being attached / in call to DeleteGlobalRef"
    abort，**每轮一次**，且把"工具收尾噪声"写进 app-death 取证（会污染
    「应用在窗口结束时仍存活」的判定）。对照实验：同一流程自然 detach 时
    crash buffer 零 abort。

    返回值："exited"（自然退出，期望路径）/ "killed"（超时或哨兵不可写，兜底强杀）/
    "none"（进程已不在或没有进程）。
    """
    if proc is None or proc.poll() is not None:
        return "none"
    stop_file = getattr(proc, "stop_file", None)
    if stop_file is None:
        # 不是 start_hook 起的进程（或不认识哨兵协议）：维持旧行为。
        kill_tree(proc, log)
        return "killed"
    try:
        stop_file.write_text("stop", encoding="utf-8")
    except OSError:
        kill_tree(proc, log)
        return "killed"
    try:
        proc.wait(timeout=timeout_s)
        return "exited"
    except subprocess.TimeoutExpired:
        kill_tree(proc, log)
        return "killed"


def app_uid(package: str) -> int | None:
    """应用 uid（不是 pid）。取不到返回 None——调用方据此跳过采样，
    绝不用一个猜的 uid 去采样然后报"零外发"。

    顺序（2026-10-19 调整）：`pm list packages -U` 是 PackageManager 的权威回答，
    带 user 维度（本机应用装在 user 10，`dumpsys package` 的 userId 曾与运行期
    socket 的 uid 对不上，导致"应用有外发"被判成"没采到"）。
    `stat /data/data/<pkg>` 只能兜底：Android 15 上它是符号链接，且卸载重装后会变。
    """
    probes = (
        ("shell", "pm", "list", "packages", "--user", "0", "-U"),
        ("shell", "stat", "-L", "-c", "%u", f"/data/user/0/{package}"),
        ("shell", "dumpsys", "package", package),
    )
    for args in probes:
        out = adb(*args, timeout=45).stdout
        if not out.strip():
            continue
        if args[1] == "pm":
            # 形如 "package:com.foo uid:10237"（-U 选项）；只认本包的 uid
            for line in out.splitlines():
                if f"package:{package}" in line:
                    m = re.search(r"uid:(\d+)", line)
                    if m:
                        return int(m.group(1))
            continue
        m = re.search(r"userId=(\d+)", out)
        if m:
            return int(m.group(1))
        if out.strip().isdigit():
            return int(out.strip())
    return None


def start_conn_probe(session: Path, log: Path, package: str,
                     seconds: int, uid: int | None = None) -> subprocess.Popen:
    """设备侧连接采样。

    这是**与客户端库无关**的外发地面真相：钩子只能证明"被挂钩的那层被走到了"，
    遇到非常规栈（重打包 Apache HttpClient / NDK / 绑定到 Network 的 socket）会给出
    "零外发"，和"应用真的没外发"长得一模一样。见 conn_probe.py 头部说明。

    传**包名**而不是 pid：Android 隔离了应用的网络命名空间，读 `/proc/net/tcp`（adb
    shell 自己的命名空间）看不到它；而本样本 pid 在窗口内会变（10658→14037），绑死
    初始 pid 的采样在应用重启后整段失明，故让**设备端每轮重解 pid**。这里不传 `--uid`：
    目标命名空间里的 socket 全部落盘、逐行带 uid，"哪些是应用自己的"留到事后判读。
    """
    cmd = [PY, str(Path(__file__).resolve().parent / "conn_probe.py"),
           "--package", package, "--seconds", str(seconds),
           "--out", str(session / "conns.jsonl")]
    # uid 给了就在解析阶段过滤（2026-10-19）：应用共享同一个网络命名空间，
    # `/proc/<app pid>/net/tcp` 里混着 system(0)/network_stack(1073)/历史 uid 的
    # socket，不过滤会把"别的进程在联网"读成"应用在联网"。
    if uid is not None:
        cmd += ["--uid", str(uid)]
    child_env = dict(os.environ)
    child_env["PYTHONUNBUFFERED"] = "1"   # 见 start_mitm 的注释：杀掉子进程时缓冲内容会丢
    proc = subprocess.Popen(cmd, stdin=subprocess.DEVNULL,
                            stdout=open(log, "w", encoding="utf-8"),
                            stderr=subprocess.STDOUT, env=child_env)
    return proc


def _process_name_variants(package: str) -> set[str]:
    """日志里进程名的可能写法。

    实测 bionic 的 comm 只保留 15 字符且**保留尾部**：
      org.breezyweather → g.breezyweather；com.kunzisoft.keepass.libre → t.keepass.libre；
      org.fossify.camera → .fossify.camera。
    首 15 字符变体也一并算上（native 守护进程用的是头截断：android.hardware.uwb-service
    → android.hardwar），免得日志形态随实现变化时认不出自己。
    """
    names = {package}
    if len(package) > 15:
        names.add(package[:15])
        names.add(package[-15:])
    return names


def parse_app_death(raw: str, package: str) -> dict:
    """从 logcat 原文里抽「死于什么」。纯函数，便于用**真实崩溃原文**做单测。

    归属两条准则（都是实测教训，不要放松）：

    ① **崩溃标记行必须自己点名我们**——`Fatal signal` 行里的 `(进程名)`、
       `FATAL EXCEPTION` 场景的 `Process: <包名>`、tombstone 的 `Cmdline: <包名>`。
       不能"先按时间前缀/包名圈块、再看块里有什么"（曾这么写，被真实数据打脸）：
       合并日志里**同一毫秒会缝进别的进程的行**——模拟器的 UWB HAL 每 5~10 秒崩一次，
       `15:10:52.349` 这一毫秒里同时有 breezy 的 PackageConfigPersister 和 UWB 的
       panic+abort 四行，按块归属会把 UWB 的 abort message（"failed to open the
       serial device"）写成 org.breezyweather 的死因。

    ② **Abort message 只从点名我们的 tombstone 里取**：以 `Cmdline: <包名>` 为锚点，
       向前找 `*** *** ***` 头；找不到头（缓冲被截断）就从锚点本身起、**只向后**扫——
       向前扩窗会把紧邻的别人的记录吃进来。
    """
    lines = raw.splitlines()
    names = _process_name_variants(package)

    fatal: list[str] = []
    cause: str | None = None

    # ① native 崩溃：Fatal signal 行点名我们
    for ln in lines:
        if "Fatal signal" in ln and any(f"({n}" in ln for n in names):
            s = ln.strip()
            if s not in fatal:
                fatal.append(s)

    # ② tombstone：Cmdline 锚定，Abort message 取自该墓碑
    for i, ln in enumerate(lines):
        if f"Cmdline: {package}" not in ln:
            continue
        start = i
        for j in range(i, max(-1, i - 400), -1):
            if "*** *** ***" in lines[j]:
                start = j
                break
        # 只向后扫：tombstone 里 Abort message 在 Cmdline 之后；若向前扩窗会把
        # 紧邻的**别人的**记录吃进来（无头可锚时尤为危险）。
        for l in lines[start:i + 300]:
            if "Abort message:" in l:
                cause = cause or l.split("Abort message:", 1)[1].strip().strip("'")
                break

    # ③ Java 崩溃：FATAL EXCEPTION 块（其下方数行内带 Process: <包名>）
    for i, ln in enumerate(lines):
        if "FATAL EXCEPTION" not in ln:
            continue
        ctx = lines[i:i + 6]
        if not any(package in c for c in ctx):
            continue
        s = ln.strip()
        if s not in fatal:
            fatal.append(s)
        if cause is None:
            for c in ctx[1:]:
                if "Exception" in c or "Error" in c:
                    cause = c.strip()
                    break

    return {"fatal_lines": fatal[:3], "cause": cause}


def app_death_reason(package: str) -> dict:
    """应用在窗口内是否死亡、死于什么。

    必须留下："窗口后半段没有事件"既可能是应用没做该动作，也可能是应用已经死了，
    只看事件文件分不出来。只读 logcat，不改任何东西。

    三个取证要点（都是实测教训）：
      ① `-b crash` 必须显式带上：native 崩溃（SIGABRT 等）的 tombstone 只在
         crash 缓冲里，而 crash 缓冲会被**其它进程的崩溃**（模拟器的 UWB HAL
         崩溃循环）快速挤占——所以要在窗口一结束就取证，晚了就真没了。
      ② 解析走 parse_app_death（见其注释）。
      ③ adb 报错 ≠ 应用死亡：多设备未指定 ANDROID_SERIAL 时 pidof 会报错，
         旧实现把它当 alive=False，会把"查不到"写成"死了"。
    """
    try:
        pid_res = adb("shell", "pidof", package, timeout=30)
    except subprocess.TimeoutExpired:
        # adb 抖动（服务重启窗口）时 pidof 会挂满超时——**不能让它把整轮采集炸掉**
        # （2026-10-16 实测：一次 adb 抖动把夹具自检整个掀翻在死亡取证这一步）。
        # 语义上与"adb 报错"一致：无法判定 → alive_at_end=None，由调用方如实降级。
        return {"alive_at_end": None, "pid": None, "fatal_lines": [], "cause": None,
                "error": "adb pidof 超时（30s）——无法判定存活", "package": package}
    err = (pid_res.stderr or "").strip()
    if "error:" in err:
        return {"alive_at_end": None, "pid": None, "fatal_lines": [], "cause": None,
                "error": err.splitlines()[0], "package": package}
    pid = (pid_res.stdout or "").strip()
    try:
        log = adb("logcat", "-d", "-b", "main", "-b", "system", "-b", "crash",
                  "-v", "time", timeout=120).stdout or ""
    except subprocess.TimeoutExpired:
        log = ""   # 同上：拿不到崩溃缓冲就如实为空，不让它掀翻整轮
    return {"alive_at_end": bool(pid), "pid": pid or None,
            **parse_app_death(log, package)}


def parse_resolved_activity(stdout: str, package: str) -> str | None:
    """从 `cmd package resolve-activity --brief` 的输出里抽 activity 部分。纯函数。

    输出形如：
        priority=0 preferredOrder=0 match=0x108000 specificIndex=-1 isDefault=false
        org.fdroid.fdroid/.views.main.MainActivity
    取组件行里 `/` 之后的部分（保守起见只认 package 段完全匹配的行）。
    """
    for ln in reversed((stdout or "").splitlines()):
        ln = ln.strip()
        if "/" in ln and ln.split("/", 1)[0] == package:
            return ln.split("/", 1)[1]
    return None


def device_main_activity(package: str) -> str | None:
    """设备侧解析默认 LAUNCHER Activity（可直接拼 `pkg/act` 交给 am start）。

    为什么以设备为准：aapt2 badging 的 `launchable-activity` 只给**第一个** LAUNCHER，
    而第一个不一定是能启动的那个——实测 F-Droid 的 `panic.CalculatorActivity` 挂在
    manifest 的 LAUNCHER 里，但类的 dex 已被 R8 裁掉，`am start` 直接报
    "Activity class does not exist"（Error type 3），整段设备检测死在 app_started。
    设备解析是系统对"点桌面图标"的权威回答（activity-alias 也解析到位，实测
    Fossify 系列会给出 .SplashActivity.Green 这种别名形态）。
    """
    r = adb("shell", "cmd", "package", "resolve-activity", "--brief",
            "-c", "android.intent.category.LAUNCHER", package, timeout=60)
    return parse_resolved_activity(r.stdout or "", package)
