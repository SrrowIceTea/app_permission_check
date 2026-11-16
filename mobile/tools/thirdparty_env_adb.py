#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""thirdparty_env 的 adb 基础层（常量 / adb 封装 / wifi / 代理 / QUIC 压制）。

从 thirdparty_env.py 拆出，保持零行为改动。仅用于授权测试。
"""
from __future__ import annotations

import os
import re
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


def current_user_id() -> int | None:
    try:
        result = adb("shell", "am", "get-current-user", timeout=30)
        value = result.stdout.strip()
        return int(value) if result.returncode == 0 and value.isascii() and value.isdigit() else None
    except (OSError, subprocess.TimeoutExpired):
        print("[adb] 无法查询当前 Android 用户，跳过按包 UID 的采集。", file=sys.stderr)
        return None


def app_uid(package: str) -> int | None:
    """Resolve an exact package and foreground-user kernel UID."""
    user = current_user_id()
    if user is None:
        return None
    try:
        result = adb("shell", "pm", "list", "packages", "--user", str(user), "-U", timeout=45)
    except (OSError, subprocess.TimeoutExpired) as exc:
        print(f"[adb] 无法查询 {package} 的 UID：{exc}", file=sys.stderr)
        return None
    if result.returncode:
        return None
    packages_by_uid: dict[int, set[str]] = {}
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) != 2 or not fields[0].startswith("package:") or not fields[1].startswith("uid:"):
            continue
        raw = fields[1][4:]
        if raw.isascii() and raw.isdigit() and int(raw) > 0:
            uid = int(raw)
            if uid < 100000:
                uid += user * 100000
            if uid // 100000 == user:
                packages_by_uid.setdefault(uid, set()).add(fields[0][8:])
    for uid, names in packages_by_uid.items():
        if names == {package}:
            return uid
    return None


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
