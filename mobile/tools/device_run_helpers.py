#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""device_run 的设备操作层（从 device_run.py 拆出，保持零行为改动）。

仅用于授权测试（已获授权的样本与设备）。

只放**与设备交互的独立函数**（adb 封装 / 启动检查 / 子进程启动 / UI 操作），
编排与判据留在 device_run.py 的 main()。
"""
from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
MOBILE = ROOT / "mobile"
PY = sys.executable
# SDK 路径解析统一走 core/sdk_paths（§8.2 B-4）：不再写死本机绝对路径。
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))   # 同目录的 thirdparty_env
from core import sdk_paths  # noqa: E402
import thirdparty_env as tp_env  # noqa: E402

ADB = sdk_paths.sdk_tool("platform-tools", "adb.exe")
PKG = "com.vscanner.privacydemo"
APK = MOBILE / "fixture-app" / "app" / "build" / "outputs" / "apk" / "debug" / "app-debug.apk"
MITM_PORT = 8888
UPSTREAM_PORT = 8080


def adb(*args: str, timeout: int = 60) -> subprocess.CompletedProcess:
    return subprocess.run([ADB, *args], capture_output=True, text=True,
                          encoding="utf-8", errors="replace", timeout=timeout)


def run(cmd: list[str], log: Path, timeout: int = 600, env: dict | None = None) -> int:
    e = dict(os.environ)
    if env:
        e.update(env)
    proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8",
                          errors="replace", timeout=timeout, env=e)
    log.write_text(f"$ {' '.join(cmd)}\n\n{proc.stdout}\n--- stderr ---\n{proc.stderr}",
                   encoding="utf-8")
    return proc.returncode


def wait_boot(timeout_s: int = 240) -> bool:
    end = time.time() + timeout_s
    while time.time() < end:
        if adb("shell", "getprop", "sys.boot_completed", timeout=20).stdout.strip() == "1":
            return True
        time.sleep(4)
    return False


def wait_for_app(package: str, timeout_s: int = 40) -> str | None:
    """**冷启动竞争**：am start 投出 intent 就返回，进程要几秒后才出现；
    立刻 pidof 退出码是 1，与"应用真的起不来"无法区分。
    钩子是 attach 模式（core/frida_host/run.py 靠 pidof 找进程），所以必须先等到 pid 再挂。"""
    end = time.time() + timeout_s
    while time.time() < end:
        pid = adb("shell", "pidof", package, timeout=20).stdout.strip()
        if pid:
            return pid
        time.sleep(1.5)
    return None


def pick_free_port() -> int:
    """上游接收端用**空闲端口**，不用固定 8080。

    实测：上一轮的 collector 若没被干净收掉，这一轮 bind 会失败，
    而失败发生在子进程里——主控只看到"上游返回 404"，看起来像应用发错了路径。
    每次挑一个空闲端口，这类冲突就不存在。
    """
    import socket
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def ensure_frida_server(log: Path) -> bool:
    """frida-server 必须以 **root** 身份在跑，且要先起来。

    两个都实测踩过，而且报错都不指向原因：
      * 没起 → `frida.TransportError: connection closed`（只字不提它没在跑）；
      * 以 shell 身份起 → `frida.PermissionDeniedError: unable to access process with pid N`
        （Android 10+ 禁止跨 uid 访问应用进程，frida-server 必须 uid 0）。
    设备是 userdebug，`adb root` 可用。
    """
    adb("root", timeout=60)
    time.sleep(3)                       # adbd 会以 root 重启一次，连接会短暂断开
    adb("wait-for-device", timeout=60)
    ps = adb("shell", "ps -A -o USER,NAME | grep frida-server", timeout=40).stdout
    if "root" not in ps:
        adb("shell", "killall frida-server", timeout=30)   # 清掉可能存在的 shell 版
        time.sleep(1)
        adb("shell", "nohup /data/local/tmp/frida-server -l 127.0.0.1:27043 "
                     ">/dev/null 2>&1 &", timeout=60)
        time.sleep(5)
        ps = adb("shell", "ps -A -o USER,NAME | grep frida-server", timeout=40).stdout
    adb("forward", "tcp:27043", "tcp:27043", timeout=40)
    log.write_text(f"ps:\n{ps}\n", encoding="utf-8")
    return "root" in ps and "frida-server" in ps


def ensure_wifi(log: Path) -> bool:
    """AAOS 模拟器**只走 wifi**（eth0 永远 down），而且 wifi 会周期性掉线。
    掉线后设备侧一切照常、只是"网络不可达"——外发失败会被读成"应用没外发"。
    所以每轮开始先确认 wlan0 是通的，不通就重连。"""
    status = adb("shell", "cmd", "wifi", "status", timeout=40).stdout
    addr = adb("shell", "ip", "-brief", "addr", "show", "wlan0", timeout=40).stdout
    ok = "connected" in status.lower() and "UP" in addr
    if not ok:
        adb("shell", "cmd", "wifi", "connect-network", "AndroidWifi", "open", timeout=60)
        time.sleep(8)
        status = adb("shell", "cmd", "wifi", "status", timeout=40).stdout
        addr = adb("shell", "ip", "-brief", "addr", "show", "wlan0", timeout=40).stdout
        ok = "connected" in status.lower() and "UP" in addr
    probe = adb("shell", "echo -n '' | toybox nc -w 3 10.0.2.2 8080; echo rc=$?", timeout=40).stdout
    log.write_text(f"wifi status:\n{status}\nwlan0:\n{addr}\nhost-probe:\n{probe}\n",
                   encoding="utf-8")
    return ok


def check_proxy_clean(log: Path) -> bool:
    """记忆里的坑：残留的全局代理会被 ConnectivityService 缓存，即使 settings 已是 null
    新进程照样走代理。症状是 mitmproxy 收到 CONNECT —— 反向模式本不该收到。"""
    cur = adb("shell", "settings", "get", "global", "http_proxy", timeout=30).stdout.strip()
    ok = cur in ("null", "")
    log.write_text(f"global http_proxy = {cur!r}；clean={ok}\n"
                   "（若不为 null：`adb shell settings put global http_proxy :0` 后 **reboot**"
                   " 才真正清干净——缓存不会随 settings 立即失效）\n", encoding="utf-8")
    return ok


def start_collector(log: Path, port: int) -> subprocess.Popen:
    """复用 core 的接收端（POST /collect → 200），无需新写。"""
    proc = subprocess.Popen([PY, str(ROOT / "core" / "collector" / "collector_server.py"),
                             "--port", str(port)],
                            stdout=open(log, "w", encoding="utf-8"), stderr=subprocess.STDOUT)
    time.sleep(1.5)
    return proc


def start_mitm(session: Path, log: Path, upstream_port: int) -> subprocess.Popen:
    env = dict(os.environ)
    env.update({
        "VSCAN_FLOW_LOG": str(session / "flows.jsonl"),
        "VSCAN_UNANSWERED_LOG": str(session / "flows-unanswered.jsonl"),
        "VSCAN_ATTRIB_SOURCES": str(session / "egress.jsonl"),
        "VSCAN_PACKAGES": PKG,
        "VSCAN_SESSION": session.name,
    })
    proc = subprocess.Popen(
        ["mitmdump", "-s", str(MOBILE / "traffic" / "addon_mobile.py"),
         "--mode", f"reverse:http://127.0.0.1:{upstream_port}",
         "--listen-host", "0.0.0.0", "--listen-port", str(MITM_PORT)],
        stdout=open(log, "w", encoding="utf-8"), stderr=subprocess.STDOUT, env=env)
    time.sleep(6.0)   # mitmproxy 启动要几秒；等不够会"应用连不上代理"而不是"代理没起来"
    return proc


def start_hook(script: str, session: Path, out_name: str, log: Path,
               seconds: int) -> subprocess.Popen:
    env = dict(os.environ)
    env["VSCAN_SESSION"] = session.name
    # 优雅停止哨兵（2026-10-16）：收尾走 tp_env.stop_hook 而不是 proc.terminate()——
    # 强杀会让 agent 在未清理状态下收尾（CheckJNI 必发 DeleteGlobalRef abort，
    # 污染死亡取证）。路径挂在 Popen 上供 stop_hook 取用；启动前删残留。
    stop_file = session / (out_name + ".stop")
    try:
        stop_file.unlink()
    except OSError:
        pass
    proc = subprocess.Popen(
        [PY, str(ROOT / "core" / "frida_host" / "run.py"), "--package", PKG,
         "--script", str(script), "--seconds", str(seconds),
         "--allow-package", PKG, "--session", session.name,
         "--out", str(session / out_name), "--stop-file", str(stop_file)],
        stdout=open(log, "w", encoding="utf-8"), stderr=subprocess.STDOUT, env=env)
    proc.stop_file = stop_file  # type: ignore[attr-defined]
    return proc


def clear_system_dialogs(marker_log: Path) -> str:
    """每次触发前先清掉遮挡界面的系统弹窗。

    为什么必须每轮都清：系统权限弹窗是**异步弹出**的，可能在 btnPerm 之后
    又晚一两秒才出现，于是它挡住的是**后面几个**按钮——实测表现为
    "前一个按钮过了、后三个全找不到控件"，看上去像控件 id 或滚动的问题。
    按 BACK 关掉它（= 拒绝），仍然会产生 PERM_RESULT，是合法证据。
    """
    text = ""
    for attempt in range(2):
        adb("shell", "uiautomator", "dump", "/data/local/tmp/dlg.xml", timeout=45)
        text = adb("shell", "cat", "/data/local/tmp/dlg.xml", timeout=45).stdout
        if "permissioncontroller" in text or "允许" in text or "Allow" in text:
            adb("shell", "input", "keyevent", "4", timeout=30)
            time.sleep(1.2)
            continue
        break
    marker_log.write_text(text[-4000:], encoding="utf-8")
    return "cleared" if ("允许" in text or "permissioncontroller" in text) else "none"


def trigger(name: str, log: Path, user: int | None) -> int:
    cmd = [PY, str(MOBILE / "tools" / "trigger.py"), "--package", PKG, "--button", name]
    if user is not None:
        cmd += ["--user", str(user)]
    return run(cmd, log, timeout=180)


def try_answer_permission_dialog(log: Path) -> tuple[bool, str]:
    """处理系统权限弹窗。→ (是否处理掉, 方式)

    两条路，都产生**合法的 PERM_RESULT**：
      * 找到「允许」按钮就点掉 → granted；
      * 找不到就按 BACK 关掉 → denied。
    为什么要 BACK 兜底：弹窗的形状随系统版本/车机定制而变（实测 AAOS 上前面几种
    匹配都不中），而**弹窗不关掉会盖住整个界面**，后续所有按钮触发都会报
    "界面上找不到控件"——一个看起来像控件 id 写错、实则是弹窗没处理的问题。
    返回方式字符串是为了让报告能说明这一轮的"同意"是怎么产生的。
    """
    import re
    time.sleep(2.0)   # 弹窗弹出需要一点时间；立刻 dump 常常 dump 到还没有弹窗的界面
    xml = adb("shell", "uiautomator", "dump", "/data/local/tmp/perm.xml", timeout=60)
    text = adb("shell", "cat", "/data/local/tmp/perm.xml", timeout=60).stdout
    log.write_text(xml.stdout + text, encoding="utf-8")

    patterns = [
        r'resource-id="com\.android\.permissioncontroller:id/permission_allow_button"[^>]*bounds="\[(\d+),(\d+)]\[(\d+),(\d+)]"',
        r'resource-id="[^"]*permission_allow[^"]*"[^>]*bounds="\[(\d+),(\d+)]\[(\d+),(\d+)]"',
        r'text="(?:允许|始终允许|仅在使用时允许|Allow|While using the app)"[^>]*bounds="\[(\d+),(\d+)]\[(\d+),(\d+)]"',
    ]
    for pat in patterns:
        m = re.search(pat, text)
        if m:
            x1, y1, x2, y2 = (int(g) for g in m.groups())
            adb("shell", "input", "tap", str((x1 + x2) // 2), str((y1 + y2) // 2), timeout=30)
            time.sleep(1.5)
            return True, "tapped_allow"

    if "permissioncontroller" in text or "允许" in text or "Allow" in text:
        adb("shell", "input", "keyevent", "4", timeout=30)   # BACK = 拒绝
        time.sleep(1.5)
        return True, "dismissed_by_back"
    return False, "no_dialog_found"