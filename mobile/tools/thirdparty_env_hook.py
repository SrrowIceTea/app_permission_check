#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""thirdparty_env 的 hook 层：mitmproxy 启动 / frida 解释器探测 / hook 子进程启停。

从 thirdparty_env.py 拆出，保持零行为改动。仅用于授权测试。
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

from thirdparty_env_adb import ROOT, MOBILE, PY, MITM_PORT, adb  # noqa: E402
from thirdparty_env_process import tcp_open, reclaim_port, kill_tree  # noqa: E402


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