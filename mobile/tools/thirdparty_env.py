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


def start_mitm(session: Path, log: Path, package: str) -> subprocess.Popen:
    """**常规代理模式**（不是 reverse）——第三方样本要访问它自己的服务端。"""
    env = dict(os.environ)
    env.update({
        "VSCAN_FLOW_LOG": str(session / "flows.jsonl"),
        "VSCAN_UNANSWERED_LOG": str(session / "flows-unanswered.jsonl"),
        "VSCAN_ATTRIB_SOURCES": os.pathsep.join([
            str(session / "egress.jsonl"), str(session / "egress_tp.jsonl")]),
        "VSCAN_PACKAGES": package,
        "VSCAN_SESSION": session.name,
        # 常规代理模式看得见真实目标 host:port，开目标校验把"别的 App 的流误认领给
        # 被审计包"这条静默错误路径关掉（见 core/collector/DECISIONS D413）。
        # **只在常规代理模式开**：reverse 模式所有 App 寻址同一代理端口，开了会把
        # 整场归因静默变 unresolved——reverse 路径（device_run.py）不设此变量。
        "VSCAN_ATTRIB_TARGET_CHECK": "1",
    })
    # **必须关掉子进程的 stdout 块缓冲**：管道/文件重定向下 Python 默认 8KB 块缓冲，
    # 而收尾一律 `taskkill /T /F`（见 kill_tree）——缓冲里没落盘的内容直接蒸发。
    # 实测：breezy 那一轮的 mitm.log 最终 0 字节（连启动横幅都没有），事后无法诊断
    # "代理到底起没起、见到了什么连接"。数据本身在 sqlite 里没丢，但人读的日志没了，
    # 违反"失败可诊断"。PYTHONUNBUFFERED 会被 mitmdump 的 console launcher 透传给
    # 真正干活的 python 子进程。
    env["PYTHONUNBUFFERED"] = "1"
    # stdin=DEVNULL：不让子进程继承标准句柄，否则下游攥住句柄会让编排层 subprocess.run 阻塞。
    proc = subprocess.Popen(
        ["mitmdump", "-s", str(MOBILE / "traffic" / "addon_mobile.py"),
         "--listen-host", "0.0.0.0", "--listen-port", str(MITM_PORT)],
        stdin=subprocess.DEVNULL, stdout=open(log, "w", encoding="utf-8"),
        stderr=subprocess.STDOUT, env=env)
    time.sleep(7.0)   # mitmproxy 启动要几秒；等不够会"应用连不上代理"而非"代理没起来"
    return proc


def start_hook(script: Path, session: Path, out_name: str, log: Path,
               seconds: int, package: str) -> subprocess.Popen:
    env = dict(os.environ)
    env["VSCAN_SESSION"] = session.name
    env["PYTHONUNBUFFERED"] = "1"   # 见 start_mitm 的注释：杀掉子进程时缓冲内容会丢
    proc = subprocess.Popen(
        [PY, str(ROOT / "core" / "frida_host" / "run.py"), "--package", package,
         "--script", str(script), "--seconds", str(seconds),
         "--allow-package", package, "--session", session.name,
         "--out", str(session / out_name)],
        stdin=subprocess.DEVNULL, stdout=open(log, "w", encoding="utf-8"),
        stderr=subprocess.STDOUT, env=env)
    return proc


def app_uid(package: str) -> int | None:
    """应用 uid（不是 pid）。取不到返回 None——调用方据此跳过采样，
    绝不用一个猜的 uid 去采样然后报"零外发"。"""
    for args in (("shell", "stat", "-c", "%u", f"/data/data/{package}"),
                 ("shell", "dumpsys", "package", package)):
        out = adb(*args, timeout=45).stdout
        m = re.search(r"userId=(\d+)", out)
        if m:
            return int(m.group(1))
        if out.strip().isdigit():
            return int(out.strip())
    return None


def start_conn_probe(session: Path, log: Path, package: str,
                     seconds: int) -> subprocess.Popen:
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
    pid_res = adb("shell", "pidof", package, timeout=30)
    err = (pid_res.stderr or "").strip()
    if "error:" in err:
        return {"alive_at_end": None, "pid": None, "fatal_lines": [], "cause": None,
                "error": err.splitlines()[0], "package": package}
    pid = (pid_res.stdout or "").strip()
    log = adb("logcat", "-d", "-b", "main", "-b", "system", "-b", "crash",
              "-v", "time", timeout=120).stdout or ""
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
