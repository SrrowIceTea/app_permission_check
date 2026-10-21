#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""thirdparty_env 的进程层：进程树回收 / 端口占用判定 / 残留 mitmproxy 识别。

从 thirdparty_env.py 拆出，保持零行为改动。仅用于授权测试。
"""
from __future__ import annotations

import socket
import subprocess
import sys
import time
from pathlib import Path


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


def _representative_death(death: dict | None, coverage: dict | None) -> dict:
    """多段采集时，报告要引用**第一次死亡**的证据，不是最后一段的。

    实测（`a4-smoke5`）：seg0 有 `SIGSEGV @ Jit thread pool`，末段只剩"进程不在了"，
    于是 bundle 被写成"signal 未知 / 死因未记录"，而证据就躺在同目录的
    `app-death-seg0.json` 里。审计把这条列为"数据在、没被用"。
    """
    best = dict(death or {})
    for s in ((coverage or {}).get("detail") or []):
        if s.get("alive_at_end") is not False:
            continue
        d = s.get("death") or {}
        if d and not (best.get("signal") and best.get("uptime_s") is not None):
            merged = dict(best)
            for k, v in d.items():
                if v not in (None, "", [], {}):
                    merged[k] = v
            merged["window_alive"] = False
            if merged.get("hooked_pid_alive") is not False:
                merged["hooked_pid_alive"] = False
            return merged
        break
    return best


def orchestrator_notes(death: dict, package: str | None = None,
                       coverage: dict | None = None) -> list[str]:
    """编排层写给报告的缺口说明（会带 [orch] 前缀进 bundle.gaps）。

    这些限制**工具无法从数据里推出来**；不写就等于让读者把「没采集到」读成「没发生」。

    注意（2026-10-19）：上半段四条是**某一个样本**（com.domivega.gps_car）的实测边界，
    原先无条件写进所有样本——别的 APK 的报告里也会出现"本样本的天气客户端是
    loopj/AsyncHttpClient"，属于把 A 样本的结论扣到 B 样本头上。现在按包名收敛。
    """
    notes: list[str] = []
    if package == "com.domivega.gps_car":
        notes += [
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
    died = death.get("hooked_pid_alive") is False or death.get("window_alive") is False
    if died:
        # 多段采集时换成"第一次死亡"的证据：末段常常只剩"进程不在了"，
        # 而 signal/uptime 都在 seg0 里（a4-smoke5 实测过的失真）。
        death = _representative_death(death, coverage)
        # 死因必须来自**本次**证据（墓碑/信号行），不能沿用某个样本的固定说法。
        sig = death.get("signal") or "signal 未知"
        thread = death.get("thread") or "线程未知"
        uptime = death.get("uptime_s")
        cause = death.get("cause")
        if not cause and death.get("fatal_lines"):
            cause = death["fatal_lines"][0]
        notes.append(
            "应用在检测窗口内死亡："
            f"{sig}，崩溃线程 {thread}"
            + (f"，进程自报 uptime {uptime}s" if uptime is not None else "")
            + f"；死因：{cause or '未记录（墓碑/崩溃缓冲已被挤掉）'}。"
            "窗口后半段没有任何事件是**失明**，不等于「应用没有该行为」；"
            "有效观测时长见 verification.json 的 coverage.observed_s。")
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
