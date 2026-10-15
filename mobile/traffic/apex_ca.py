#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Android 14+ 的系统信任库搬进了 conscrypt APEX，装 CA 必须多走这一步。

"为什么不是 iptables""为什么必须 `-writable-system`"见 transparent.py 的模块
开头；这里只负责把 CA 挂进**应用真正会读的那份**信任库。

## 为什么值得单独一个模块

因为这里的失败**极其安静**，而且只有在设备上才看得出来：

    adb shell 里 `ls /apex/com.android.conscrypt/cacerts` 明明有 121 张证书，
    App 却照样 `certificate unknown`。

原因是应用进程有**自己的 mount namespace**（zygote 启动时 unshare 过），只挂进
adb shell 的命名空间等于没挂。必须对**每个 zygote** 跑
`nsenter -t <pid> -m -- mount --bind ...`，之后它 fork 出来的应用才继承得到；
已经跑着的应用要重启才看得到。离线测试造不出这个场景（没有设备），
只能把**命令序列的形状**钉住——所以命令生成与执行都留在这个文件里，测试放旁边。

## 另一个安静失败：不要删正在被读的目录

不能"先摘旧挂载、再重建同一个目录"：`rm -rf` 一个正被某个命名空间当证书库读的
目录，那个命名空间会瞬间看到一个**空**信任库——比不装更糟，而且不报错。
所以每轮**新建**一个带时间戳的 stage 目录再挂上去（bind 叠挂，顶层生效），
旧目录不删。代价是 /data/local/tmp 下每轮多几百 KB，模拟器上可以忽略。
"""
from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

# 同 core 的取法：不写死本机绝对路径（§8.2 B-4）。
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from core import sdk_paths  # noqa: E402

ADB = sdk_paths.sdk_tool("platform-tools", "adb.exe")
APEX_CA_DIR = "/apex/com.android.conscrypt/cacerts"
CA_STAGE_PREFIX = "/data/local/tmp/cacerts-vscan"
# 实测：目录本身和里面每个文件都必须是这个上下文，写错会被 SELinux 挡住。
SELINUX_CTX = "u:object_r:system_security_cacerts_file:s0"
# app_zygote 给 isolatedProcess 用，不是每台设备都有——查不到就跳过。
ZYGOTE_NAMES = ("zygote64", "zygote", "webview_zygote", "app_zygote")


def adb(*args: str, timeout: int = 120) -> subprocess.CompletedProcess:
    return subprocess.run([ADB, *args], capture_output=True, text=True,
                          encoding="utf-8", errors="replace", timeout=timeout)


# --------------------------------------------------------------------------
# 纯计算部分（可离线测试）
# --------------------------------------------------------------------------

def stage_dir(stamp: str | None = None) -> str:
    """每轮一个**新**目录——见模块开头"不要删正在被读的目录"。"""
    return f"{CA_STAGE_PREFIX}-{stamp or time.strftime('%m%d-%H%M%S')}"


def mount_plan(fname: str, stage: str, src: str,
               zygote_pids: dict[str, str]) -> list[tuple[str, str]]:
    """把设备上的 `src`（PEM）挂进 APEX 信任库的完整命令序列。

    准备三步的顺序不能换：

    - `prepare` 先把**当前 APEX 里的全部证书**拷进 stage，再补我们那张。
      少拷这一步，挂上去就等于把系统 120 张根证书全弄丢了。
    - `perm` 里目录给 755、文件给 644：`chmod -R 644` 会把目录自己的 x 位
      也抹掉，root 都进不去（这是最容易被顺手写错的一处）。
    - 最后按 zygote 逐个挂。**少一个 zygote，它 fork 出来的应用就看不到这张
      CA**——表现正是 shell 里看着有、App 依然不受信。
    """
    plan = [
        ("prepare", f"mkdir -p {stage} && cp -a {APEX_CA_DIR}/. {stage}/ && "
                    f"cp {src} {stage}/{fname}"),
        ("perm", f"chown -R root:root {stage} && chmod 755 {stage} && "
                 f"chmod 644 {stage}/* && chcon -R {SELINUX_CTX} {stage}"),
        # shell 命名空间那份不服务应用，但它是人排障时唯一看得见的东西。
        ("mount_shell", f"mount --bind {stage} {APEX_CA_DIR}"),
    ]
    plan += [(f"mount_{name}",
              f"nsenter -t {pid} -m -- mount --bind {stage} {APEX_CA_DIR}")
             for name, pid in zygote_pids.items()]
    return plan


# --------------------------------------------------------------------------
# 设备操作
# --------------------------------------------------------------------------

def device_state(timeout: int = 30) -> str:
    """`"device"`，或失败缘由（如 `"error: device offline"`）；都拿不到时 `"unknown"`。

    **必须有这一层**：设备 offline 或没连上时，`adb shell` 同样返回非 0——
    和"设备上没有这个目录"根本分不开。少了它，"连不上设备"会被读成
    "不需要这一步"，于是**报一个成功的假结论**，正是本模块最该防的那种。
    """
    p = adb("get-state", timeout=timeout)
    if p.returncode == 0 and (p.stdout or "").strip() == "device":
        return "device"
    # 失败时缘由在 stderr（"error: device offline" / "no devices found"）。
    lines = [ln for ln in (p.stderr or "").splitlines() if ln.strip()]
    return lines[-1].strip() if lines else "unknown"


def zygote_pids(names: tuple[str, ...] = ZYGOTE_NAMES) -> dict[str, str]:
    """在读的 zygote 及其 pid。查不到的跳过（如没起 isolated 进程时 app_zygote）。"""
    found: dict[str, str] = {}
    for name in names:
        p = adb("shell", f"pidof {name}", timeout=30)
        pids = (p.stdout or "").split()
        if p.returncode == 0 and pids:
            found[name] = pids[0]
    return found


def visible(pid: str, fname: str) -> bool:
    """在**该 zygote 的命名空间**里能不能看见这张证书。

    只查 shell 命名空间是没有意义的——那正是"看着装好了、App 却不受信"的来源。
    """
    p = adb("shell", f"nsenter -t {pid} -m -- ls {APEX_CA_DIR}/{fname}", timeout=30)
    return p.returncode == 0 and "No such file" not in (p.stdout or "")


def install(fname: str, src: str, log: Path | None = None) -> dict:
    """把设备上的 `src` 挂进 APEX 信任库 + 每个 zygote 的命名空间。

    `src` 由调用方先 push 到设备（transparent.install_system_ca 已经做过）。
    Android < 14 没有这个 APEX，算**不适用**而不是失败。返回状态字典，不抛异常。
    """
    result: dict = {"needed": False, "mounted": False, "steps": [], "error": None}

    state = device_state()
    result["device_state"] = state
    if state != "device":
        # 连不上 ≠ 不需要。"没测到"绝不能落成"不用测"（§8.6 红线同款）。
        result["error"] = (f"设备不可用（adb get-state: {state or '连 adbd 都够不着'}）——"
                           "无法判断 APEX 信任库状态，拒绝报成功")
        return _dump(result, log)

    if adb("shell", f"ls -d {APEX_CA_DIR}", timeout=30).returncode != 0:
        result["note"] = "设备没有 conscrypt APEX 信任库（Android < 14），无需这一步"
        result["mounted"] = True          # 不适用 ≠ 失败
        return _dump(result, log)

    result["needed"] = True
    pids = zygote_pids()
    result["zygote_pids"] = pids
    if not pids:
        # 只在 shell 命名空间里挂，应用一点都拿不到。宁可不做，也不能报成功。
        result["error"] = ("没找到任何 zygote——只挂 shell 命名空间等于没挂，"
                           "应用照样不受信。拒绝在看不到 zygote 时宣称成功。")
        return _dump(result, log)

    result["stage"] = stage = stage_dir()
    for label, cmd in mount_plan(fname, stage, src, pids):
        p = adb("shell", cmd)
        result["steps"].append({"step": label, "rc": p.returncode,
                                "out": (p.stdout + p.stderr).strip()[:200]})
        if p.returncode != 0:
            result["error"] = f"步骤 {label} 失败——信任库处于半成品状态，需重跑"
            return _dump(result, log)

    seen = {name: visible(pid, fname) for name, pid in pids.items()}
    result["zygote_visible"] = seen
    result["mounted"] = bool(seen) and all(seen.values())
    if not result["mounted"]:
        result["error"] = ("挂载命令都返回成功，但某些 zygote 命名空间里看不到证书。"
                           "判断以 zygote_visible 为准，不要只看 shell 里的 ls。")
    return _dump(result, log)


def status(fname: str) -> dict:
    """排障用：APEX 在不在、有哪些 zygote、各命名空间里看不看得见这张 CA。"""
    state = device_state()
    out: dict = {"device_state": state}
    if state != "device":
        out["note"] = ("设备不可用——这是**没测到**，不是『没有 APEX』。"
                       "修好连接后重跑。")
        return out
    pids = zygote_pids()
    out.update({
        "apex_present": adb("shell", f"ls -d {APEX_CA_DIR}", timeout=30).returncode == 0,
        "zygote_pids": pids,
        "shell_namespace_sees_ca": adb(
            "shell", f"ls {APEX_CA_DIR}/{fname}", timeout=30).returncode == 0,
        "shell_note": "shell 里看得见**不代表**应用看得见——以 zygote_sees_ca 为准",
        "zygote_sees_ca": {name: visible(pid, fname) for name, pid in pids.items()},
    })
    return out


def _dump(result: dict, log: Path | None) -> dict:
    if log:
        log.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    return result


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--fname", required=True,
                    help="CA 在信任库里的文件名（transparent.android_ca_name 给出）")
    ap.add_argument("--install", metavar="SRC",
                    help="把设备上的 SRC 挂进信任库（含各 zygote 命名空间）")
    ap.add_argument("--status", action="store_true", help="只报告各命名空间的可见性")
    args = ap.parse_args()

    if args.install:
        print(json.dumps(install(args.fname, args.install), ensure_ascii=False, indent=2))
    else:
        print(json.dumps(status(args.fname), ensure_ascii=False, indent=2))
