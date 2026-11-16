#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""批次守护进程：模拟器崩溃后自动复位，批次用 `--resume` 接着跑。

**为什么需要它**（2026-10-19 实测）：本机跑批每 ~20 分钟 qemu 进程会消失——
不是脚本报错退出，是模拟器进程本身没了。批次随之 `device_failed` 终止，
前几个样本的产出完好，但没人接着跑下一个。几小时的批次不能靠人盯。

它是 `supervise60.py`（原先躺在 D:/vscanner-tp/ds-run 里写死旧批次）的正式版本：
  - 输出目录 / 样本目录 / 分类表全部参数化，不再绑死某一次跑批
  - SDK 路径统一走 `core.sdk_paths`，不再写死 `D:/Anroid/SDK`
  - 端口回收改用 `thirdparty_env.reclaim_port`（只收自己的残留 mitm），
    原版 `kill_port` 会把 8888 上**任何**进程 taskkill 掉——同机别的采集
    会被无声打断

**硬约束**（都是踩过的坑，不能简化）：
  ① 代理必须**先于**模拟器进程存在。emulator 只在启动那一刻探测 `-http-proxy`
     地址，失败就把 SLIRP 重定向整条关掉，事后补起代理也不会恢复
     （见 `mobile/traffic/transparent.py:emulator_capture_args`）。
  ② `-writable-system` + 装系统 CA/APEX 信任库，否则 HTTPS 全断。
     APEX 那步是挂进 zygote 命名空间，不需要重启设备。
  ③ 上次崩溃可能留下 AVD 锁文件，不清掉下次启动直接失败。

用法：
    python supervise_batch.py --apk-dir "D:/数据集/数据集/F-Droid-60" \
        --out "D:/vscanner-tp/ds60b" --static-reuse "D:/数据集/数据集/static-batch-fdroid60" \
        --category-file "D:/vscanner-tp/ds-category-args.txt"
"""
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "mobile" / "traffic"))

from core import sdk_paths  # noqa: E402
from core.log_rotation import open_capped  # noqa: E402

ADB = sdk_paths.sdk_tool("platform-tools", "adb.exe")
EMULATOR = sdk_paths.sdk_tool("emulator", "emulator.exe")
AVD = "VScan_Phone"
MITM_PORT = 8888

RUN_DIR: Path = Path(".")
LOG: Path = Path("supervise.log")


def log(msg: str) -> None:
    line = f"[{time.strftime('%H:%M:%S')}] {msg}"
    print(line, flush=True)
    # 守护进程一跑几小时、每轮还追加一次，走有上限的追加（超 20 MB 分卷）。
    with open_capped(LOG) as fh:
        fh.write(line + "\n")


def adb(*args: str, timeout: int = 60) -> subprocess.CompletedProcess:
    return subprocess.run([ADB, *args], capture_output=True, text=True,
                          encoding="utf-8", errors="replace", timeout=timeout)


def device_ok() -> bool:
    """有没有**任何**一台已开机完成的设备。

    不写死 `emulator-5554`：端口会随之前的实例漂移（5554/5556/…），
    写死会让"设备其实在线"被判成掉线，于是每轮都去重启、互相打断。
    """
    out = adb("devices", timeout=30).stdout
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[1] == "device":
            p = adb("-s", parts[0], "shell", "getprop", "sys.boot_completed", timeout=30)
            if p.stdout.strip().replace("\r", "") == "1":
                return True
    return False


def start_pre_proxy():
    """模拟器启动探测用的占位代理。起来后立刻收掉，把端口让给批次。

    直接复用 `thirdparty_env.start_mitm`：它自带「端口被占就报错」和
    「起来后确认真在监听」两道校验。自己拼 mitmdump 命令行实测起不来
    （子进程静默退出），而这层静默恰恰是 emulator `-http-proxy` 探测会踩的坑。
    """
    import thirdparty_env as tpe
    ok, note = tpe.reclaim_port(MITM_PORT)
    if not ok:
        log(f"端口 {MITM_PORT} 无法回收：{note}")
        return None
    sess = RUN_DIR / "_preproxy"
    sess.mkdir(parents=True, exist_ok=True)
    try:
        return tpe.start_mitm(sess, sess / "mitm.log", "com.vscanner.privacydemo")
    except RuntimeError as exc:
        log(f"占位代理启动失败：{exc}")
        return None


def start_emulator(seconds_boot: int = 420) -> bool:
    # headless 模式的进程名是 qemu-system-x86_64-headless.exe，不是带窗口时的
    # qemu-system-x86_64.exe——只收后者会留下僵尸占着 AVD 和 5554。
    for exe in ("qemu-system-x86_64.exe", "qemu-system-x86_64-headless.exe",
                "emulator.exe"):
        subprocess.run(["taskkill", "/F", "/IM", exe],
                       capture_output=True, text=True, encoding="utf-8", errors="replace")
    time.sleep(3)
    # AVD 目录**不一定**在 %USERPROFILE%\.android\avd：本机设了 ANDROID_AVD_HOME
    # （`D:\Android studio\AVD`），按 USERPROFILE 拼出来的路径根本不存在，于是
    # "清 AVD 锁"这一步静默变成 no-op——上一次 qemu 崩溃留下的 *.lock 会让下次启动
    # 直接失败，而日志里只有一行"模拟器 xxx s 内未启动完成"，看不出是锁。
    avd_home = Path(os.environ.get("ANDROID_AVD_HOME")
                    or Path(os.environ.get("USERPROFILE", "")) / ".android" / "avd")
    avd_dir = avd_home / f"{AVD}.avd"
    if avd_dir.exists():
        for lock in avd_dir.glob("*.lock"):
            shutil.rmtree(lock, ignore_errors=True)
    else:
        log(f"⚠ 未找到 AVD 目录 {avd_dir}（ANDROID_AVD_HOME={os.environ.get('ANDROID_AVD_HOME')}）"
            "——跳过清锁；若启动失败请先手动清 *.lock")

    proxy = start_pre_proxy()
    if proxy is None:
        log("占位代理未能在 8888 就绪——启动模拟器会让 SLIRP 重定向静默失效，放弃本轮")
        return False
    log("占位代理就绪，启动模拟器（headless / swiftshader）")
    emu_log = open_capped(RUN_DIR / "emulator.log")
    emu_log.write(f"\n===== {time.strftime('%Y-%m-%d %H:%M:%S')} 重启 =====\n")
    emu_log.flush()
    subprocess.Popen(
        [EMULATOR, "-avd", AVD, "-no-boot-anim", "-no-window",
         "-gpu", "swiftshader_indirect",
         "-http-proxy", f"http://127.0.0.1:{MITM_PORT}",
         "-no-snapshot-load", "-writable-system"],
        stdout=emu_log, stderr=emu_log)

    booted = False
    for i in range(max(1, seconds_boot // 6)):
        if device_ok():
            booted = True
            log(f"启动完成（约 {i * 6}s）")
            break
        time.sleep(6)

    if not booted:
        log(f"模拟器 {seconds_boot}s 内未启动完成")
        proxy.kill()
        return False

    import transparent as tp
    res = tp.install_system_ca()
    log(f"系统 CA: installed={res.get('installed')} "
        f"apex={res.get('apex', {}).get('mounted')} err={res.get('error')}")
    adb("shell", "stop", "vendor.uwb_hal", timeout=30)
    adb("shell", "settings", "put", "global", "http_proxy", ":0", timeout=30)
    time.sleep(3)

    proxy.kill()
    subprocess.run(["taskkill", "/PID", str(proxy.pid), "/T", "/F"],
                   capture_output=True, text=True, encoding="utf-8", errors="replace")
    log("占位代理已收，端口让给批次")
    return res.get("installed") is True


def batch_progress(out_dir: Path, apk_dir: Path) -> tuple[int, int]:
    from batch_plan import completed_attempt

    apks = sorted(apk_dir.glob("*.apk"))
    done = 0
    for d in out_dir.glob("*"):
        if not d.is_dir() or d.name.startswith("_"):
            continue
        if completed_attempt(d):
            done += 1
    return done, len(apks)


def run_batch(args, cats: list[str]) -> int:
    cmd = [sys.executable, str(HERE / "batch_thirdparty.py"),
           "--apk-dir", str(args.apk_dir), "--out", str(args.out),
           "--skip-ai", "--seconds", str(args.seconds), "--resume", *cats]
    if args.static_reuse:
        cmd += ["--static-reuse", str(args.static_reuse)]
    if getattr(args, "spawn_hook", False):
        cmd += ["--spawn-hook"]
    # 政策库必须透传（2026-10-20 修）：`batch_thirdparty`/`batch_dynamic` 早就支持
    # `--policy-store`，但守护进程不转发，于是**批次永远用不到准备好的本地政策库**，
    # 60 个样本一律 `policy.available=false`——政策一致性维度整批不可判定。
    # 传进来但不可用也不会损伤：device_run 会先 load_policy 回验，失败就**不**把它
    # 传给 correlate（传了会挡住默认库回退）。
    if getattr(args, "policy_store", None):
        cmd += ["--policy-store", str(args.policy_store)]
    with open_capped(RUN_DIR / "batch.log") as fh:
        fh.write(f"\n===== {time.strftime('%Y-%m-%d %H:%M:%S')} 批次启动 =====\n")
        fh.flush()
        return subprocess.call(cmd, stdout=fh, stderr=subprocess.STDOUT, cwd=str(ROOT))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--apk-dir", required=True)
    ap.add_argument("--out", required=True, help="批次输出目录")
    ap.add_argument("--static-reuse", default=None)
    ap.add_argument("--category-file", default=None,
                    help="每行一个 `--category PKG=KEY` 的文本文件（原样透传）")
    ap.add_argument("--seconds", type=int, default=150)
    ap.add_argument("--max-restart", type=int, default=25)
    ap.add_argument("--boot-timeout", type=int, default=420)
    ap.add_argument("--run-dir", default=None,
                    help="守护日志与占位代理目录（默认 <out>/_supervise）")
    ap.add_argument("--spawn-hook", action="store_true",
                    help="动态阶段用 Frida spawn 注入（钩子先于应用第一条指令）。"
                         "attach 太晚导致应用启动瞬间联网漏采、flows 归因 unresolved。")
    ap.add_argument("--policy-store", default=None,
                    help="本地应用政策库目录，透传给 batch_thirdparty。"
                         "不给则逐样本回退 policy_library.DEFAULT_STORE。"
                         "目录里没有可用条目不会损伤样本——device_run 会回验后再决定用不用。")
    args = ap.parse_args()

    global RUN_DIR, LOG
    args.apk_dir = Path(args.apk_dir).resolve()
    args.out = Path(args.out).resolve()
    RUN_DIR = Path(args.run_dir).resolve() if args.run_dir else args.out / "_supervise"
    RUN_DIR.mkdir(parents=True, exist_ok=True)
    LOG = RUN_DIR / "supervise.log"
    args.out.mkdir(parents=True, exist_ok=True)

    cats: list[str] = []
    if args.category_file:
        cats = Path(args.category_file).read_text(encoding="utf-8").split()

    # 批次的 stdout 直落文件；不开无缓冲的话整段日志要等 8KB 攒满才可见，
    # 而收尾一律 taskkill——缓冲里的内容直接蒸发。
    os.environ["PYTHONUNBUFFERED"] = "1"
    os.environ["PYTHONIOENCODING"] = "utf-8"

    for attempt in range(1, args.max_restart + 1):
        done, total = batch_progress(args.out, args.apk_dir)
        log(f"第 {attempt} 轮：已完成 {done}/{total}")
        if done >= total:
            log("全部样本完成")
            return 0
        if not device_ok():
            log("设备不在线，复位模拟器")
            if not start_emulator(args.boot_timeout):
                log("复位失败，10 秒后重试")
                time.sleep(10)
                continue
        rc = run_batch(args, cats)
        done, total = batch_progress(args.out, args.apk_dir)
        log(f"批次退出 rc={rc}，已完成 {done}/{total}")
        if done >= total:
            return 0
        time.sleep(5)
    log(f"达到最大重启次数 {args.max_restart} 仍未完成")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
