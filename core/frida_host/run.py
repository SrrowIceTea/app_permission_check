#!/usr/bin/env python3
"""Drive a Phase 3 hook bundle and collect its JSONL on the PC.

仅用于授权测试（自有设备与自有 APK）/ For authorized testing on owned devices and APKs only.

Why the JSONL lands on the PC rather than /data/local/tmp: hooking the *app* process
is the only way to observe CarPropertyManager reads (system_server cannot bind the
Car service - it has no app identity), and an app runs as untrusted_app, which
SELinux forbids from appending to shell_data_file. Measured denial:

    avc: denied { append } for name="vscan.log"
      scontext=u:r:untrusted_app:s0:c250,... tcontext=u:object_r:shell_data_file:s0
      permissive=0

So the script streams each event with send() and this driver owns the file. The
script still attempts a best-effort device-side copy for the cases where that is
permitted (system_server, com.android.car).

  python run.py --package com.vscanner.targetapp --script dist/hook_vhal.bundle.js \
      --seconds 30 --out logs/hook_vhal.jsonl

Requires: the frida Python module (Python313 interpreter on this machine), a
frida-server already running on the device, and dist/<name>.bundle.js built by
build.py - an unbundled script cannot run on Frida 17.
"""
from __future__ import annotations

import argparse
import os
import re
import threading
import uuid
import json
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent.parent))
from core.event_store import EventStore
from core.frida_host.bundle_config import configure
# frida-server on this device is started with `-l 127.0.0.1:27043`, not the default
# 27042. Connecting to 27042 fails with "connection closed"; the forward is required.
FRIDA_PORT = 27043


def adb(*args: str, timeout: int = 60) -> str:
    return subprocess.run(["adb", *args], capture_output=True, encoding="utf-8",
                          errors="replace", timeout=timeout, check=True).stdout.strip()


def ensure_forward() -> None:
    forwards = adb("forward", "--list")
    if f"tcp:{FRIDA_PORT}" not in forwards:
        adb("forward", f"tcp:{FRIDA_PORT}", f"tcp:{FRIDA_PORT}")
        print(f"established adb forward tcp:{FRIDA_PORT}", flush=True)


def pid_alive(pid: int) -> bool:
    """进程还在不在。用 /proc/<pid> 而不是 `pidof`——**pidof 会返回一个同名的新 pid**，
    换过进程之后它照样有输出，看上去一切正常。这里要问的是"原来那个还在吗"。"""
    return adb("shell", f"if test -d /proc/{pid}; then echo y; else echo n; fi").strip() == "y"


def resolve_pid(package: str) -> int:
    out = adb("shell", f"pidof {package}")
    pids = out.split()
    if not pids:
        raise SystemExit(
            f"{package} is not running. Start it first, e.g.\n"
            f"  adb shell am start -n {package}/.MainActivity\n"
            "Frida spawn is unreliable on this emulator (times out while the app "
            "launches normally), so this driver attaches instead."
        )
    return int(pids[0])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("--pid", type=int)
    target.add_argument("--package")
    parser.add_argument("--script", required=True, type=Path,
                        help="a dist/*.bundle.js produced by build.py")
    parser.add_argument("--seconds", type=float, default=30.0)
    parser.add_argument("--out", type=Path, required=True, help="JSONL written on this PC")
    parser.add_argument("--gadget", action="store_true")
    parser.add_argument("--spawn", action="store_true",
                        help="spawn 注入（钩子在应用第一条指令前就位）。"
                             "用于必须抓启动瞬间流量的场景；默认 attach。")
    parser.add_argument("--port", type=int)
    parser.add_argument("--allow-package", action="append")
    parser.add_argument("--event-db", type=Path)
    parser.add_argument("--session", default=None)
    parser.add_argument("--label", default="", help="free-form tag stored on every record")
    # 分档定位开关（DEV_FIX_REPORT §5.1 A1/H1+H2）。环境变量是主通道：mobile 的
    # device_run*.py 经 thirdparty_env.start_hook 透传 os.environ 给本进程，
    # `VSCAN_WATCH_LIMIT=8 python mobile/tools/device_run_thirdparty.py ...` 即可分档。
    parser.add_argument("--watch-limit", type=int, default=None,
                        help="只挂前 N 条监视项（0=全不挂；未给=全量）。同 VSCAN_WATCH_LIMIT")
    parser.add_argument("--no-stack", action="store_true",
                        help="事件不带 thread_name/stack 字段值。同 VSCAN_NO_STACK=1")
    parser.add_argument("--args-only", action="store_true",
                        help="H5：事件不带任何返回值字段（不哈希、不计数）。同 VSCAN_ARGS_ONLY=1")
    parser.add_argument("--deoptimize", type=int, default=None, choices=[0, 1, 2],
                        help="A1 修复：替换 ArtMethod 前把已编译方法退回解释器，消除 JIT 竞态"
                             "（1=everything、2=boot image、0=关）。同 VSCAN_DEOPTIMIZE")
    parser.add_argument("--stop-file", type=Path, default=None,
                        help="优雅停止哨兵：该文件一出现就结束采集、走正常 detach 退出。"
                             "调用方应以此替代 taskkill /F——强杀会让 agent 在未清理状态下"
                             "收尾，CheckJNI（userdebug 默认开启）上必发 "
                             "'DeleteGlobalRef ... without being attached' abort，"
                             "每轮一次、污染 app-death 取证（2026-10-16 实测，见 "
                             "thirdparty_env.stop_hook 注释）")
    args = parser.parse_args()
    if args.watch_limit is None:
        env_limit = os.environ.get("VSCAN_WATCH_LIMIT", "").strip()
        if env_limit:
            try:
                args.watch_limit = int(env_limit)
            except ValueError:
                parser.error(f"VSCAN_WATCH_LIMIT 不是整数：{env_limit!r}")
    if args.watch_limit is not None and args.watch_limit < 0:
        parser.error("--watch-limit 不能为负（0=全不挂）")
    no_stack = args.no_stack or os.environ.get("VSCAN_NO_STACK", "").strip() == "1"
    args_only = args.args_only or os.environ.get("VSCAN_ARGS_ONLY", "").strip() == "1"
    if args.deoptimize is None:
        env_deopt = os.environ.get("VSCAN_DEOPTIMIZE", "").strip()
        if env_deopt:
            try:
                args.deoptimize = int(env_deopt)
            except ValueError:
                parser.error(f"VSCAN_DEOPTIMIZE 不是整数：{env_deopt!r}")
    if args.deoptimize is not None and args.deoptimize not in (0, 1, 2):
        parser.error("VSCAN_DEOPTIMIZE 只能是 0（关）/ 1（everything）/ 2（boot image）")
    global FRIDA_PORT
    FRIDA_PORT = args.port or (27044 if args.gadget else 27043)
    # 白名单**没有默认值**（§8.2 B-1）：内核不再默认放行车载夹具包名，
    # 授权测试的包名必须由调用方显式给出。
    allowed = args.allow_package or []
    if not allowed:
        parser.error("未给 --allow-package：白名单为空（内核不再默认假定 "
                     "com.vscanner.targetapp{,2}）。授权测试请显式列出受监控包名。")
    if any(not re.fullmatch(r"[A-Za-z]\w*(?:\.\w+)+", pkg) for pkg in allowed):
        parser.error("无效白名单包名")
    if args.package and args.package not in allowed:
        parser.error("目标未在白名单；授权包需显式 --allow-package")
    if args.gadget and not args.package:
        parser.error("Gadget 模式必须使用 --package")
    session_id = args.session or uuid.uuid4().hex
    failed = []
    lock = threading.Lock()

    try:
        import frida  # noqa: PLC0415
    except ImportError:
        print("frida module missing. Use the Python313 interpreter that has frida installed:\n"
              f"  {sys.executable} run.py ...",
              file=sys.stderr)
        return 2

    if not args.script.exists():
        print(f"no such script: {args.script}", file=sys.stderr)
        return 2
    body = args.script.read_text(encoding="utf-8")
    if "frida-java-bridge" not in body:
        print(f"{args.script.name} does not bundle the Java bridge. On Frida 17 it will "
              f"fail with `ReferenceError: 'Java' is not defined`. Run build.py first.",
              file=sys.stderr)
        return 2

    ensure_forward()
    args.out.parent.mkdir(parents=True, exist_ok=True)

    device = frida.get_device_manager().add_remote_device(f"127.0.0.1:{FRIDA_PORT}")
    if args.gadget:
        pid = device.spawn(["re.frida.Gadget"])
    elif args.spawn:
        # spawn 注入（2026-10-18 新增）：attach 模式下应用**启动那一刻**的握手/外发
        # 全在钩子装上之前，实测 F-Droid 首轮 SSL 明文一条没捕到、keylog 也装不上
        # （App 的 SSL_CTX 在我们 attach 前就建好了）。spawn 时钩子在应用跑第一条
        # 指令前就已就位，这两处缺口同时消失。
        if not args.package:
            print("--spawn 需要 --package", file=sys.stderr)
            return 2
        pid = device.spawn([args.package])
    else:
        pid = args.pid or resolve_pid(args.package)
    session = device.attach(pid)
    session.on("detached", lambda *info: failed.append("detached: " + str(info)))
    store = EventStore(args.event_db or args.out.with_suffix(".sqlite"))
    script = session.create_script(
        configure(body, allowed, watch_limit=args.watch_limit, no_stack=no_stack,
                  args_only=args_only, deoptimize=args.deoptimize))
    if (args.watch_limit is not None or no_stack or args_only
            or args.deoptimize is not None):
        print(f"分档模式：watch_limit={args.watch_limit} no_stack={no_stack} "
              f"args_only={args_only} deoptimize={args.deoptimize}", flush=True)

    counts: dict[str, int] = {}
    records = 0

    def process_message(message, _data):
        nonlocal records
        if message.get("type") == "send":
            payload = message.get("payload") or {}
            line = payload.get("line")
            if not line:
                return
            record = json.loads(line)
            if args.label:
                record["run_label"] = args.label
            # 主机收到该事件的时刻。**设备与主机的时钟偏移会漂移**（实测曾从
            # "设备快 530ms"漂到"设备慢 1731ms"），任何固定偏移假设都会静默失效。
            # 这个字段让下游（Phase 4 归因）完全绕开跨时钟比较。
            record["host_received_ts"] = int(time.time() * 1000)
            record["session_id"] = session_id
            line = json.dumps(record, ensure_ascii=False)
            with args.out.open("a", encoding="utf-8") as handle:
                handle.write(line + "\n")
            with lock:
                store.append(session_id, str(args.out.resolve()), record)
            records += 1
            event = json.loads(line).get("ev", "?")
            counts[event] = counts.get(event, 0) + 1
        elif message.get("type") == "error":
            failed.append("script_error")
            record = {"ev": "SCRIPT_ERROR", "src": "driver", "session_id": session_id,
                      "host_received_ts": int(time.time() * 1000), "message": message}
            with args.out.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(record, ensure_ascii=False) + "\n")
            print("SCRIPT ERROR " + json.dumps(message, ensure_ascii=False)[:400], flush=True)

    def on_message(message, data):
        try:
            process_message(message, data)
        except Exception as exc:
            failed.append("capture_error: " + str(exc))
            error = {"ev": "CAPTURE_ERROR", "src": "driver", "session_id": session_id,
                     "host_received_ts": int(time.time() * 1000), "error": str(exc)}
            print(json.dumps(error, ensure_ascii=False), file=sys.stderr, flush=True)
            try:
                with args.out.open("a", encoding="utf-8") as handle:
                    handle.write(json.dumps(error, ensure_ascii=False) + "\n")
            except OSError:
                pass  # stderr 与非零退出码仍保留故障，不能伪装成零事件。

    script.on("message", on_message)
    script.load()
    if args.gadget or args.spawn:
        device.resume(pid)
    print(f"attached pid {pid}; collecting for {args.seconds:.0f}s -> {args.out}", flush=True)

    # 轮询而不是一觉睡到底：**进程中途死掉的话，钩子跟着消失**，此后一个事件也收不到。
    # 而"钩子掉了"与"应用什么都没做"的结果**完全一样**——一个空 JSONL，
    # 没有任何异常。实测踩过：挂了两个钩子，点完两个按钮回来是零条记录，
    # 日志干干净净，只能靠事后比对 pid 才发现进程早就换了一个。
    started = time.monotonic()
    deadline = started + args.seconds
    died_at = None
    try:
        while time.monotonic() < deadline:
            time.sleep(1.0)
            if failed:
                break
            if args.stop_file is not None and args.stop_file.exists():
                # 优雅停止（2026-10-16）：调用方以文件哨兵收尾而非 taskkill——
                # 强杀会让 agent 在未清理状态下收尾，CheckJNI 上必发
                # "DeleteGlobalRef ... without being attached" abort（实测每轮一次）。
                # 这里 break 后走 finally 的 session.detach()，正常卸载。
                print("stop-file 出现：优雅收尾（正常 detach）", flush=True)
                break
            if not args.gadget and died_at is None and not pid_alive(pid):
                died_at = time.monotonic()
                print(f"\n!! pid {pid} 在第 {died_at - started:.0f}s 消失——钩子已随之失效，"
                      f"此后的事件一条也收不到。\n"
                      f"!! 这**不是**「应用没有动作」：两者都表现为记录为空。"
                      f"请确认 pid 是否变了（adb shell pidof {args.package or ''}）。", flush=True)
    except KeyboardInterrupt:
        print("interrupted", flush=True)
    finally:
        unhealthy = bool(failed) or died_at is not None
        run_catching(session.detach, "detach")
        store.close()

    print(f"\ncollected {records} JSONL records")
    for event in sorted(counts):
        print(f"  {counts[event]:5}  {event}")
    return 1 if unhealthy else 0


def run_catching(fn, what: str) -> None:
    try:
        fn()
    except Exception as exc:  # noqa: BLE001
        print(f"{what}: {exc}", flush=True)


if __name__ == "__main__":
    raise SystemExit(main())
