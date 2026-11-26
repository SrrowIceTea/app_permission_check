"""Capture the background/offline/resend controls on an owned mobile emulator. 仅用于授权测试。

网络拓扑（关键）：
- mitmproxy 监听宿主 18960；设备侧 `10.0.2.2:18960`（真实网络路径，SLIRP 转发到宿主回环）
  与 `127.0.0.1:18960`（adb reverse，调试通道）都落到同一个代理，因此两条路径都能归因。
- 接收端绑随机端口，只被代理转发到；它全程监听，所以"断网区间零回执"才是有意义的判据
  （若接收端本身不在，零回执是废话）。
- 断网用飞行模式（实测唯一能放倒 eth0/wlan0 的手段），断网期间 adb reverse 仍可用，
  正好用来证明失败原因是网络而不是应用。
"""
from __future__ import annotations

import argparse
from contextlib import ExitStack, contextmanager
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import sys
import time
import uuid

from mobile.lab.mobile_network_actions import MobileNetworkActions
from mobile.lab.offline_control import PACKAGE, OBSERVATION, case_inputs
from mobile.lab.resend_receiver import start as start_receiver
from mobile.lab.window_benchmark import OFFLINE_STEPS, ROOT, check, load, rows, save, sha

sys.path.insert(0, str(ROOT / "mobile/tools"))
from device_capture import wait_listener  # noqa: E402
from device_environment import AdbClient, collect_device_profile, resolve_adb  # noqa: E402
from device_provenance import host_frida_version, inspect_gadget  # noqa: E402

ACTIVITY = PACKAGE + "/.WindowBenchmarkActivity"
GADGET_PORT = 27044
DEVICE_HTTP = "tcp:18960"
PROXY_PORT = 18960


def millis():
    return time.time_ns() // 1_000_000


def ensure_port_free(port):
    probe = socket.socket()
    probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        probe.bind(("127.0.0.1", port))
    except OSError as error:
        raise ValueError(f"宿主端口 {port} 已被占用: {error}") from error
    finally:
        probe.close()


def command(adb, *args):
    result = adb(*map(str, args), timeout=35)
    check(result.returncode == 0, f"ADB {args[:3]}: {result.stderr.strip()}")
    return result.stdout.strip()


def sample_until(predicate, processes, description, seconds=25):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        check(all(child.poll() is None for child in processes), f"采集子进程提前退出：{description}")
        result = predicate()
        if result:
            return result
        time.sleep(0.25)
    raise ValueError(f"采集等待超时：{description}")


def start_process(stack, args, logfile, env, stop_file):
    log = stack.enter_context(logfile.open("x", encoding="utf-8"))
    process = subprocess.Popen(args, cwd=ROOT, env=env, stdout=log, stderr=log)
    def close():
        if process.poll() is None:
            stop_file.touch()
            try:
                process.wait(timeout=20)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
                raise ValueError(f"采集器强制停止，检查 {logfile.name}")
        check(process.returncode == 0, f"采集器异常退出，检查 {logfile.name}")
    stack.enter_context(_cleanup(close))
    return process


@contextmanager
def _cleanup(action):
    try:
        yield
    except BaseException:
        try: action()
        except Exception as error: print(f"offline_cleanup_failed: {error}", file=sys.stderr)
        raise
    else:
        action()


def best_effort(label, action):
    try:
        return action()
    except Exception as error:  # noqa: BLE001
        print(f"offline_cleanup_failed[{label}]: {error}", file=sys.stderr)
        return None


def read_actor(adb, pid, token):
    output = command(adb, "shell", "logcat", "-d", "--pid", pid, "-v", "raw", "-s", "VScanWindow:I")
    records = [json.loads(line) for line in output.splitlines() if line.startswith("{")]
    records = [row for row in records if row.get("run") == token]
    check(not any(row.get("event") == "error" for row in records), "夹具动作报告失败")
    return records


def trigger(adb, user, step, token):
    output = command(adb, "shell", "am", "start", "-W", "--user", user, "-n", ACTIVITY,
                     "--es", "benchmark_run", token, "--es", "benchmark_step", step)
    check("Error" not in output, f"am start 失败: {step}: {output[:120]}")


def step_predicate(adb, pid, token, folder, step, read_count):
    """按步骤名显式匹配要等的事件，不再用"记录条数"隐式推算。"""
    if step.startswith(("bg-read", "read-")):
        return lambda: (lambda records: records if (
            len(obtained(rows(folder / "reads.jsonl"))) >= read_count
            and len([r for r in records if r["event"] == "read"]) >= read_count) else None)(
                read_actor(adb, pid, token))
    if step.startswith("bg-probe"):
        stage = step.removeprefix("bg-probe-")
        return lambda: (lambda records: records if any(
            r["event"] == "probe" and r.get("stage") == stage for r in records) else None)(
                read_actor(adb, pid, token))
    wanted = {"bg-send-a": "send", "bg-flush-a": "flush_done"}.get(step)
    if step == "bg-offline-send-a":
        def offline():
            records = read_actor(adb, pid, token)
            done = (any(r["event"] == "enqueue" for r in records)
                    and any(r["event"] == "offline_failed" for r in records))
            return records if done else None
        return offline
    return lambda: (lambda records: records if any(r["event"] == wanted for r in records) else None)(
        read_actor(adb, pid, token))


def capture_case(adb, user, apk_sha, case, token, folder, bundle, network):
    folder.mkdir()
    for name in ("reads.jsonl", "flows.jsonl", "egress.jsonl"):
        (folder / name).touch()
    command(adb, "shell", "am", "force-stop", "--user", user, PACKAGE)
    command(adb, "shell", "am", "start", "-W", "--user", user, "-n", ACTIVITY, "--es", "benchmark_run", token)
    trigger(adb, user, "bg-queue-clear", token)
    pid = command(adb, "shell", "pidof", PACKAGE)
    check(pid.isdecimal(), "夹具主进程未就绪")
    offline_window = {}
    try:
        with ExitStack() as stack:
            server = start_receiver(stack, folder, token)
            stop_proxy = folder / ".proxy-stop"
            env = os.environ.copy()
            env.update(PYTHONUTF8="1", VSCAN_SESSION=token, VSCAN_SERIAL=adb.serial,
                       VSCAN_PACKAGES=PACKAGE, VSCAN_STRICT_PACKAGE_SCOPE="0",
                       VSCAN_ATTRIB_TARGET_CHECK="1", VSCAN_ATTRIB_CONSERVATIVE="1",
                       VSCAN_FLOW_LOG=str(folder / "flows.jsonl"), VSCAN_ATTRIB_SOURCES=str(folder / "reads.jsonl"),
                       VSCAN_STOP_FILE=str(stop_proxy), VSCAN_EVENT_DB=str(folder / "flows.sqlite"))
            proxy = start_process(stack, [sys.executable, "-u", "-c",
                "from mitmproxy.tools.main import mitmdump; mitmdump()", "-s", str(ROOT / "mobile/traffic/addon_mobile.py"),
                "--mode", f"reverse:http://127.0.0.1:{server.server_port}", "--listen-host", "127.0.0.1",
                "--listen-port", str(PROXY_PORT), "--set", "keep_host_header=true", "--set", f"confdir={folder / 'certs'}"],
                folder / "proxy.log", env, stop_proxy)
            check(wait_listener(PROXY_PORT, proxy), "本机反向代理未就绪")
            command(adb, "reverse", "--no-rebind", DEVICE_HTTP, f"tcp:{PROXY_PORT}")
            stack.callback(best_effort, "reverse", lambda: command(adb, "reverse", "--remove", DEVICE_HTTP))
            plan = folder / "hook-plan.json"
            save(plan, [{"script": str(bundle), "output": "reads.jsonl"}])
            stop_hook = folder / ".hook-stop"
            hook = start_process(stack, [sys.executable, "-u", str(ROOT / "mobile/tools/device_hook_driver.py"),
                "--plan", str(plan), "--session-dir", str(folder), "--session", token,
                "--port", str(GADGET_PORT), "--seconds", "240", "--stop-file", str(stop_hook)],
                folder / "driver.log", env, stop_hook)
            children = (proxy, hook)
            sample_until(lambda: any(r.get("src") == "privacy" and r.get("ev") == "ARMED"
                         and r.get("hook") == OBSERVATION and r.get("hooks") == 1
                         for r in rows(folder / "reads.jsonl")), children, "privacy ARMED")
            steps, read_count = [], 0
            for step in OFFLINE_STEPS[case]:
                started = millis()
                if step == "net_off":
                    network.apply("net_off", token + "-off")
                    offline_window["offline_start_ms"] = millis()
                elif step == "net_on":
                    network.apply("net_on", token + "-on")
                else:
                    trigger(adb, user, step, token)
                    read_count += int(step.startswith(("bg-read", "read-")))
                    sample_until(step_predicate(adb, pid, token, folder, step, read_count), children, step)
                    if step == "bg-probe-after":
                        offline_window["online_confirmed_ms"] = millis()
                steps.append({"step": step, "start_ms": started, "end_ms": millis()})
            time.sleep(1)
            save(folder / "steps.json", steps)
            save(folder / "actor.json", read_actor(adb, pid, token))
            check(command(adb, "shell", "pidof", PACKAGE) == pid, "采集中夹具 PID 变化")
    except Exception:
        try:
            crash = adb("shell", "logcat", "-d", "-b", "crash", "--pid", pid, timeout=10)
            (folder / "device-crash.log").write_text(crash.stdout + crash.stderr, encoding="utf-8")
        except (OSError, subprocess.SubprocessError) as error:
            print(f"device_crash_log_failed: {error}", file=sys.stderr)
        raise
    finally:
        save(folder / "receipts.json", server.receipts if "server" in locals() else [])
        if offline_window:
            save(folder / "offline-window.json", offline_window)
    check(command(adb, "shell", "pidof", PACKAGE) == pid, "夹具进程结束态不一致")
    manifest = {"session_id": token, "apk_sha256": apk_sha, "hook_sha256": sha(bundle.read_bytes()), "passed": True}
    driver = load(folder / "hook-driver-verification.json")
    check(str(driver.get("pid")) == pid, "Hook 未附加到实际夹具 PID")
    if case != "bg_read_only":
        shutil.copyfile(folder / "body-0.bin", folder / "body.bin")
    from mobile.lab.offline_control import truth_offline
    truth_offline(folder, case, manifest)
    manifest["sha256"] = {name: sha((folder / name).read_bytes()) for name in sorted(case_inputs(case))}
    save(folder / "manifest.json", manifest)


def obtained(events):
    return [r for r in events if r.get("outcome") == "ok" and r.get("data_types") and "android_id" in r["data_types"]]


def capture(serial, apk, out):
    adb = AdbClient(resolve_adb(), serial)
    check(re.fullmatch(r"emulator-\d+", adb.select_device()) and command(adb, "shell", "getprop", "ro.kernel.qemu") == "1",
          "仅允许自有手机模拟器")
    api = command(adb, "shell", "getprop", "ro.build.version.sdk")
    user = command(adb, "shell", "am", "get-current-user")
    profile = collect_device_profile(adb, "gadget")
    check(profile["nonroot_shell_observed"] and "automotive" not in command(adb, "shell", "getprop", "ro.build.characteristics"),
          "需要非 root 手机模拟器")
    artifact = inspect_gadget(apk, profile, GADGET_PORT, host_frida_version())
    check(f"package:{PACKAGE}" not in command(adb, "shell", "pm", "list", "packages", "--user", user, PACKAGE).splitlines(),
          "设备已有同包应用")
    ensure_port_free(PROXY_PORT)
    out.mkdir(parents=True, exist_ok=False)
    save(out / "device.json", {**profile, "api": api, "user": user, "artifact": artifact})
    apk_sha = sha(apk.read_bytes())
    shutil.copyfile(ROOT / "mobile/rules/rules_mobile.db", out / "rules.db")
    built = ROOT / "mobile/hooks/dist/hook_window_benchmark.bundle.js"
    check(built.is_file(), "先构建 hook_window_benchmark")
    shutil.copyfile(built, out / "hook.bundle.js")
    check("Success" in command(adb, "install", "--user", user, apk), "自有 APK 安装失败")
    network = MobileNetworkActions(adb, out)
    try:
        path = command(adb, "shell", "pm", "path", "--user", user, PACKAGE)
        check(path.startswith("package:/") and "\n" not in path, "装机 APK 路径不明确")
        installed = command(adb, "shell", "sha256sum", path.removeprefix("package:"))
        check(installed.split()[0] == apk_sha, "装机 APK 摘要不一致")
        command(adb, "forward", "--no-rebind", f"tcp:{GADGET_PORT}", f"tcp:{GADGET_PORT}")
        cases = {case: uuid.uuid4().hex for case in OFFLINE_STEPS}
        for case, token in cases.items():
            print(f"采集 {case}…", flush=True)
            capture_case(adb, user, apk_sha, case, token, out / case, built, network)
    finally:
        best_effort("forward", lambda: command(adb, "forward", "--remove", f"tcp:{GADGET_PORT}"))
        best_effort("network", network.close)
        best_effort("uninstall", lambda: command(adb, "shell", "pm", "uninstall", "--user", user, PACKAGE))
    save(out / "suite.json", {"package": PACKAGE, "device_api": api, "apk_sha256": apk_sha,
                             "rules_sha256": sha((out / "rules.db").read_bytes()),
                             "hook_sha256": sha(built.read_bytes()), "cases": cases})


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--serial", required=True)
    parser.add_argument("--apk", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        capture(args.serial, args.apk.resolve(), args.out.resolve())
    except (OSError, ValueError, KeyError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"offline_control_capture_failed: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
