"""Capture the background/offline/resend controls on an owned mobile emulator. 仅用于授权测试。"""
from __future__ import annotations

import argparse
from contextlib import ExitStack, contextmanager
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import threading
import time
import uuid

from mobile.lab.mobile_network_actions import MobileNetworkActions
from mobile.lab.offline_control import OFFLINE_INPUTS, PACKAGE, OBSERVATION
from mobile.lab.window_benchmark import OFFLINE_STEPS, ROOT, check, load, rows, save, sha

sys.path.insert(0, str(ROOT / "mobile/tools"))
from device_capture import pick_free_port, wait_listener  # noqa: E402
from device_environment import AdbClient, collect_device_profile, resolve_adb  # noqa: E402
from device_provenance import host_frida_version, inspect_gadget  # noqa: E402

ACTIVITY = PACKAGE + "/.WindowBenchmarkActivity"
GADGET_PORT = 27044
DEVICE_HTTP = "tcp:18960"


def millis():
    return time.time_ns() // 1_000_000


class Receiver(BaseHTTPRequestHandler):
    def do_POST(self):
        now = millis()
        size = self.headers.get("Content-Length", "")
        if self.path != "/collect" or not size.isascii() or not size.isdecimal() or not 0 < int(size) <= 2048:
            self.send_error(400)
            return
        self.connection.settimeout(5)
        body = self.rfile.read(int(size))
        if len(body) != int(size):
            self.send_error(400)
            return
        try:
            value = json.loads(body)
            valid = (value["run"] == self.server.token and value["source_batch"] == "a"
                     and re.fullmatch(r"[0-9a-fA-F]{16}", value["android_id"])
                     and value.get("origin") in ("foreground", "background"))
        except (ValueError, KeyError, TypeError):
            valid = False
        if not valid:
            self.send_error(400)
            return
        index = len(self.server.receipts)
        (self.server.folder / f"body-{index}.bin").open("xb").write(body)
        checksum = sha(body)
        self.server.receipts.append({"status": 200, "path": self.path, "sha256": checksum,
                                     "received_ms": now, "source_batch_tokens": value.get("source_batch_tokens", []),
                                     "body_file": f"body-{index}.bin"})
        reply = json.dumps({"sha256": checksum}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(reply)))
        self.end_headers()
        self.wfile.write(reply)


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


def read_actor(adb, pid, token):
    output = command(adb, "shell", "logcat", "-d", "--pid", pid, "-v", "raw", "-s", "VScanWindow:I")
    records = [json.loads(line) for line in output.splitlines() if line.startswith("{")]
    records = [row for row in records if row.get("run") == token]
    check(not any(row.get("event") == "error" for row in records), "夹具动作报告失败")
    return records


def trigger(adb, user, step, token):
    command(adb, "shell", "am", "start", "-W", "--user", user, "-n", ACTIVITY,
            "--es", "benchmark_run", token, "--es", "benchmark_step", step)


def capture_case(adb, user, apk_sha, case, token, folder, bundle, network):
    folder.mkdir()
    for name in ("reads.jsonl", "flows.jsonl", "egress.jsonl"):
        (folder / name).touch()
    command(adb, "shell", "am", "force-stop", "--user", user, PACKAGE)
    command(adb, "shell", "am", "start", "-W", "--user", user, "-n", ACTIVITY,
            "--es", "benchmark_run", token)
    trigger(adb, user, "bg-queue-clear", token)
    pid = command(adb, "shell", "pidof", PACKAGE)
    check(pid.isdecimal(), "夹具主进程未就绪")
    offline_window = {}
    try:
        with ExitStack() as stack:
            server = HTTPServer(("127.0.0.1", 0), Receiver)
            server.folder, server.token, server.receipts = folder, token, []
            stack.callback(server.server_close)
            thread = threading.Thread(target=server.serve_forever)
            thread.start()
            stack.callback(thread.join)
            stack.callback(server.shutdown)
            proxy_port, stop_proxy = pick_free_port(), folder / ".proxy-stop"
            env = __import__("os").environ.copy()
            env.update(PYTHONUTF8="1", VSCAN_SESSION=token, VSCAN_SERIAL=adb.serial,
                       VSCAN_PACKAGES=PACKAGE, VSCAN_STRICT_PACKAGE_SCOPE="0",
                       VSCAN_ATTRIB_TARGET_CHECK="1", VSCAN_ATTRIB_CONSERVATIVE="1",
                       VSCAN_FLOW_LOG=str(folder / "flows.jsonl"), VSCAN_ATTRIB_SOURCES=str(folder / "reads.jsonl"),
                       VSCAN_STOP_FILE=str(stop_proxy), VSCAN_EVENT_DB=str(folder / "flows.sqlite"))
            proxy = start_process(stack, [sys.executable, "-u", "-c",
                "from mitmproxy.tools.main import mitmdump; mitmdump()", "-s", str(ROOT / "mobile/traffic/addon_mobile.py"),
                "--mode", f"reverse:http://127.0.0.1:{server.server_port}", "--listen-host", "127.0.0.1",
                "--listen-port", str(proxy_port), "--set", "keep_host_header=true", "--set", f"confdir={folder / 'certs'}"],
                folder / "proxy.log", env, stop_proxy)
            check(wait_listener(proxy_port, proxy), "本机反向代理未就绪")
            command(adb, "reverse", "--no-rebind", DEVICE_HTTP, f"tcp:{proxy_port}")
            stack.callback(command, adb, "reverse", "--remove", DEVICE_HTTP)
            plan = folder / "hook-plan.json"
            save(plan, [{"script": str(bundle), "output": "reads.jsonl"}])
            stop_hook = folder / ".hook-stop"
            hook = start_process(stack, [sys.executable, "-u", str(ROOT / "mobile/tools/device_hook_driver.py"),
                "--plan", str(plan), "--session-dir", str(folder), "--session", token,
                "--port", str(GADGET_PORT), "--seconds", "180", "--stop-file", str(stop_hook)],
                folder / "driver.log", env, stop_hook)
            children = (proxy, hook)
            sample_until(lambda: any(r.get("src") == "privacy" and r.get("ev") == "ARMED"
                         and r.get("hook") == OBSERVATION and r.get("hooks") == 1
                         for r in rows(folder / "reads.jsonl")), children, "privacy ARMED")
            steps = []
            read_count = 0
            for step in OFFLINE_STEPS[case]:
                started = millis()
                if step == "wifi_off":
                    offline_window["offline_start_ms"] = millis()
                    network.apply("wifi_off", token + "-off")
                    time.sleep(1)
                elif step == "wifi_on":
                    network.apply("wifi_on", token + "-on")
                    offline_window["online_confirmed_ms"] = millis()
                    time.sleep(1)
                else:
                    trigger(adb, user, step, token)
                    read_count += int(step.startswith(("bg-read", "read-")))
                    def delivered():
                        records = read_actor(adb, pid, token)
                        enough = len(obtained(rows(folder / "reads.jsonl"))) >= read_count
                        if not enough:
                            return None
                        # 断网发送是后台线程 + 5s 连接超时，必须等 offline_failed
                        # 落盘再往下走，否则 wi-fi 切换会跑在失败确认之前。
                        if step == "bg-offline-send-a":
                            return records if any(r.get("event") == "offline_failed" for r in records) else None
                        return records if len(records) >= len(steps) + 1 else None
                    sample_until(delivered, children, step, seconds=25)
                steps.append({"step": step, "start_ms": started, "end_ms": millis()})
                if step == "bg-flush-a":
                    sample_until(lambda: any(r.get("event") == "flush_done" for r in read_actor(adb, pid, token)),
                                 children, "补传完成")
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
    from mobile.lab.offline_control import truth_offline
    truth_offline(folder, case, manifest)
    paths = [n for n in OFFLINE_INPUTS if (folder / n).is_file()]
    if case != "bg_read_only":
        paths.append("body.bin")
        shutil.copyfile(folder / "body-0.bin", folder / "body.bin")
    manifest["sha256"] = {name: sha((folder / name).read_bytes()) for name in paths}
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
        command(adb, "forward", "--no-rebind", f"tcp:{GADGET_PORT}", f"tcp:{GADGET_PORT}")
        cases = {case: uuid.uuid4().hex for case in OFFLINE_STEPS}
        for case, token in cases.items():
            print(f"采集 {case}…", flush=True)
            capture_case(adb, user, apk_sha, case, token, out / case, built, network)
    finally:
        command(adb, "forward", "--remove", f"tcp:{GADGET_PORT}")
        network.close()  # 内部已写 environment-cleanup.json（含 cleanup_ok）
        command(adb, "shell", "pm", "uninstall", "--user", user, PACKAGE)
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
