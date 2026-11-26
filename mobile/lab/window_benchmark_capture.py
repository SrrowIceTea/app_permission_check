"""Capture four controls on a dedicated, owned mobile emulator. 仅用于授权测试。"""
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

from core.privacy.semantics import obtained_reads
from mobile.lab.window_benchmark import INPUTS, OBSERVATION, PACKAGE, ROOT, STEPS, check, load, rows, save, sha, truth

sys.path.insert(0, str(ROOT / "mobile/tools"))
from device_capture import pick_free_port, wait_listener  # noqa: E402
from device_environment import AdbClient, collect_device_profile, resolve_adb  # noqa: E402
from device_provenance import host_frida_version, inspect_gadget  # noqa: E402

ACTIVITY = PACKAGE + "/.WindowBenchmarkActivity"
GADGET_PORT = 27044
DEVICE_HTTP = "tcp:18960"


class Receiver(BaseHTTPRequestHandler):
    def do_POST(self):
        now = millis()
        size = self.headers.get("Content-Length", "")
        if self.path != "/collect" or not size.isascii() or not size.isdecimal() or not 0 < int(size) <= 1024:
            self.send_error(400)
            return
        self.connection.settimeout(5)
        body = self.rfile.read(int(size))
        if len(body) != int(size) or self.server.receipts:
            self.send_error(409)
            return
        try:
            value = json.loads(body)
            valid = (value["run"] == self.server.token and value["source_batch"] == "a"
                     and re.fullmatch(r"[0-9a-fA-F]{16}", value["android_id"]))
        except (ValueError, KeyError, TypeError):
            valid = False
        if not valid:
            self.send_error(400)
            return
        with (self.server.folder / "body.bin").open("xb") as handle:
            handle.write(body)
        checksum = sha(body)
        self.server.receipts.append({"status": 200, "path": self.path, "sha256": checksum, "received_ms": now})
        reply = json.dumps({"sha256": checksum}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(reply)))
        self.end_headers()
        self.wfile.write(reply)


def millis():
    return time.time_ns() // 1_000_000


def command(adb, *args):
    result = adb(*map(str, args), timeout=35)
    check(result.returncode == 0, f"ADB {args[:3]}: {result.stderr.strip()}")
    return result.stdout.strip()


@contextmanager
def cleanup(action, *args):
    try:
        yield
    except BaseException:
        try:
            action(*args)
        except Exception as error:
            print(f"mobile_window_cleanup_failed: {error}", file=sys.stderr)
        raise
    else:
        action(*args)


def uninstall_fixture(adb, user):
    check("Success" in command(adb, "shell", "pm", "uninstall", "--user", user, PACKAGE), "夹具卸载失败")


def sample_until(predicate, processes, description, seconds=25):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        check(all(child.poll() is None for child in processes), f"采集子进程提前退出，查看日志：{description}")
        result = predicate()
        if result:
            return result
        time.sleep(.25)
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

    stack.enter_context(cleanup(close))
    return process


def activity(adb, user, *extras):
    output = command(adb, "shell", "am", "start", "-W", "--user", user, "-n", ACTIVITY, *extras)
    check("Error" not in output, "夹具 Activity 启动失败")


def read_actor(adb, pid, token):
    output = command(adb, "shell", "logcat", "-d", "--pid", pid, "-v", "raw", "-s", "VScanWindow:I")
    records = [json.loads(line) for line in output.splitlines() if line.startswith("{")]
    records = [row for row in records if row.get("run") == token]
    check(not any(row.get("event") == "error" for row in records), "夹具动作报告失败")
    return records


def execute_steps(adb, user, case, token, pid, folder, children):
    read_count = 0
    actions = []
    for index, step in enumerate(STEPS[case], 1):
        if index == 2 and case in ("delayed", "cross_batch"):
            time.sleep(36)
        started = millis()
        activity(adb, user, "--es", "benchmark_run", token, "--es", "benchmark_step", step)
        read_count += int(step.startswith("read-"))

        def delivered():
            records = read_actor(adb, pid, token)
            enough_reads = len(obtained_reads(rows(folder / "reads.jsonl"), "android_id")) >= read_count
            return records if len(records) == index and enough_reads else None

        actor = sample_until(delivered, children, step)
        actions.append({"step": step, "start_ms": started, "end_ms": millis()})
    if case != "read_only":
        sample_until(lambda: rows(folder / "flows.jsonl"), children, "HTTP flow")
    else:
        time.sleep(1)
    save(folder / "steps.json", actions)
    save(folder / "actor.json", actor)


def capture_case(adb, user, apk_sha, case, token, folder, bundle):
    folder.mkdir()
    for name in ("reads.jsonl", "flows.jsonl", "egress.jsonl"):
        (folder / name).touch()
    command(adb, "shell", "am", "force-stop", "--user", user, PACKAGE)
    activity(adb, user)
    pid = command(adb, "shell", "pidof", PACKAGE)
    check(pid.isdecimal(), "夹具主进程未就绪")
    try:
        with ExitStack() as stack:
            server = stack.enter_context(HTTPServer(("127.0.0.1", 0), Receiver))
            server.folder, server.token, server.receipts = folder, token, []
            thread = threading.Thread(target=server.serve_forever)
            thread.start()
            stack.callback(thread.join)
            stack.callback(server.shutdown)
            proxy_port, stop_proxy = pick_free_port(), folder / ".proxy-stop"
            env = adb.environment()
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
            stack.enter_context(cleanup(command, adb, "reverse", "--remove", DEVICE_HTTP))
            plan = folder / "hook-plan.json"
            save(plan, [{"script": str(bundle), "output": "reads.jsonl"}])
            stop_hook = folder / ".hook-stop"
            hook = start_process(stack, [sys.executable, "-u", str(ROOT / "mobile/tools/device_hook_driver.py"),
                "--plan", str(plan), "--session-dir", str(folder), "--session", token,
                "--port", str(GADGET_PORT), "--seconds", "130", "--stop-file", str(stop_hook)],
                folder / "driver.log", env, stop_hook)
            children = (proxy, hook)
            sample_until(lambda: any(row.get("src") == "privacy" and row.get("ev") == "ARMED"
                         and row.get("hook") == OBSERVATION and row.get("hooks") == 1
                         for row in rows(folder / "reads.jsonl")), children, "privacy ARMED")
            execute_steps(adb, user, case, token, pid, folder, children)
            check(command(adb, "shell", "pidof", PACKAGE) == pid, "采集中夹具 PID 发生变化")
    except Exception:
        try:
            crash = adb("shell", "logcat", "-d", "-b", "crash", "--pid", pid, timeout=10)
            (folder / "device-crash.log").write_text(crash.stdout + crash.stderr, encoding="utf-8")
        except (OSError, subprocess.SubprocessError) as error:
            print(f"mobile_window_crash_log_failed: {error}", file=sys.stderr)
        raise
    finally:
        if "server" in locals():
            save(folder / "receipts.json", server.receipts)
    check(not any(DEVICE_HTTP in line.split() for line in command(adb, "reverse", "--list").splitlines()),
          "夹具回环转发未释放")
    manifest = {"session_id": token, "apk_sha256": apk_sha, "hook_sha256": sha(bundle.read_bytes()), "passed": True}
    driver = load(folder / "hook-driver-verification.json")
    check(str(driver.get("pid")) == pid, "Hook 未附加到本轮实际夹具 PID")
    truth(folder, case, manifest)
    paths = (*INPUTS, "body.bin") if case != "read_only" else INPUTS
    manifest["sha256"] = {name: sha((folder / name).read_bytes()) for name in paths}
    save(folder / "manifest.json", manifest)


def capture(serial, apk, out):
    adb = AdbClient(resolve_adb(), serial)
    check(re.fullmatch(r"emulator-\d+", adb.select_device()) and command(adb, "shell", "getprop", "ro.kernel.qemu") == "1",
          "仅允许明确选择的自有手机模拟器")
    api = command(adb, "shell", "getprop", "ro.build.version.sdk")
    user = command(adb, "shell", "am", "get-current-user")
    profile = collect_device_profile(adb, "gadget")
    check(profile["nonroot_shell_observed"] and "automotive" not in command(adb, "shell", "getprop", "ro.build.characteristics"),
          "需要非 root 手机模拟器")
    artifact = inspect_gadget(apk, profile, GADGET_PORT, host_frida_version())
    packages = command(adb, "shell", "pm", "list", "packages", "--user", user, PACKAGE)
    check(f"package:{PACKAGE}" not in packages.splitlines(), "设备已有同包应用，保留其安装与数据")
    out.mkdir(parents=True, exist_ok=False)
    save(out / "device.json", {**profile, "api": api, "user": user, "artifact": artifact})
    apk_sha = sha(apk.read_bytes())
    rules = out / "rules.db"
    shutil.copyfile(ROOT / "mobile/rules/rules_mobile.db", rules)
    built = ROOT / "mobile/hooks/dist/hook_window_benchmark.bundle.js"
    check(built.is_file(), "先构建 hook_window_benchmark")
    bundle = out / "hook.bundle.js"
    shutil.copyfile(built, bundle)
    check("Success" in command(adb, "install", "--user", user, apk), "自有 APK 安装失败")
    with cleanup(uninstall_fixture, adb, user):
        path = command(adb, "shell", "pm", "path", "--user", user, PACKAGE)
        check(path.startswith("package:/") and "\n" not in path, "装机 APK 路径不明确")
        installed = command(adb, "shell", "sha256sum", path.removeprefix("package:"))
        check(installed.split()[0] == apk_sha, "装机 APK 摘要不一致")
        endpoint = f"tcp:{GADGET_PORT}"
        command(adb, "forward", "--no-rebind", endpoint, endpoint)
        with cleanup(command, adb, "forward", "--remove", endpoint):
            cases = {case: uuid.uuid4().hex for case in STEPS}
            for case, token in cases.items():
                print(f"采集 {case}…", flush=True)
                capture_case(adb, user, apk_sha, case, token, out / case, bundle)
    save(out / "suite.json", {"package": PACKAGE, "device_api": api, "apk_sha256": apk_sha,
                             "rules_sha256": sha(rules.read_bytes()), "hook_sha256": sha(bundle.read_bytes()),
                             "cases": cases})


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--serial", required=True)
    parser.add_argument("--apk", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        capture(args.serial, args.apk.resolve(), args.out.resolve())
    except (OSError, ValueError, KeyError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"mobile_window_capture_failed: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
