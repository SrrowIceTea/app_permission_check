"""自有移动模拟器采集的公共管道：adb 包装、子进程生命周期、动作读取。仅用于授权测试。

这里只放两套采集脚本真正共用的部分（窗口基准与后台/断网对照）。两者的接收端语义
不同（前者只收一条、后者按批次多条），因此 Receiver 各自保留，不进本模块。

sys.path 的注入也只在这里做一次：`mobile/tools` 下的 device_* 是脚本级模块，
重复插入会遮蔽同名模块，也会让"哪份实现生效"变得不可推理。
"""
from __future__ import annotations

from contextlib import contextmanager
import json
import re
import subprocess
import sys
import time

from mobile.lab.window_benchmark import PACKAGE, ROOT, check, save

sys.path.insert(0, str(ROOT / "mobile/tools"))
from device_capture import pick_free_port, wait_listener  # noqa: E402,F401
from device_environment import AdbClient, collect_device_profile, resolve_adb  # noqa: E402,F401
from device_provenance import host_frida_version, inspect_gadget  # noqa: E402,F401

ACTIVITY = PACKAGE + "/.WindowBenchmarkActivity"
GADGET_PORT = 27044
DEVICE_HTTP = "tcp:18960"


def millis():
    return time.time_ns() // 1_000_000


def command(adb, *args):
    result = adb(*map(str, args), timeout=35)
    check(result.returncode == 0, f"ADB {args[:3]}: {result.stderr.strip()}")
    return result.stdout.strip()


@contextmanager
def cleanup(action, *args):
    """成功或失败都执行一次清理；清理异常不掩盖原始异常。"""
    try:
        yield
    except BaseException:
        try:
            action(*args)
        except Exception as error:
            print(f"mobile_capture_cleanup_failed: {error}", file=sys.stderr)
        raise
    else:
        action(*args)


def best_effort(label, action):
    """多个清理动作串行时互不阻断，并保留各自的失败信息。"""
    try:
        return action()
    except Exception as error:  # noqa: BLE001
        print(f"mobile_capture_cleanup_failed[{label}]: {error}", file=sys.stderr)
        return None


def sample_until(predicate, processes, description, seconds=25):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        check(all(child.poll() is None for child in processes), f"采集子进程提前退出：{description}")
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


def start_activity(adb, user, run=None, step=None):
    extras = [] if run is None else ["--es", "benchmark_run", run]
    if step is not None:
        extras += ["--es", "benchmark_step", step]
    output = command(adb, "shell", "am", "start", "-W", "--user", user, "-n", ACTIVITY, *extras)
    # am start 可能在退出码 0 的情况下打印 Error，必须看输出。
    check("Error" not in output, f"夹具 Activity 启动失败: {(step or 'launch')}")


def read_actor(adb, pid, token):
    output = command(adb, "shell", "logcat", "-d", "--pid", pid, "-v", "raw", "-s", "VScanWindow:I")
    records = [json.loads(line) for line in output.splitlines() if line.startswith("{")]
    records = [row for row in records if row.get("run") == token]
    check(not any(row.get("event") == "error" for row in records), "夹具动作报告失败")
    return records


def capture_env(adb, folder, token):
    """采集子进程的统一环境：带 VSCAN_ADB/ANDROID_SERIAL，避免丢掉工具链定位。"""
    env = adb.environment()
    env.update(PYTHONUTF8="1", VSCAN_SESSION=token, VSCAN_SERIAL=adb.serial,
               VSCAN_PACKAGES=PACKAGE, VSCAN_STRICT_PACKAGE_SCOPE="0",
               VSCAN_ATTRIB_TARGET_CHECK="1", VSCAN_ATTRIB_CONSERVATIVE="1",
               VSCAN_FLOW_LOG=str(folder / "flows.jsonl"),
               VSCAN_ATTRIB_SOURCES=str(folder / "reads.jsonl"),
               VSCAN_STOP_FILE=str(folder / ".proxy-stop"),
               VSCAN_EVENT_DB=str(folder / "flows.sqlite"))
    return env


def prepare_device(adb):
    """只允许明确选择的自有手机模拟器；返回 (api, user, profile)。"""
    check(re.fullmatch(r"emulator-\d+", adb.select_device()) and command(adb, "shell", "getprop", "ro.kernel.qemu") == "1",
          "仅允许明确选择的自有手机模拟器")
    api = command(adb, "shell", "getprop", "ro.build.version.sdk")
    user = command(adb, "shell", "am", "get-current-user")
    profile = collect_device_profile(adb, "gadget")
    check(profile["nonroot_shell_observed"]
          and "automotive" not in command(adb, "shell", "getprop", "ro.build.characteristics"),
          "需要非 root 手机模拟器")
    return api, user, profile


def assert_device_apk(adb, user, apk_sha):
    """设备上真正装着的 APK 必须与本地文件同摘要，否则整轮归因无锚点。"""
    path = command(adb, "shell", "pm", "path", "--user", user, PACKAGE)
    check(path.startswith("package:/") and "\n" not in path, "装机 APK 路径不明确")
    installed = command(adb, "shell", "sha256sum", path.removeprefix("package:"))
    check(installed.split()[0] == apk_sha, "装机 APK 摘要不一致")


def write_hook_plan(folder, bundle):
    plan = folder / "hook-plan.json"
    save(plan, [{"script": str(bundle), "output": "reads.jsonl"}])
    return plan
