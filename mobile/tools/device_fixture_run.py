#!/usr/bin/env python3
"""Self-owned mobile fixture E2E: Gadget non-root by default, explicit root compatibility.

仅用于授权测试（自有源码夹具与已授权设备）。失败保留原始事件、日志和 verification.json。
Gadget 不使用 adb root/su/frida-server，不装系统 CA；不支持任意第三方 APK 注入。
Example: python mobile/tools/device_fixture_run.py --mode gadget --serial emulator-5554 --skip-ai
"""
from __future__ import annotations

import argparse
import os
import time
from pathlib import Path

from device_actions import CaptureCancelled, check_cancel, trigger_sequence
from device_capture import HOOKS, hook_readiness, start_hooks, start_services, stop_capture, wait_hooks, traffic_checks
from device_environment import AdbClient, PKG, ROOT, collect_device_profile, ensure_transport
from device_environment import resolve_adb, wait_boot, wait_for_app
from device_finalize import finish, generate_artifacts, permission_snapshot, write_json
from device_provenance import capabilities, default_apk, host_frida_version, inspect_gadget


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("gadget", "root"), default="gadget")
    parser.add_argument("--serial", default=os.environ.get("ANDROID_SERIAL"),
                        help="明确选择设备；省略仅在恰好一个在线设备时允许")
    parser.add_argument("--adb", help="覆盖 ADB 路径；否则 SDK/PATH/当前用户发现")
    parser.add_argument("--apk", type=Path, help="自有夹具 APK；Gadget 字节/授权 provenance 必须通过")
    parser.add_argument("--gadget-port", type=int, default=27044)
    parser.add_argument("--root-port", type=int, default=27043)
    parser.add_argument("--user", type=int)
    parser.add_argument("--seconds", type=int, default=600, help="采集最长时限，UI 结束后提前正常停止")
    parser.add_argument("--skip-ai", action="store_true", help="不调用外部模型")
    parser.add_argument("--app-category", default="map_navigation")
    parser.add_argument("--permission-response", choices=("allow", "deny"), default="allow",
                        help="仅自有夹具权限弹窗的自动操作；不等同隐私政策接受")
    parser.add_argument("--preflight-only", action="store_true", help="只读设备/校验 APK，不安装或采集")
    args = parser.parse_args(argv)
    for port in (args.gadget_port, args.root_port):
        if not 1 <= port <= 65535:
            parser.error("端口必须在 1..65535")
    if args.seconds <= 0:
        parser.error("--seconds 必须正数")
    return args


def execute(args, out: Path, checks: list, metadata: dict):
    session = out / "session"
    processes, hooks = [], []
    adb, transport_owned, capture_started = None, False, False
    apk = args.apk or default_apk(args.mode)
    port = args.gadget_port if args.mode == "gadget" else args.root_port

    def require(name, ok, note=None):
        checks.append({"name": name, "exit_code": 0 if ok else 1, "note": note})
        if not ok:
            raise RuntimeError(name + (": " + note if note else ""))

    try:
        check_cancel(args)
        require("apk_present", apk.is_file(), str(apk))
        adb = AdbClient(resolve_adb(args.adb), args.serial)
        metadata["serial"] = adb.select_device()
        metadata["adb"] = adb.executable
        check_cancel(args)
        require("device_booted", wait_boot(adb))
        check_cancel(args)
        profile = collect_device_profile(adb, args.mode)
        metadata["device_profile"] = profile
        write_json(out / "device-profile.json", profile)
        require("device_identity", profile["identity_exit_code"] == 0 and profile["shell_uid"] is not None)
        if args.mode == "gadget":
            require("nonroot_shell", profile["nonroot_shell_observed"], "不降级到 root 路径")
            provenance = inspect_gadget(apk, profile, port, host_frida_version())
            metadata["gadget"] = provenance
            write_json(out / "gadget-apk-verification.json", provenance)
            require("gadget_packaged_provenance", True)
        check_cancel(args)
        permission_snapshot(adb, out, "before-install")
        metadata["initial_permissions"] = "permissions-before-install.txt (observed, not reset)"
        if args.preflight_only:
            metadata["device_capture"] = "not_run (preflight only)"
            return
        for item in HOOKS:
            require(f"bundle_{item['name']}_present", item["script"].is_file(), str(item["script"]))
        check_cancel(args)
        existing = adb("forward", "--list").stdout
        pair = f"{adb.serial} tcp:{port} tcp:{port}"
        already_forwarded = any(line.strip() == pair for line in existing.splitlines())
        if already_forwarded and args.mode == "gadget":
            (out / "transport.log").write_text("reusing selected-device forward: " + pair, encoding="utf-8")
            require("transport", True)
        else:
            require("transport", ensure_transport(adb, args.mode, port, out / "transport.log"))
            transport_owned = not already_forwarded
        if args.mode == "root":
            metadata["device_profile_after_transport"] = collect_device_profile(adb, args.mode)
        proxy = adb("shell", "settings", "get", "global", "http_proxy")
        (out / "proxy-check.log").write_text(proxy.stdout + proxy.stderr, encoding="utf-8")
        require("proxy_clean", proxy.returncode == 0 and proxy.stdout.strip() in ("", "null", ":0"),
                "仅检查；已有全局代理不会被脚本改写")
        install_args = ["install", "-r"]  # No -g: pre-grant would contaminate permission timing.
        if args.user is not None:
            install_args += ["--user", str(args.user)]
        check_cancel(args)
        install = adb(*install_args, str(apk), timeout=300)
        (out / "install.log").write_text(install.stdout + install.stderr, encoding="utf-8")
        require("install", install.returncode == 0 and "Success" in install.stdout)
        check_cancel(args)
        permission_snapshot(adb, out, "initial")
        require("network_up", start_services(adb, session, out, 8888, processes),
                "夹具连接模拟器宿主 10.0.2.2:8888；未修改设备网络/系统 CA")
        check_cancel(args)
        adb("shell", "logcat", "-c")
        start = ["shell", "am", "start"]
        if args.user is not None:
            start += ["--user", str(args.user)]
        check_cancel(args)
        started = adb(*start, "-W", "-n", f"{PKG}/.MainActivity", timeout=120)
        (out / "app-start.log").write_text(started.stdout + started.stderr, encoding="utf-8")
        require("app_started", started.returncode == 0 and bool(wait_for_app(adb)))
        check_cancel(args)
        hooks = start_hooks(adb, args.mode, port, session, out, args.seconds)
        processes.extend(hooks)
        capture_started = True
        readiness = wait_hooks(session, args.mode, hooks)
        checks.extend(readiness)
        if any(item["exit_code"] for item in readiness):
            raise RuntimeError("Hook 未通过 ARMED/应用身份硬门控，未触发 UI")
        check_cancel(args)
        trigger_sequence(adb, args, out, hooks, checks)
    except CaptureCancelled as exc:
        metadata["cancelled"] = True
        checks.append({"name": "capture_cancelled", "exit_code": 1, "note": str(exc)})
    except Exception as exc:
        checks.append({"name": "pipeline_exception", "exit_code": 1,
                       "note": f"{type(exc).__name__}: {exc}"})
        metadata["failure"] = f"{type(exc).__name__}: {exc}"
    finally:
        try:
            checks.extend(stop_capture(processes, hooks, session, args.mode))
        except Exception as exc:
            checks.append({"name": "capture_cleanup_exception", "exit_code": 1, "note": str(exc)})
        if capture_started:
            try:
                checks.extend({**item, "name": item["name"] + "_after_capture"}
                              for item in hook_readiness(session, args.mode))
                checks.extend(traffic_checks(session))
            except Exception as exc:
                checks.append({"name": "capture_validation_exception", "exit_code": 1,
                               "note": f"{type(exc).__name__}: {exc}"})
        if adb and transport_owned:
            try:
                removed = adb("forward", "--remove", f"tcp:{port}")
                checks.append({"name": "forward_cleanup", "exit_code": removed.returncode,
                               "note": "仅移除此轮新建 forward"})
            except Exception as exc:
                checks.append({"name": "forward_cleanup_exception", "exit_code": 1, "note": str(exc)})
    if capture_started and not metadata.get("cancelled"):
        try:
            check_cancel(args)
            generate_artifacts(adb, args, apk, out, checks, metadata["device_profile"])
        except CaptureCancelled as exc:
            metadata["cancelled"] = True
            checks.append({"name": "capture_cancelled", "exit_code": 1, "note": str(exc)})
        except Exception as exc:
            checks.append({"name": "artifact_exception", "exit_code": 1,
                           "note": f"{type(exc).__name__}: {exc}"})


def main(argv=None) -> int:
    args = parse_args(argv)
    stamp = time.strftime("%Y%m%d-%H%M%S") + f"-{time.time_ns() % 1000000:06d}"
    out = ROOT / "output" / f"mobile-device-{args.mode}-{stamp}"
    (out / "session").mkdir(parents=True, exist_ok=False)
    checks = []
    metadata = {"mode": args.mode, "scope": "self-owned-source-fixture",
                "capabilities": capabilities(args.mode), "logical_session_id": out.name,
                "device_capture": "attempted", "ai_requested": not args.skip_ai}
    try:
        execute(args, out, checks, metadata)
    except Exception as exc:
        checks.append({"name": "unhandled_pipeline_exception", "exit_code": 1,
                       "note": f"{type(exc).__name__}: {exc}"})
    return finish(out, checks, metadata)


if __name__ == "__main__":
    raise SystemExit(main())
