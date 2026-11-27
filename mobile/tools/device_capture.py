"""Process capture and readiness gates; 仅用于授权测试（自有设备与自有 APK）。"""
from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

from device_environment import MOBILE, PKG, ROOT

PY = sys.executable
HOOKS = [
    {"name": "privacy", "script": MOBILE / "hooks/dist/hook_privacy.bundle.js",
     "output": "reads.jsonl", "ready": "ARMED"},
    {"name": "consent", "script": MOBILE / "hooks/dist/hook_consent.bundle.js",
     "output": "consent.jsonl", "ready": "ARMED"},
    {"name": "egress", "script": ROOT / "core/frida_host/dist/hook_egress.bundle.js",
     "output": "egress.jsonl", "ready": "ARMED"},
    {"name": "tls", "script": ROOT / "core/frida_host/dist/ssl_pinning_bypass.bundle.js",
     "output": "tls.jsonl", "ready": "PINNING_ARMED"},
]


def run(cmd: list[str], log: Path, timeout: int = 600, env: dict | None = None) -> int:
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8",
                                errors="replace", timeout=timeout, env=env)
        text, code = result.stdout + "\n--- stderr ---\n" + result.stderr, result.returncode
    except (OSError, subprocess.TimeoutExpired) as exc:
        text, code = f"{type(exc).__name__}: {exc}", 1
    log.write_text(f"$ {' '.join(cmd)}\n\n{text}", encoding="utf-8")
    return code


def launch(cmd: list[str], log: Path, env: dict):
    with log.open("w", encoding="utf-8") as handle:
        return subprocess.Popen(cmd, stdout=handle, stderr=subprocess.STDOUT, env=env,
                                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)


def pick_free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def wait_listener(port: int, process, timeout: int = 30) -> bool:
    end = time.monotonic() + timeout
    while time.monotonic() < end and process.poll() is None:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=.5):
                return True
        except OSError:
            time.sleep(.3)
    return False


def mitmdump_path() -> str:
    explicit = os.environ.get("VSCAN_MITMDUMP")
    candidates = [explicit] if explicit else [
        str(Path(PY).parent / ("mitmdump.exe" if os.name == "nt" else "mitmdump")),
        shutil.which("mitmdump"), shutil.which("mitmdump.exe")]
    for candidate in candidates:
        if candidate and Path(candidate).is_file():
            return str(candidate)
    raise FileNotFoundError("找不到 mitmdump；用当前 Python 环境安装 mitmproxy 或设 VSCAN_MITMDUMP")


def start_services(adb, session: Path, out: Path, port: int, processes: list):
    # A legacy listener could accept our readiness probe before the new proxy exits.
    # Fail explicitly instead of observing another run's server on the fixed fixture port.
    with socket.socket() as probe:
        try:
            probe.bind(("127.0.0.1", port))
        except OSError as exc:
            raise RuntimeError(f"夹具代理端口 {port} 已占用，未启动采集") from exc
    env = adb.environment()
    upstream = pick_free_port()
    collector = launch([PY, str(ROOT / "core/collector/collector_server.py"), "--port", str(upstream)],
                       out / "collector.log", env)
    processes.append(collector)
    if not wait_listener(upstream, collector):
        raise RuntimeError("collector 未成功监听（见 collector.log）")
    env.update({"VSCAN_FLOW_LOG": str(session / "flows.jsonl"),
                "VSCAN_UNANSWERED_LOG": str(session / "flows-unanswered.jsonl"),
                "VSCAN_ATTRIB_SOURCES": str(session / "egress.jsonl"),
                "VSCAN_PACKAGES": PKG, "VSCAN_SESSION": out.name})
    proxy = launch([mitmdump_path(), "-s", str(MOBILE / "traffic/addon_mobile.py"),
                    "--mode", f"reverse:http://127.0.0.1:{upstream}", "--listen-host", "127.0.0.1",
                    "--listen-port", str(port)], out / "mitm.log", env)
    processes.append(proxy)
    if not wait_listener(port, proxy):
        raise RuntimeError("mitmproxy 未成功监听（见 mitm.log）")
    probe = adb("shell", f"toybox nc -z -w 3 10.0.2.2 {port}; echo probe_rc=$?", timeout=20)
    (out / "network-probe.log").write_text(probe.stdout + probe.stderr, encoding="utf-8")
    return probe.returncode == 0 and "probe_rc=0" in probe.stdout


def hook_command(adb, script: Path, session: Path, output: str, seconds: int, port: int) -> list:
    # Root compatibility path uses the existing shared driver, serial via environment.
    return [PY, str(ROOT / "core/frida_host/run.py"), "--package", PKG,
            "--script", str(script), "--seconds", str(seconds), "--port", str(port),
            "--allow-package", PKG, "--session", session.parent.name, "--out", str(session / output)]


def start_hooks(adb, mode: str, port: int, session: Path, out: Path, seconds: int) -> list:
    env = adb.environment()
    env["VSCAN_SESSION"] = out.name
    if mode == "gadget":
        plan = out / "hook-plan.json"
        plan.write_text(json.dumps([{**item, "script": str(item["script"])} for item in HOOKS],
                                   indent=2), encoding="utf-8")
        cmd = [PY, str(MOBILE / "tools/device_hook_driver.py"), "--plan", str(plan),
               "--session-dir", str(session), "--session", session.parent.name,
               "--port", str(port), "--seconds", str(seconds),
               "--stop-file", str(session / ".capture-stop")]
        return [launch(cmd, out / "hook-gadget.log", env)]
    return [launch(hook_command(adb, item["script"], session, item["output"], seconds, port),
                   out / f"hook-{item['name']}.log", env) for item in HOOKS]


def read_events(path: Path) -> list:
    if not path.exists():
        return []
    result = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.strip():
            try:
                result.append(json.loads(line))
            except json.JSONDecodeError:
                result.append({"ev": "MALFORMED_EVENT"})
    return result


def hook_readiness(session: Path, mode: str) -> list:
    checks = []
    for item in HOOKS:
        events = read_events(session / item["output"])
        armed = next((ev for ev in events if ev.get("ev") == item["ready"]), None)
        count = (armed or {}).get("count", (armed or {}).get("hooks", 0))
        count = len(count) if isinstance(count, list) else count
        fatal = any(ev.get("ev") in ("SCRIPT_ERROR", "CAPTURE_ERROR", "MALFORMED_EVENT")
                    for ev in events)
        ok = isinstance(count, int) and count > 0 and not fatal
        disabled = item["name"] == "tls" and any(ev.get("ev") == "TLS_BYPASS_DISABLED" for ev in events)
        note = "TLS 审计开关未开启；白名单夹具验收可显式设置 VSCAN_TLS_BYPASS=1" if disabled else (
            None if ok else "未确认非零挂载，或采集脚本失败")
        checks.append({"name": f"hook_{item['name']}_armed", "exit_code": 0 if ok else 1,
                       "armed": armed, "note": note, "disabled": disabled})
    if mode == "gadget":
        starts = [ev for ev in read_events(session / "reads.jsonl") if ev.get("ev") == "START"]
        start = starts[0] if starts else {}
        valid = start.get("pkg") == PKG and isinstance(start.get("uid"), int) and start["uid"] > 0
        checks.append({"name": "gadget_app_identity", "exit_code": 0 if valid else 1,
                       "package": start.get("pkg"), "app_uid": start.get("uid")})
    return checks


def wait_hooks(session: Path, mode: str, processes: list, timeout: int = 50) -> list:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        checks = hook_readiness(session, mode)
        if all(check["exit_code"] == 0 for check in checks):
            return checks
        if any(check.get("disabled") for check in checks):
            return checks
        if any(process.poll() is not None for process in processes):
            return checks
        time.sleep(.5)
    return hook_readiness(session, mode)


def stop_capture(processes: list, hooks: list, session: Path, mode: str) -> list:
    results = []
    if mode == "gadget" and hooks:
        (session / ".capture-stop").write_text("controller requested stop\n", encoding="utf-8")
        for hook in hooks:
            try:
                hook.wait(timeout=15)
            except subprocess.TimeoutExpired:
                hook.terminate()
    for process in reversed(processes):
        try:
            if process.poll() is None:
                process.terminate()
            code = process.wait(timeout=20)
            if process in hooks and mode == "gadget":
                results.append({"name": "gadget_driver_exit", "exit_code": code})
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=10)
            results.append({"name": "capture_shutdown_timeout", "exit_code": 1})
    return results


def traffic_checks(session: Path) -> list:
    """Fixture acceptance needs answered app-attributed flows, not connection attempts."""
    flows = read_events(session / "flows.jsonl")
    accepted = [flow for flow in flows if flow.get("session_id") == session.parent.name
                and flow.get("package") == PKG and flow.get("attribution") == "app_process_hook"
                and flow.get("status_code") == 200 and (flow.get("request_bytes") or 0) > 0
                and flow.get("terminal") != "error" and flow.get("path") == "/collect"]
    return [{"name": name, "exit_code": 0 if matches else 1,
             "flow_ids": [flow.get("evt_id") for flow in matches],
             "note": "只验证自有夹具可观测流量，不按敏感读取数量判断成功"}
            for name, matches in (("http_flow_observed", [flow for flow in accepted
                                                          if flow.get("intercepted_tls") is False]),
                                  ("https_flow_observed", [flow for flow in accepted
                                                           if flow.get("intercepted_tls") is True]))]
