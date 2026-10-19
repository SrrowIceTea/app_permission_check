"""Actual root observation to the original correlate/evidence session contract.

python -m mobile.lab.core_capture --apk APP --package PKG --out DIR
  --serial emulator-5562 --scenario libchecker --authorize
No correlate/AI/report duplication: callers use the existing downstream modules.
"""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import time
from mobile.lab.root_runtime import Android, save
from mobile.lab.core_observer import CoreObserver
from mobile.lab.core_traffic import Traffic
from mobile.lab.core_capture_ui import explore
from mobile.tools.device_environment import resolve_adb
from core.static.apkmeta import collect
from core.static.toolchain import android_build_tool
from core.io_utils import load_jsonl


def _jsonl(path):
    rows = load_jsonl(path)
    if not all(isinstance(row, dict) for row in rows):
        raise ValueError(f"JSONL records must be objects: {path}")
    return rows


def _evidence_jsonl(path, errors):
    try:
        return _jsonl(path)
    except (OSError, ValueError) as exc:
        errors.append({"file": path.name, "error": f"{type(exc).__name__}: {exc}"})
        return None


def capture(apk: Path, package: str, out: Path, *, serial="emulator-5562", scenario="launch",
            seconds=20, adb=None, startup_mode="spawn", install_abi=None, android_jar=None) -> dict:
    if not re.fullmatch(r"[A-Za-z]\w*(?:\.\w+)+", package):
        raise ValueError("invalid explicit package whitelist")
    if scenario not in {"fixture", "libchecker", "readyou", "launch", "launch-only", "legacy-review"}:
        raise ValueError("unsupported declared UI scenario")
    if install_abi not in {None, "armeabi-v7a", "arm64-v8a", "x86", "x86_64"}:
        raise ValueError("unsupported explicit install ABI")
    if startup_mode not in {"spawn", "attach"}:
        raise ValueError("unsupported startup mode")
    if not 5 <= seconds <= 180:
        raise ValueError("capture duration must be between 5 and 180 seconds")
    apk, out = Path(apk).resolve(), Path(out).resolve()
    out.mkdir(parents=True, exist_ok=False)
    session = out / "session"
    session.mkdir()
    android = Android(str(adb or resolve_adb()), serial)
    android.folder = out
    result = {"package": package, "apk_path": str(apk),
              "apk_sha256": hashlib.sha256(apk.read_bytes()).hexdigest(),
              "started_at": datetime.now(timezone.utc).isoformat(), "scenario": scenario, "ui_scenario_version": 3,
              "startup_mode": startup_mode, "install_abi": install_abi,
              "session_dir": str(session), "state": "failed", "checks": {}, "gaps": []}
    observer, traffic, installed = None, None, False
    try:
        result["apk_metadata"] = collect(android_build_tool("aapt2"), apk)
        if result["apk_metadata"].get("package") != package:
            raise RuntimeError("source APK package differs from explicit target whitelist")
        (session / "requested-permissions.txt").write_text(
            "\n".join(result["apk_metadata"].get("permissions", [])) + "\n", encoding="utf-8")
        result["device"] = android.profile()
        android.call("forward", "tcp:27043", "tcp:27043")
        if "package:" in android.shell("pm", "path", package, check=False):
            raise RuntimeError("refusing to replace existing package on emulator; remove only prior test artifacts explicitly")
        # Real apps start with ordinary permission defaults, not blanket runtime grants.
        options = ["-g"] if scenario == "fixture" else []
        result["runtime_permissions_pregranted"] = bool(options)
        if install_abi:
            options += ["--abi", install_abi]
            result["gaps"].append("Original APK installed using explicit Android package-manager ABI selection: " + install_abi)
        try:
            installed_msg = android.call("install", *options, apk, timeout=180)
        except RuntimeError as error:
            installed_msg = str(error)
        if "INSTALL_FAILED_DEPRECATED_SDK_VERSION" in installed_msg:
            result["legacy_target_install_bypass"] = True
            result["gaps"].append("Dedicated lab installation bypassed Android's old-target SDK block; not a production-device compatibility claim.")
            try:
                installed_msg = android.call("install", "--bypass-low-target-sdk-block", *options,
                                             apk, timeout=180)
            except RuntimeError as error:
                installed_msg = str(error)
        if "Success" not in installed_msg:
            raise RuntimeError("installation did not return Success: " + installed_msg)
        installed = True
        remote_path = android.shell("pm", "path", package).splitlines()[0].removeprefix("package:")
        actual = hashlib.sha256(android.call("exec-out", "cat", remote_path, binary=True)).hexdigest()
        result["checks"]["original_apk_installed"] = actual == result["apk_sha256"]
        if not result["checks"]["original_apk_installed"]:
            raise RuntimeError("installed APK hash differs from source")
        traffic = Traffic(android, session, package, scenario == "fixture")
        traffic.start()
        observer = CoreObserver(package, session, serial, android)
        observer.startup_mode = startup_mode
        if android_jar:
            observer.android_jar, observer.android_api = Path(android_jar), result["device"]["android_api"]
            result["gaps"].append("SDK-specific hook signature subset selected from supplied android.jar; compliance rules DB remains its original version.")
        if startup_mode == "attach":
            observer.before_attach = lambda: save(session / "pre-attach-ui-actions.json",
                                                  explore(android, package, scenario, traffic))
            result["gaps"].append("Late attach: application started before hook installation; startup and pre-attach behavior are outside this observation window.")
        observer_started = False
        try:
            pid = observer.start()
            result["pid"] = pid
            observer_started = True
        finally:
            # spawn() assigns observer.pid before ARM waiting; retain it even if start raises.
            spawned_pid = getattr(observer, "pid", None)
            if spawned_pid is not None:
                result["pid"] = spawned_pid
            save(out / "observer-start.json", {"pid": result.get("pid"),
                "start_completed": observer_started, "package": package,
                "recorded_at": datetime.now(timezone.utc).isoformat()})
        save(session / "ui-actions.json", explore(android, package, scenario, traffic))
        time.sleep(seconds)
        result["checks"]["original_pid_alive"] = android.shell(
            "test -d /proc/" + str(pid) + " && echo yes || echo no").strip() == "yes"
        result["checks"]["scripts_error_free"] = not observer.errors
        result["checks"]["hooks_armed"] = observer.healthy()
        result["state"] = "done" if all(result["checks"].values()) else "failed"
    except Exception as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        cleanup_errors = []
        if observer:
            # A dead process has no hook to unload. Calling synchronous Frida unload on
            # its stale session can hang and prevent PCAP export/owned-app cleanup.
            if result.get("checks", {}).get("original_pid_alive") is False and hasattr(observer, "dead"):
                observer.dead.set()
            try:
                observer.close()
            except Exception as exc:
                cleanup_errors.append("observer: " + str(exc))
            result["hooks"] = observer.summary()
        if traffic:
            try:
                traffic.close()
            except Exception as exc:
                cleanup_errors.append("traffic: " + str(exc))
        for name, args in {"app.log": ("logcat", "-d", "-s", "VSPrivacyDemo:I", "*:S"),
                           "crash.log": ("logcat", "-d", "-b", "crash")}.items():
            try:
                (session / name).write_text(android.shell(*args, check=False), encoding="utf-8")
            except Exception as exc:
                cleanup_errors.append("diagnostics: " + str(exc))
        if installed:
            try:
                android.shell("am", "force-stop", package)
                message = android.call("uninstall", package)
                result["checks"]["test_install_removed"] = "Success" in message
            except Exception as exc:
                cleanup_errors.append("uninstall: " + str(exc))
                result["checks"]["test_install_removed"] = False
        evidence_errors = []
        rows = _evidence_jsonl(session / "reads.jsonl", evidence_errors)
        flows = _evidence_jsonl(session / "flows.jsonl", evidence_errors)
        result["real_privacy_reads"] = sum(r.get("ev") == "PRIVACY_READ" for r in rows) if rows is not None else None
        result["flows"] = len(flows) if flows is not None else None
        pcap_summary = session / "pcap-summary.json"
        if pcap_summary.is_file():
            try:
                result["pcap"] = json.loads(pcap_summary.read_text(encoding="utf-8"))
                if not isinstance(result["pcap"], dict):
                    raise ValueError("PCAP summary must be an object")
                if result["pcap"].get("unknown_packets") or result["pcap"].get("truncations"):
                    result["gaps"].append("Some captured PCAP records are unsupported/truncated; inspect pcap-summary.json.")
            except (OSError, ValueError) as exc:
                evidence_errors.append({"file": pcap_summary.name, "error": f"{type(exc).__name__}: {exc}"})
        result["checks"]["evidence_parseable"] = not evidence_errors
        if evidence_errors:
            result["evidence_errors"] = evidence_errors
            result["gaps"].append("Raw evidence contains malformed or unreadable records; counts remain unknown and capture failed.")
        if scenario == "fixture":
            result["checks"]["positive_control_read_observed"] = any(
                r.get("ev") == "PRIVACY_READ" and r.get("collection_state") == "obtained" for r in (rows or []))
            result["checks"]["positive_control_network_observed"] = any(
                row.get("package") == package and row.get("status_code") == 200
                and row.get("attribution") != "unresolved" for row in (flows or []))
        if cleanup_errors:
            result["cleanup_errors"] = cleanup_errors
        scope = out / "compiled-hooks/sdk-hook-scope.json"
        if scope.is_file():
            result["hook_scope"] = json.loads(scope.read_text(encoding="utf-8"))
        result["failed_checks"] = [name for name, passed in result["checks"].items() if passed is not True]
        if cleanup_errors or result["failed_checks"]:
            result["state"] = "failed"
            if not result.get("error"):
                reasons = ["capture checks failed: " + ", ".join(result["failed_checks"])] if result["failed_checks"] else []
                reasons.extend(cleanup_errors)
                result["error"] = "; ".join(reasons)
        result["gaps"] += ["HTTPS without test CA is opaque; PCAP covers packets, not universal decryption.",
                            "UI scenario is finite; no observation does not prove absence of a behavior."]
        result["completed_at"] = datetime.now(timezone.utc).isoformat()
        save(out / "verification.json", result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apk", type=Path, required=True)
    parser.add_argument("--package", required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--serial", default="emulator-5562")
    parser.add_argument("--scenario", default="launch", choices=("fixture", "libchecker", "readyou", "launch", "launch-only", "legacy-review"))
    parser.add_argument("--seconds", type=int, default=20)
    parser.add_argument("--startup-mode", choices=("spawn", "attach"), default="spawn")
    parser.add_argument("--install-abi", choices=("armeabi-v7a", "arm64-v8a", "x86", "x86_64"))
    parser.add_argument("--android-jar", type=Path, help="Explicit SDK jar matching this device; exact javap signature subset, no rules DB rewrite")
    parser.add_argument("--authorize", action="store_true")
    args = parser.parse_args()
    if not args.authorize:
        parser.error("--authorize required for explicitly selected APK and dedicated emulator")
    result = capture(args.apk, args.package, args.out, serial=args.serial, scenario=args.scenario, seconds=args.seconds, startup_mode=args.startup_mode, install_abi=args.install_abi, android_jar=args.android_jar)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["state"] == "done" else 1


if __name__ == "__main__":
    raise SystemExit(main())
