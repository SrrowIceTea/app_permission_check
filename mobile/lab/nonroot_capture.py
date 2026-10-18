"""Actual non-root Gadget capture into the original session contract. 仅用于授权测试。

The original APK remains the static/policy identity; only an explicitly bound,
re-signed APK is installed. No root/su/server, run-as, system CA or proxy changes.
"""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import time
from core.io_utils import load_jsonl
from core.static.apkmeta import collect
from core.static.toolchain import android_build_tool
from mobile.lab.gadget_observer import GadgetObserver
from mobile.lab.nonroot_identity import NonRootAndroid, file_hash, instrumentation
from mobile.lab.nonroot_traffic import NonRootTraffic
from mobile.lab.root_runtime import save
from mobile.tools.device_environment import resolve_adb

SCENARIOS = ("fixture", "libchecker", "readyou", "launch", "ghera-ecb", "ghera-cbc")


def capture(original_apk, instrumented_apk, manifest, package, out, *, serial="emulator-5560",
            scenario="launch", seconds=20, adb=None, pcap_sidecar=False, consent_timeout=120):
    if not re.fullmatch(r"[A-Za-z]\w*(?:\.\w+)+", package):
        raise ValueError("invalid explicit package whitelist")
    if scenario not in SCENARIOS or not 5 <= seconds <= 180 or not 1 <= consent_timeout <= 600:
        raise ValueError("unsupported declared scenario or observation/consent duration")
    original_apk, instrumented_apk, out = map(lambda p: Path(p).resolve(), (original_apk, instrumented_apk, out))
    proof = instrumentation(original_apk, instrumented_apk, manifest, package)
    out.mkdir(parents=True, exist_ok=False)
    session = out / "session"
    session.mkdir()
    android = NonRootAndroid(str(adb or resolve_adb()), serial)
    android.folder = out
    result = {"package": package, "apk_path": str(original_apk), "apk_sha256": file_hash(original_apk),
              "instrumented_apk_path": str(instrumented_apk), "instrumented_apk_sha256": file_hash(instrumented_apk),
              "instrumentation": proof, "instrumentation_manifest": str(Path(manifest).resolve()),
              "mode": "nonroot-gadget", "original_bytes_installed": False, "scenario": scenario,
              "started_at": datetime.now(timezone.utc).isoformat(), "session_dir": str(session),
              "state": "failed", "checks": {}, "gaps": [
                  "Dynamic observations belong to a re-signed Gadget-instrumented derivative, not byte-identical original APK.",
                  "Gadget loads during Application startup; work before the load point and other processes is outside this observation window.",
                  "Re-signing can change integrity checks, signature permissions and backend behavior; no signature self-check bypass is performed."]}
    observer, traffic, installed, forwarded = None, None, False, False
    try:
        result["apk_metadata"] = collect(android_build_tool("aapt2"), original_apk)
        changed_metadata = collect(android_build_tool("aapt2"), instrumented_apk)
        if result["apk_metadata"].get("package") != package or changed_metadata.get("package") != package:
            raise RuntimeError("original or instrumented APK package differs from explicit whitelist")
        if str(result["apk_metadata"].get("version_code")) != str(changed_metadata.get("version_code")):
            raise RuntimeError("instrumented APK version differs from original identity")
        result["checks"]["original_identity_bound"] = True
        (session / "requested-permissions.txt").write_text("\n".join(result["apk_metadata"].get("permissions", [])) + "\n", encoding="utf-8")
        result["device"] = android.profile()
        if "package:" in android.shell("pm", "path", package, check=False):
            raise RuntimeError("refusing to replace an existing application; remove only prior owned test artifacts explicitly")
        options = ["-g"] if scenario == "fixture" else []
        result["runtime_permissions_pregranted"] = bool(options)
        try:
            message = android.call("install", *options, instrumented_apk, timeout=180)
        except RuntimeError as exc:
            message = str(exc)
        if "INSTALL_FAILED_DEPRECATED_SDK_VERSION" in message:
            result["gaps"].append("Dedicated lab installation explicitly bypassed Android's legacy-target SDK installation block.")
            result["legacy_target_install_bypass"] = True
            try:
                message = android.call("install", "--bypass-low-target-sdk-block", *options, instrumented_apk, timeout=180)
            except RuntimeError as exc:
                message = str(exc)
        if "Success" not in message:
            raise RuntimeError("instrumented install did not return Success: " + message)
        installed = True
        remote = android.shell("pm", "path", package).splitlines()[0].removeprefix("package:")
        actual = hashlib.sha256(android.call("exec-out", "cat", remote, binary=True)).hexdigest()
        result["checks"]["instrumented_apk_installed"] = actual == result["instrumented_apk_sha256"]
        if not result["checks"]["instrumented_apk_installed"]:
            raise RuntimeError("installed APK hash differs from the bound re-signed derivative")
        android.call("forward", "--no-rebind", "tcp:27042", "tcp:27042")
        forwarded = True
        traffic = NonRootTraffic(android, session, package, scenario == "fixture",
                                 sidecar=pcap_sidecar, consent_timeout=consent_timeout, scenario=scenario)
        traffic.start()
        if traffic.network.get("uid_filter", {}).get("matches") is False:
            raise RuntimeError("VPN UID filter excludes current target UID; stop and restart the owned sidecar before a new capture")
        observer = GadgetObserver(package, session, serial, android)
        try:
            result["pid"] = observer.start()
        finally:
            result["pid"] = observer.pid
            save(out / "observer-start.json", {"pid": observer.pid, "package": package,
                                               "start_completed": bool(observer.healthy()), "mode": "nonroot-gadget"})
        from mobile.lab.nonroot_capture_ui import explore_nonroot
        save(session / "ui-actions.json", explore_nonroot(android, package, scenario, traffic, result["pid"], out))
        time.sleep(seconds)
        result["checks"].update(target_pid_alive=str(result["pid"]) in android.shell("pidof", package, check=False).split(),
                                  scripts_error_free=not observer.errors, hooks_armed=observer.healthy())
        result["state"] = "done" if all(result["checks"].values()) else "failed"
    except Exception as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        cleanup_errors = []
        if observer:
            if result.get("checks", {}).get("target_pid_alive") is False:
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
                cleanup_errors.append("network cleanup: " + str(exc))
            result["traffic"] = traffic.network
            result["gaps"].extend(traffic.network.get("gaps", []))
            if traffic.sidecar and traffic.requested and traffic.network.get("stopped") is not True:
                cleanup_errors.append("VPN sidecar stop was not confirmed")
        try:
            if installed:
                android.shell("am", "force-stop", package)
                result["checks"]["test_install_removed"] = "Success" in android.call("uninstall", package)
            if forwarded:
                android.call("forward", "--remove", "tcp:27042")
                result["checks"]["owned_forward_removed"] = True
        except Exception as exc:
            cleanup_errors.append("owned test artifact cleanup: " + str(exc))
        evidence_errors, records = [], {}
        for name in ("reads", "flows", "consent", "egress", "audit"):
            try:
                records[name] = load_jsonl(session / (name + ".jsonl"))
                if not all(isinstance(row, dict) for row in records[name]):
                    raise ValueError("records must be objects")
            except (OSError, ValueError) as exc:
                evidence_errors.append({"source": name, "error": str(exc)})
                records[name] = []
        result["real_privacy_reads"] = sum(r.get("ev") == "PRIVACY_READ" for r in records["reads"])
        result["flows"] = len(records["flows"])
        result["checks"]["evidence_parseable"] = not evidence_errors
        if evidence_errors:
            result["evidence_errors"] = evidence_errors
        if scenario == "fixture":
            result["checks"].update(
                positive_control_read_observed=any(r.get("ev") == "PRIVACY_READ" and r.get("collection_state") == "obtained" for r in records["reads"]),
                positive_control_network_observed=any(r.get("package") == package and r.get("status_code") == 200 and r.get("attribution") != "unresolved" for r in records["flows"]))
            if pcap_sidecar:
                result["checks"]["positive_control_vpn_packet_observed"] = bool(
                    result.get("traffic", {}).get("state") == "done" and result["traffic"].get("fixture_http_packets", 0) > 0)
        result["failed_checks"] = [name for name, value in result["checks"].items() if value is not True]
        if cleanup_errors or result["failed_checks"]:
            result["state"] = "failed"
            result["cleanup_errors"] = cleanup_errors
            result.setdefault("error", "; ".join([*result["failed_checks"], *cleanup_errors]))
        result["gaps"].append("Finite UI observation and opaque encrypted network payloads cannot prove absence of leakage.")
        result["completed_at"] = datetime.now(timezone.utc).isoformat()
        save(out / "verification.json", result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--original-apk", required=True, type=Path)
    parser.add_argument("--instrumented-apk", required=True, type=Path)
    parser.add_argument("--instrumentation", required=True, type=Path)
    parser.add_argument("--package", required=True)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--serial", default="emulator-5560")
    parser.add_argument("--scenario", choices=SCENARIOS, default="launch")
    parser.add_argument("--seconds", type=int, default=20)
    parser.add_argument("--pcap-sidecar", action="store_true")
    parser.add_argument("--consent-timeout", type=int, default=120)
    parser.add_argument("--authorize", action="store_true")
    args = parser.parse_args()
    if not args.authorize:
        parser.error("--authorize is required for the explicitly selected APK and dedicated emulator")
    value = capture(args.original_apk, args.instrumented_apk, args.instrumentation, args.package, args.out,
                    serial=args.serial, scenario=args.scenario, seconds=args.seconds,
                    pcap_sidecar=args.pcap_sidecar, consent_timeout=args.consent_timeout)
    print(json.dumps(value, ensure_ascii=False, indent=2))
    return 0 if value["state"] == "done" else 1


if __name__ == "__main__":
    raise SystemExit(main())
