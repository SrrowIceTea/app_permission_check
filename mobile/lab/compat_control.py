"""Original APK compatibility control on one dedicated emulator. 仅用于授权测试。

No Frida, no proxy and no traffic collector are loaded. Native ABI selection is an
Android package-manager option; it does not rewrite or re-sign the original APK.
"""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import hashlib
from pathlib import Path
import time
from core.static.apkmeta import collect
from core.static.toolchain import android_build_tool
from mobile.lab.core_capture_ui import explore
from mobile.lab.root_runtime import Android, save
from mobile.tools.device_environment import resolve_adb


def control(apk, package, out, *, serial="emulator-5564", abi=None, launch_only=False, legacy_review=False):
    apk, out = Path(apk).resolve(), Path(out).resolve()
    out.mkdir(parents=True, exist_ok=False)
    android = Android(str(resolve_adb()), serial)
    android.folder = out
    result = {"apk_path": str(apk), "package": package,
              "apk_sha256": hashlib.sha256(apk.read_bytes()).hexdigest(),
              "control": "original APK; no Frida/proxy/traffic collector",
              "started_at": datetime.now(timezone.utc).isoformat(),
              "requested_abi": abi, "ui_mode": "launch-only" if launch_only else "declared-explore", "checks": {}, "state": "failed"}
    installed, install_attempted = False, False
    try:
        result["metadata"] = collect(android_build_tool("aapt2"), apk)
        if result["metadata"].get("package") != package:
            raise ValueError("source APK identity differs from explicit package whitelist")
        result["device"] = android.profile()
        result["device"]["abis"] = android.shell("getprop", "ro.product.cpu.abilist").strip()
        result["device"]["native_bridge"] = android.shell("getprop", "ro.dalvik.vm.native.bridge").strip()
        if "package:" in android.shell("pm", "path", package, check=False):
            raise RuntimeError("refusing to replace existing installation")
        if android.shell("settings", "get", "global", "http_proxy").strip() not in {"", "null", ":0"}:
            raise RuntimeError("control requires a device without a configured proxy")
        options = ["--abi", abi] if abi else []
        install_attempted = True
        message = android.call("install", *options, apk, timeout=600)
        if "Success" not in message:
            raise RuntimeError("installation failed: " + message)
        installed = True
        remote = android.shell("pm", "path", package).splitlines()[0].removeprefix("package:")
        digest = hashlib.sha256(android.call("exec-out", "cat", remote, binary=True)).hexdigest()
        result["checks"]["original_apk_installed"] = digest == result["apk_sha256"]
        if not result["checks"]["original_apk_installed"]:
            raise RuntimeError("installed APK differs from original")
        (out / "package.txt").write_text(android.shell("dumpsys", "package", package), encoding="utf-8")
        android.shell("logcat", "-c")  # This runner owns this dedicated emulator.
        try:
            if launch_only:
                result["ui_actions"] = [{"action": "launcher start only", "output": android.shell("monkey", "-p", package, "-c", "android.intent.category.LAUNCHER", "1")} ]
                time.sleep(10)
                if legacy_review:
                    active = android.shell("dumpsys", "activity", "activities")
                    (out / "pre-review-activity.txt").write_text(active, encoding="utf-8")
                    (out / "pre-review-screen.png").write_bytes(android.call("exec-out", "screencap", "-p", binary=True))
                    if package != "com.ruanmei.magiclines" or not any("mResumedActivity" in line and "ReviewPermissionsActivity" in line for line in active.splitlines()):
                        raise RuntimeError("expected observed legacy permission review for Pop Lines only")
                    if "720x1280" not in android.shell("wm", "size"):
                        raise RuntimeError("legacy review requires the observed 720x1280 display")
                    android.shell("input", "tap", "640", "1135")
                    result["ui_actions"].append({"action": "visible legacy permission review Continue",
                        "coordinates": [640, 1135], "source": "retained 720x1280 pre-review screenshot",
                        "note": "Pre-Android-6 system permission review accepted by test automation; not inferred policy consent."})
                    time.sleep(5)
            else:
                result["ui_actions"] = explore(android, package, "launch", None)
        except Exception as exc:
            result["ui_observation_gap"] = f"{type(exc).__name__}: {exc}"
        result["pids_after_ui"] = android.shell("pidof", package, check=False).strip().split()
        time.sleep(20)
        result["pids_after_wait"] = android.shell("pidof", package, check=False).strip().split()
        result["checks"]["process_alive_after_wait"] = bool(result["pids_after_wait"])
        try:
            if not launch_only:
                android.screen("final-ui")
        except Exception as exc:
            result.setdefault("diagnostic_errors", []).append("final UI: " + str(exc))
        (out / "screen.png").write_bytes(android.call("exec-out", "screencap", "-p", binary=True))
    except Exception as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        if install_attempted and not installed:
            try:
                path = android.shell("pm", "path", package, check=False).strip()
                if path.startswith("package:"):
                    actual = hashlib.sha256(android.call("exec-out", "cat", path.splitlines()[0][8:], binary=True)).hexdigest()
                    installed = actual == result["apk_sha256"]
                    result["partial_install_matches_source"] = installed
                    if not installed:
                        result["cleanup_error"] = "Interrupted installation identity mismatch; not removing it."
            except Exception as exc:
                result["cleanup_error"] = "Interrupted installation cleanup check: " + str(exc)
        for filename, args in {"crash.log": ("logcat", "-d", "-b", "crash"),
                               "logcat.log": ("logcat", "-d", "-v", "threadtime")}.items():
            try:
                (out / filename).write_text(android.shell(*args, check=False), encoding="utf-8")
            except Exception as exc:
                result.setdefault("diagnostic_errors", []).append(str(exc))
        if installed:
            try:
                android.shell("am", "force-stop", package)
                result["checks"]["test_install_removed"] = "Success" in android.call("uninstall", package)
            except Exception as exc:
                result["cleanup_error"] = str(exc)
        result["state"] = "done" if result["checks"] and all(result["checks"].values()) and not result.get("error") else "failed"
        result["completed_at"] = datetime.now(timezone.utc).isoformat()
        save(out / "verification.json", result)
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--apk", type=Path, required=True)
    p.add_argument("--package", required=True)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--serial", default="emulator-5564")
    p.add_argument("--abi", choices=("armeabi-v7a", "arm64-v8a", "x86", "x86_64"))
    p.add_argument("--launch-only", action="store_true", help="No UI automation service; retain process/screenshot and launch-only coverage")
    p.add_argument("--legacy-review", action="store_true", help="Accept observed legacy Pop Lines system review on the dedicated 720x1280 display")
    p.add_argument("--authorize", action="store_true")
    a = p.parse_args()
    if not a.authorize:
        p.error("--authorize is required for the selected original APK and dedicated emulator")
    r = control(a.apk, a.package, a.out, serial=a.serial, abi=a.abi, launch_only=a.launch_only, legacy_review=a.legacy_review)
    print(f"{a.package}: {r['state']}; {r.get('error', r['checks'])}", flush=True)
    return 0 if r["state"] == "done" else 1


if __name__ == "__main__":
    raise SystemExit(main())
