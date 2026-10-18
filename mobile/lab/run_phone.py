"""One-command physical-device fixture acceptance; 仅用于授权测试。

Prerequisites: prepared matching ARM64 Gadget APK, compiled probe, PCAPdroid,
and local lab certificate already packaged into the owned fixture APK.
Phone-side capture/VPN consent is never bypassed. Only synthetic fixture traffic.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "mobile/tools"))
from device_environment import resolve_adb
from pcap_sidecar import Sidecar


def save(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--serial", required=True)
    parser.add_argument("--host", required=True, help="explicit local LAN IPv4, reachable by the phone")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--cert-dir", type=Path, required=True)
    parser.add_argument("--canary", required=True)
    parser.add_argument("--authorize-owned-fixture", action="store_true")
    parser.add_argument("--consent-timeout", type=int, default=180)
    args = parser.parse_args(argv)
    out, cert = args.out.resolve(), args.cert_dir.resolve()
    try:
        host = ipaddress.IPv4Address(args.host)
        if host.is_loopback or host.is_unspecified or host.is_multicast:
            parser.error("an explicit unicast LAN IPv4 is required")
        if not args.authorize_owned_fixture:
            parser.error("explicit --authorize-owned-fixture is required")
        if not re.fullmatch(r"VSCAN_TEST_[A-Za-z0-9_]{1,64}", args.canary):
            parser.error("synthetic VSCAN_TEST_ marker required")
        if not out.is_relative_to((ROOT / "output").resolve()) or out.exists():
            parser.error("use a new experiment directory inside this checkout's output/")
        if not 1 <= args.consent_timeout <= 600:
            parser.error("consent timeout must be 1..600 seconds")
        for name in ("lab-cert.pem", "lab-key.pem"):
            if not (cert / name).is_file():
                parser.error("certificate directory must contain the packaged test anchor and private key")
    except ValueError as exc:
        parser.error(str(exc))
    out.mkdir(parents=True, exist_ok=False)
    for name in ("lab-cert.pem", "lab-key.pem"):
        shutil.copy2(cert / name, out / name)
    name = "vscanner-" + str(time.time_ns()) + ".pcap"
    sidecar = Sidecar(resolve_adb(), args.serial)
    checks, failures = [], []
    started = False
    result = {"serial": args.serial, "host": str(host), "scope": "self_owned_fixture_acceptance",
              "canary": args.canary, "remote_capture": name, "capture_context": "physical-vpn",
              "scope_not_claimed": "arbitrary_APKs_or_universal_protocol_decryption",
              "system_ca_changed": False, "root_requested": False}

    def require(label, ok):
        checks.append({"name": label, "passed": bool(ok)})
        if not ok:
            raise RuntimeError(label)

    def command(label, command):
        env = {**os.environ, "PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8"}
        completed = subprocess.run(command, cwd=ROOT, env=env, capture_output=True,
                                   text=True, encoding="utf-8", errors="replace", timeout=240)
        (out / (label + ".log")).write_text(completed.stdout + completed.stderr, encoding="utf-8")
        require(label, completed.returncode == 0)

    def finish_capture():
        nonlocal started
        state = sidecar.stop(name)
        deadline = time.monotonic() + 60
        while state["status"] != "stopped" and time.monotonic() < deadline:
            time.sleep(1)
            state = sidecar.status(name)
        save(out / "capture-stop.json", state)
        require("capture_stopped", state["status"] == "stopped")
        started = False

    try:
        # Install before target-UID filtering: don't let the VPN start with a missing package.
        apk = ROOT / "mobile/fixture-app/app/build/outputs/apk/gadget/app-gadget.apk"
        command("install_owned_fixture", sidecar.prefix + ["install", "-r", str(apk)])
        state = sidecar.start(name)
        started = True
        save(out / "capture-request.json", state)
        print("如设备弹出 PCAPdroid 控制/VPN 请求，请在设备上确认；等待采集就绪。", flush=True)
        end = time.monotonic() + args.consent_timeout
        while not state.get("requested_capture_confirmed") and time.monotonic() < end:
            time.sleep(1)
            state = sidecar.status(name, observe=True)
        save(out / "capture-running.json", state)
        require("capture_running_before_probe", state.get("requested_capture_confirmed") is True)
        command("probe", [sys.executable, str(ROOT / "mobile/lab/run_probe.py"),
                          "--out", str(out), "--serial", args.serial, "--transport", "lan",
                          "--host", str(host), "--bind-host", str(host), "--canary", args.canary,
                          "--authorize-owned-fixture", "--skip-install"])
        require("capture_running_after_probe", sidecar.status(name).get("requested_capture_confirmed") is True)
        finish_capture()
        save(out / "capture-pull.json", sidecar.pull(name, out / "network.pcap"))
        command("network", [sys.executable, str(ROOT / "mobile/lab/validate_network.py"),
                            "--pcap", str(out / "network.pcap"),
                            "--receipts", str(out / "sink-receipts.jsonl"), "--canary", args.canary,
                            "--capture-context", "physical-vpn", "--out", str(out / "network-verification.json")])
        probe = json.loads((out / "probe-verification.json").read_text(encoding="utf-8"))
        profile = probe["device_profile"]
        require("production_user_image", profile.get("ro.build.type") == "user"
                and profile.get("ro.debuggable") == "0")
        require("nonroot_shell", profile.get("shell_uid") == 2000)
        assessment = json.loads((out / "probe-assessment.json").read_text(encoding="utf-8"))
        events = [json.loads(line) for line in (out / "probe-events.jsonl").read_text(encoding="utf-8").splitlines()]
        disk_matches = {}
        for filename in ("audit-ecb.bin", "audit-gcm.bin"):
            observed = [row.get("bytes", {}).get("hex") for row in events
                        if row.get("ev") == "FILE_WRITE" and row.get("success") is True
                        and row.get("path", {}).get("text", "").endswith("/" + filename)
                        and row.get("bytes", {}).get("truncated") is False]
            disk_matches[filename] = (out / filename).read_bytes().hex() in observed
        require("ciphertext_disk_bytes_match_observed_writes", all(disk_matches.values()))
        result["ciphertext_disk_matches"] = disk_matches
        result.update(device_profile=profile, gadget_abi=probe["gadget"]["selected_abi"],
                      storage_plaintext_observed=assessment["storage_plaintext_observed"],
                      weak_ciphertext_storage_observed=assessment["weak_ciphertext_storage_observed"],
                      encrypted_storage_evidence=assessment["encrypted_storage_evidence"])
    except Exception as exc:
        failures.append({"type": type(exc).__name__, "detail": str(exc)})
    finally:
        if started:
            try:
                finish_capture()
            except Exception as exc:
                failures.append({"cleanup": str(exc), "action": "stop PCAPdroid on the phone"})
        result.update(checks=checks, failures=failures,
                      passed=bool(checks) and all(x["passed"] for x in checks) and not failures)
        save(out / "phone-verification.json", result)
    print(json.dumps({"passed": result["passed"], "out": str(out), "failures": failures}, ensure_ascii=False))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
