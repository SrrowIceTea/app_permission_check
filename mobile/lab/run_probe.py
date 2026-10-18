"""Explicit, owned-fixture non-root experiment. 仅用于授权测试，不操作第三方 APK。

Prepare the public local TLS anchor before building the gadget APK:
  python mobile/lab/run_probe.py --prepare-cert-only --out output/YOUR_SESSION
Then build :app:assembleGadget and compile mobile/audit/storage_crypto.js.
This runner never starts adb root, su, frida-server or a system CA/proxy change.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import re
import subprocess
import sys
import threading
import time
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "mobile/tools"), str(ROOT / "mobile/audit")]
from device_environment import AdbClient, collect_device_profile, resolve_adb, wait_boot
from device_provenance import inspect_gadget
from local_probe_servers import LocalProbeServers, prepare_certificate, transport_config

PKG = "com.vscanner.privacydemo"


def current_probe_lines(log, canary, run_id):
    marker = " token=" + canary + " run=" + run_id
    return "\n".join(line for line in log.splitlines() if line.rstrip().endswith(marker))


def prepare_fixture_apk(command, apk, skip_install=False):
    if not skip_install:
        command("install", "-r", str(apk), timeout=180)
        return {"install_mode": "install_replace"}
    listed = command("shell", "pm", "path", PKG)
    bases = [line.removeprefix("package:").strip() for line in listed.splitlines()
             if line.startswith("package:") and line.strip().endswith("/base.apk")]
    if len(bases) != 1:
        raise RuntimeError("expected one installed fixture base.apk")
    base = bases[0]
    output = command("shell", "sha256sum", base).strip()
    match = re.fullmatch(r"([a-fA-F0-9]{64})\s+\*?" + re.escape(base), output)
    if not match:
        raise RuntimeError("installed base.apk sha256sum was not verifiable")
    digest = hashlib.sha256(apk.read_bytes()).hexdigest()
    if match[1].lower() != digest:
        raise RuntimeError("installed APK differs from --apk; install before starting VPN capture")
    return {"install_mode": "verified_existing_apk", "installed_base_apk": base,
            "installed_apk_sha256": digest}


def wait_gadget_processes(device, frida_module, timeout=25):
    end, processes = time.monotonic() + timeout, []
    while time.monotonic() < end:
        try:
            processes = device.enumerate_processes()
            if processes:
                break
        except (frida_module.TransportError, frida_module.ServerNotRunningError):
            pass
        time.sleep(.5)
    return processes


def cleanup_gadget_forward(adb):
    pair = [adb.serial, "tcp:27044", "tcp:27044"]
    def state():
        listing = adb("forward", "--list")
        rows = [line.split() for line in listing.stdout.splitlines()]
        return listing, "owned" if pair in rows else "changed" if any(
            row[:2] == pair[:2] for row in rows) else "absent"
    listing, status = state()
    result = None
    if listing.returncode == 0 and status == "owned":
        result = adb("forward", "--remove", "tcp:27044")
        if result.returncode == 0:
            status = "removed"
        else:
            listing, status = state()
    passed = listing.returncode == 0 and status in ("absent", "removed")
    return {"name": "forward_cleanup", "passed": passed,
            "state": status if passed or status == "changed" else "error",
            "stderr": (result.stderr if result else listing.stderr)}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--serial")
    parser.add_argument("--skip-install", action="store_true", help="verify the already-installed APK bytes; do not replace during VPN capture")
    parser.add_argument("--transport", choices=("usb", "emulator", "lan"), default="emulator")
    parser.add_argument("--host", help="device destination IPv4; LAN requires explicit local IP")
    parser.add_argument("--udp-host", help="USB reverse cannot carry UDP; explicit LAN IP enables it")
    parser.add_argument("--bind-host", help="exact local IP to bind; no wildcard")
    parser.add_argument("--udp-bind-host", help="exact local UDP listener IP")
    parser.add_argument("--replace-test-certificate", action="store_true")
    parser.add_argument("--canary", default="VSCAN_TEST_STORAGE_NETWORK_20261017")
    parser.add_argument("--authorize-owned-fixture", action="store_true")
    parser.add_argument("--prepare-cert-only", action="store_true")
    parser.add_argument("--bundle", type=Path, default=ROOT / "mobile/audit/storage_crypto.bundle.js")
    parser.add_argument("--apk", type=Path, default=ROOT / "mobile/fixture-app/app/build/outputs/apk/gadget/app-gadget.apk")
    args = parser.parse_args(argv)
    try:
        network = transport_config(args.transport, args.host, args.udp_host, args.bind_host, args.udp_bind_host)
    except ValueError as error:
        parser.error(str(error))
    out = args.out.resolve()
    if not out.is_relative_to((ROOT / "output").resolve()):
        parser.error("--out must be an experiment directory inside this checkout's output/")
    out.mkdir(parents=True, exist_ok=True)
    if args.prepare_cert_only:
        asset = ROOT / "mobile/fixture-app/app/src/gadget/assets/audit-local-ca.pem"
        try:
            prepare_certificate(out, asset, hosts=[network["host"]], replace=args.replace_test_certificate)
        except ValueError as error:
            parser.error(str(error))
        return 0
    if not args.authorize_owned_fixture or not args.serial:
        parser.error("explicit --serial and --authorize-owned-fixture are required")
    if not re.fullmatch(r"VSCAN_TEST_[A-Za-z0-9_]{1,64}", args.canary):
        parser.error("only synthetic VSCAN_TEST_* canaries are accepted")
    if (out / "probe-events.jsonl").exists():
        parser.error("probe output already exists; do not overwrite an earlier run")
    import frida
    from assess_probe import assess

    checks, events, failures = [], [], []
    lock = threading.RLock()
    armed = threading.Event()
    adb = AdbClient(resolve_adb(), args.serial)
    session, forwarded, device = None, False, None
    owned_reverses, run_id = [], str(time.time_ns())
    metadata = {"scope": "self_owned_synthetic_fixture", "canary": args.canary,
                "startup_coverage": "after_attach_only", "system_ca_changed": False,
                "system_proxy_changed": False, "frida_server_used": False,
                "tls_content_hook_used": False, "vpn_sidecar_tested": False, "network": network,
                "audit_run_id": run_id, "owned_reverse_cleanup": []}

    def require(name, ok, detail=None):
        checks.append({"name": name, "passed": bool(ok), "detail": detail})
        if not ok:
            raise RuntimeError(name)

    def command(*parts, timeout=60):
        result = adb(*parts, timeout=timeout)
        require("adb_" + "_".join(parts[:2]), result.returncode == 0,
                (result.stdout + result.stderr)[-2000:])
        return result.stdout

    def receive(message, _data):
        if message.get("type") == "error":
            failures.append(message)
            return
        if message.get("type") != "send":
            return
        payload = message.get("payload", {})
        event = json.loads(payload["line"]) if payload.get("line") else payload
        event = {**event, "host_received_ts": int(time.time() * 1000), "session_id": out.name}
        with lock:
            events.append(event)
            with (out / "probe-events.jsonl").open("a", encoding="utf-8") as stream:
                stream.write(json.dumps(event, ensure_ascii=False) + "\n")
        if event.get("ev") == "ARMED" and event.get("pkg") == PKG:
            armed.set()

    try:
        require("selected_device", adb.select_device() == args.serial)
        require("device_boot_completed", wait_boot(adb))
        profile = collect_device_profile(adb, "gadget")
        metadata["device_profile"] = profile
        require("nonroot_shell", profile["nonroot_shell_observed"])
        metadata["gadget"] = inspect_gadget(args.apk, profile, 27044, frida.__version__)
        with zipfile.ZipFile(args.apk) as archive:
            require("local_tls_anchor_matches_apk", archive.read("assets/audit-local-ca.pem")
                    == (out / "lab-cert.pem").read_bytes())
        require("clean_proxy", command("shell", "settings", "get", "global", "http_proxy").strip()
                in ("", "null", ":0"))
        forwards = command("forward", "--list")
        require("gadget_forward_not_already_owned", f"tcp:27044" not in forwards)
        metadata.update(prepare_fixture_apk(command, args.apk, args.skip_install))
        command("shell", "am", "force-stop", PKG)
        command("forward", "--no-rebind", "tcp:27044", "tcp:27044")
        forwarded = True
        with LocalProbeServers(out, network["bind_host"], network["udp_bind_host"],
                               enable_udp=bool(network["udp_host"])) as sinks:
            metadata["local_listener_startup_checks"] = sinks.startup_checks
            if args.transport == "usb":
                existing = command("reverse", "--list")
                for port in (18890, 18891, 18889):
                    endpoint = f"tcp:{port}"
                    require("reverse_not_already_owned_" + str(port), endpoint not in existing)
                    command("reverse", "--no-rebind", endpoint, endpoint)
                    owned_reverses.append(endpoint)
            command("shell", "am", "start", "-W", "-n", PKG + "/.MainActivity")
            device = frida.get_device_manager().add_remote_device("127.0.0.1:27044")
            processes = wait_gadget_processes(device, frida)
            require("single_gadget_process", len(processes) == 1)
            metadata["gadget_pid"] = processes[0].pid
            metadata["app_process"] = "\n".join(line for line in command("shell", "ps", "-A", "-o", "UID,PID,NAME").splitlines() if PKG in line)
            session = device.attach(processes[0].pid)
            script = session.create_script(args.bundle.read_text(encoding="utf-8"))
            script.on("message", receive)
            script.load()
            require("probe_armed", armed.wait(20))
            command("shell", "am", "start", "-W", "-n", PKG + "/.AuditProbeActivity",
                    "--es", "audit_token", args.canary, "--es", "audit_run_id", run_id,
                    "--es", "fixture_host", network["host"], "--es", "udp_host",
                    network["udp_host"] or network["host"], "--ez", "skip_udp",
                    "false" if network["udp_host"] else "true")
            deadline, log = time.monotonic() + 60, ""
            while time.monotonic() < deadline:
                raw_log = command("shell", "logcat", "-d", "-s", "AuditProbe:I", "*:S")
                log = current_probe_lines(raw_log, args.canary, run_id)
                if "AUDIT_PROBE DONE " + args.canary in log:
                    break
                time.sleep(.8)
            (out / "probe-logcat.txt").write_text(log, encoding="utf-8")
            require("probe_completed", "AUDIT_PROBE DONE " + args.canary in log)
            require("fixture_no_failures", "AUDIT_PROBE " in log and "_FAIL " not in log)
            counts = Counter(row["protocol"] for row in sinks.records
                             if row["synthetic_payload"] == args.canary)
            metadata["sink_receipts"] = dict(counts)
            for protocol in ("http", "https", "tcp") + (("udp",) if network["udp_host"] else ()):
                require(protocol + "_received_exact_canary", counts[protocol] >= 1)
            # Debug-fixture disk cross-check only, not generic release-APK run-as access.
            disk = {}
            for name in ("audit-plaintext.txt", "audit-ecb.bin", "audit-gcm.bin"):
                result = subprocess.run([adb.executable, "-s", args.serial, "exec-out", "run-as",
                                         PKG, "cat", "files/" + name], capture_output=True, timeout=20)
                require("read_owned_fixture_" + name, result.returncode == 0)
                (out / name).write_bytes(result.stdout)
                disk[name] = {"bytes": len(result.stdout), "canary_present": args.canary.encode() in result.stdout}
            metadata["debug_fixture_disk_crosscheck"] = disk
            require("plaintext_persisted", disk["audit-plaintext.txt"]["canary_present"])
            require("ciphertext_does_not_contain_plaintext_canary", not any(
                disk[name]["canary_present"] for name in ("audit-ecb.bin", "audit-gcm.bin")))
            require("gadget_process_still_alive", bool(command("shell", "pidof", PKG).strip()))
            time.sleep(.3)
        require("no_script_errors", not failures, failures)
        with lock:
            assessment = assess(list(events), args.canary, evidence_origin="device")
        require("plaintext_storage_control", assessment["storage_plaintext_observed"])
        require("weak_ciphertext_storage_control", assessment["weak_ciphertext_storage_observed"])
        require("gcm_not_flagged_weak", all(row["algorithm"] == "AES/ECB/PKCS5Padding" for row in assessment["weak_crypto_evidence"]))
        (out / "probe-assessment.json").write_text(json.dumps(assessment, ensure_ascii=False, indent=2), encoding="utf-8")
        metadata["event_counts"] = dict(Counter(event.get("ev", "unknown") for event in events))
    except Exception as exc:
        failures.append({"exception": type(exc).__name__, "detail": str(exc)})
    finally:
        if session:
            try:
                session.detach()
            except Exception as exc:
                failures.append({"detach": str(exc)})
        if device:
            frida.get_device_manager().remove_remote_device("127.0.0.1:27044")
        for endpoint in owned_reverses:
            listing = adb("reverse", "--list")
            unchanged = listing.returncode == 0 and any(
                row.split()[-2:] == [endpoint, endpoint] for row in listing.stdout.splitlines())
            result = adb("reverse", "--remove", endpoint) if unchanged else None
            item = {"name": "reverse_cleanup_" + endpoint, "passed": bool(result and result.returncode == 0)}
            checks.append(item)
            metadata["owned_reverse_cleanup"].append(item)
        if forwarded:
            checks.append(cleanup_gadget_forward(adb))
        functional = not failures and bool(checks) and all(x["passed"] for x in checks)
        metadata.update(checks=checks, failures=failures, functional_checks_passed=functional,
                        status="passed" if functional and network["coverage"] == "full" else
                        "partial" if functional else "failed",
                        passed=functional and network["coverage"] == "full")
        (out / "probe-verification.json").write_text(json.dumps(metadata, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"passed": metadata["passed"], "out": str(out), "failures": failures}, ensure_ascii=False))
    return 0 if metadata["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
