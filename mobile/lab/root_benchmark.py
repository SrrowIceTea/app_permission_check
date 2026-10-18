"""Run pinned real APKs on one root emulator, retain all failures. 仅用于授权测试。

python -m mobile.lab.root_benchmark --serial emulator-5562 --authorize-benchmarks
Only the original Ghera Benign/Secure APKs are selected, never attack APKs.
"""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sys
import time
import frida
from mobile.lab.root_assessment import summarize
from mobile.lab.root_cases import ROOT, COMMIT, selected
from mobile.lab.root_runtime import Android, Observer, Capture, save
from mobile.lab.root_static import scan
from mobile.lab.root_triggers import TLSSink, trigger
from mobile.tools.device_environment import resolve_adb


def now():
    return datetime.now(timezone.utc).isoformat()


def sample_run(android, remote, spec, out, bundle, batch_id, jadx):
    folder = out / "samples" / spec["sample_id"]
    folder.mkdir(parents=True)
    android.folder, android.sequence = folder, 0
    result = {**spec, "stages": {name: {"state": "not_run"} for name in
              ("static", "install", "launch", "trigger", "observe")}, "event_count": None,
              "findings": [], "verdict": "not_run", "reason": "Not started",
              "evidence_path": f"samples/{spec['sample_id']}/result.json", "started_at": now()}
    installed, observer, capture, sink = False, None, None, None
    stage, oracle = "static", {}
    session_id = batch_id + ":" + spec["sample_id"]
    try:
        result["static_summary"] = scan(spec, folder / "static", jadx)
        result["stages"]["static"] = {"state": "done"}
        stage = "install"
        if "package:" in android.shell("pm", "path", spec["package"], check=False):
            raise RuntimeError("refusing to replace an existing package; use a dedicated clean emulator")
        install = android.call("install", "-g", spec["apk"], timeout=120)
        if "Success" not in install:
            raise RuntimeError("APK installer did not confirm success")
        installed = True
        # Check the installed file is the unchanged upstream APK, not a fixture/variant substitute.
        package_path = android.shell("pm", "path", spec["package"]).strip().splitlines()[0].removeprefix("package:")
        installed_bytes = android.call("exec-out", "cat", package_path, binary=True)
        if hashlib.sha256(installed_bytes).hexdigest() != spec["apk_sha256"]:
            raise RuntimeError("installed APK identity differs from the upstream sample")
        result["stages"]["install"] = {"state": "done", "original_apk_verified": True}
        stage = "launch"
        if spec["kind"] == "tls":
            sink = TLSSink(folder, spec["canary"])
            sink.start()
        if spec["kind"] in {"socket", "tls"}:
            capture = Capture(android, folder, spec["sample_id"] + "-" + str(time.time_ns()), "any")
        observer = Observer(remote, spec["package"], bundle, folder, session_id)
        pid = observer.start()
        result["pid"] = pid
        result["stages"]["launch"] = {"state": "done", "bootstrap": "spawn_attach_load_resume"}
        stage = "trigger"
        oracle = trigger(android, spec, folder, pid, sink)
        if not oracle.get("pid_alive"):
            raise RuntimeError("application process died during the benchmark trigger")
        result["stages"]["trigger"] = {"state": "done"}
        stage = "observe"
        time.sleep(.4)
        if capture:
            marker = oracle.get("payload_marker") or spec["canary"]
            oracle["pcap"] = capture.close(marker)
            capture = None
            save(folder / "oracle.json", oracle)
        assessment = summarize(spec, observer.events, oracle, session_id)
        save(folder / "assessment.json", assessment)
        result.update({key: assessment[key] for key in ("findings", "observations", "verdict", "reason")})
        result["stages"]["observe"] = {"state": "done" if assessment["verdict"] == "observed" else "failed"}
        result["event_count"] = len(observer.events)
    except Exception as exc:
        result.update(verdict="failed", reason=f"{type(exc).__name__}: {exc}")
        result["stages"][stage] = {"state": "failed", "reason": result["reason"]}
    finally:
        if capture:
            try:
                oracle["pcap"] = capture.close(spec["canary"])
            except Exception as exc:
                result["capture_cleanup_error"] = str(exc)
        cleanup_errors = []
        if observer:
            try:
                observer.close()
            except Exception as exc:
                cleanup_errors.append("observer close: " + str(exc))
            result["event_count"] = len(observer.events)
            result["observer_errors"] = observer.errors
            probe_errors = [e for e in observer.events if e.get("ev") in
                            {"PROBE_ERROR", "OBSERVATION_ERROR", "SCRIPT_ERROR", "NOT_READY"}]
            if observer.errors or probe_errors:
                cleanup_errors.append("probe/script reported errors; inspect events and observer-errors")
        if sink:
            try:
                sink.close()
            except Exception as exc:
                cleanup_errors.append("TLS sink close: " + str(exc))
        result["cleanup_passed"] = not installed
        if installed:
            try:
                android.shell("am", "force-stop", spec["package"], check=False)
                cleanup = android.call("uninstall", spec["package"], check=False)
                result["cleanup_passed"] = "Success" in cleanup and "package:" not in android.shell(
                    "pm", "path", spec["package"], check=False)
            except Exception as exc:
                cleanup_errors.append("owned package cleanup: " + str(exc))
        if not result["cleanup_passed"]:
            cleanup_errors.append("owned package removal was not confirmed")
        if cleanup_errors:
            result["cleanup_errors"] = cleanup_errors
            result["verdict"] = "failed"
            result["reason"] += "; " + "; ".join(cleanup_errors)
            result["stages"]["observe"] = {"state": "failed", "reason": "; ".join(cleanup_errors)}
        result["completed_at"] = now()
        result["oracle"] = oracle
        save(folder / "result.json", result)
        android.folder = None
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--serial", required=True)
    parser.add_argument("--authorize-benchmarks", action="store_true")
    parser.add_argument("--corpus", type=Path, default=ROOT / "output/benchmark-corpus-20261017/ghera")
    parser.add_argument("--out", type=Path)
    parser.add_argument("--kinds", nargs="+", choices=("ecb", "cbc", "storage", "socket", "tls"))
    parser.add_argument("--frida-port", type=int, default=27043)
    parser.add_argument("--jadx-classpath", help="existing official JADX CLI lib/* classpath")
    parser.add_argument("--java", default=str(Path(os.environ.get("JAVA_HOME", "")) / "bin/java.exe"))
    args = parser.parse_args(argv)
    if not args.authorize_benchmarks:
        parser.error("explicit authorization for the pinned benchmark APKs is required")
    batch_id = "root-benchmark-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    out = (args.out or ROOT / "output" / batch_id).resolve()
    if not out.is_relative_to((ROOT / "output").resolve()) or not out.name.startswith("root-benchmark-") or out.exists():
        parser.error("use a new root-benchmark-* directory inside this checkout's output/")
    cases = selected(args.corpus, args.kinds)
    android = Android(resolve_adb(), args.serial)
    environment = android.profile()
    remote = frida.get_device_manager().add_remote_device(f"127.0.0.1:{args.frida_port}")
    remote.enumerate_processes()  # fail before publishing or installing if the server is absent
    bundle = (ROOT / "mobile/audit/storage_crypto.bundle.js").read_text(encoding="utf-8")
    out.mkdir(parents=True)
    batch = {"schema_version": 1, "batch_id": batch_id, "created_at": now(), "status": "running",
             "environment": environment, "dataset": {"name": "Ghera", "revision": COMMIT},
             "samples": [], "planned_sample_count": len(cases),
             "scope": f"{len(cases)} selected published APKs, not the entire downloaded corpus",
             "ai_state": "not_run", "metrics": "No accuracy/recall claim without adapted ground truth"}
    save(out / "batch.json", batch)
    jadx = (args.java, args.jadx_classpath) if args.jadx_classpath else None
    for spec in cases:
        print("START", spec["sample_id"], flush=True)
        result = sample_run(android, remote, spec, out, bundle, batch_id, jadx)
        # Large per-sample evidence stays in result.json; the dashboard reads only this compact index.
        batch["samples"].append({k: v for k, v in result.items() if k not in {"oracle", "apk", "observer_errors"}})
        save(out / "batch.json", batch)
        print("END", spec["sample_id"], result["verdict"], result["reason"], flush=True)
    batch.update(completed_at=now(), status="completed")
    batch["acceptance"] = {"selected": len(cases), "observed": sum(s["verdict"] == "observed" for s in batch["samples"]),
                           "cleaned": sum(s["cleanup_passed"] for s in batch["samples"])}
    save(out / "batch.json", batch)
    print(json.dumps({"output": str(out), "acceptance": batch["acceptance"]}), flush=True)
    return 0 if batch["acceptance"]["observed"] == len(cases) and batch["acceptance"]["cleaned"] == len(cases) else 1


if __name__ == "__main__":
    raise SystemExit(main())
