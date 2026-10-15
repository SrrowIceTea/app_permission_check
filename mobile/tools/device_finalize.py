"""Evidence, report and run manifest; failed and partial attempts are retained."""
from __future__ import annotations

import hashlib
import json
import os
import re
import sys
from pathlib import Path

from device_capture import run
from device_actions import check_cancel
from device_environment import MOBILE, PKG, ROOT
from device_provenance import capabilities

PY = sys.executable


def permission_snapshot(adb, out: Path, label: str) -> str:
    result = adb("shell", "dumpsys", "package", PKG, timeout=90)
    text = result.stdout + "\n--- stderr ---\n" + result.stderr
    (out / f"permissions-{label}.txt").write_text(text, encoding="utf-8")
    return result.stdout


def requested_permissions(dump: str) -> list[str]:
    """Read only the declaration block, never install/runtime granted-state entries."""
    permissions = set()
    block_indent = None
    for raw in dump.expandtabs().splitlines():
        text = raw.strip()
        if not text:
            continue
        indent = len(raw) - len(raw.lstrip())
        if text == "requested permissions:":
            block_indent = indent
            continue
        if block_indent is None:
            continue
        if indent <= block_indent:
            block_indent = None
            continue
        # dumpsys prints one bare fully-qualified declared permission per line.
        # State lines have ': granted=...' and are deliberately not accepted.
        if re.fullmatch(r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+", text):
            permissions.add(text)
    return sorted(permissions)


def atomic_text(path: Path, text: str) -> None:
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(text, encoding="utf-8")
    os.replace(temporary, path)


def write_json(path: Path, data: dict) -> None:
    atomic_text(path, json.dumps(data, ensure_ascii=False, indent=2))


def bind_runtime(bundle_path: Path, args, profile: dict, capture_checks: list) -> dict:
    """Optional runtime extension, committed before AI validation/report SHA bindings."""
    bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
    runtime = {"schema_version": 1, "mode": args.mode, "scope": "self-owned-source-fixture",
               "device_profile": profile, "capabilities": capabilities(args.mode),
               "capture_checks": [dict(item) for item in capture_checks],
               "capture_failed": [item["name"] for item in capture_checks
                                  if item.get("exit_code") != 0 and not item.get("optional")],
               "stage": "capture_completed_or_failed (not entire pipeline verification)"}
    driver_record = bundle_path.parent.parent / "session/hook-driver-verification.json"
    if driver_record.exists():
        runtime["hook_driver"] = json.loads(driver_record.read_text(encoding="utf-8"))
    bundle["runtime"] = runtime
    notes = ["[runtime] 自有源码夹具验收不证明任意第三方 APK 可注入；政策接受状态仍未知。",
             "[runtime] attach 前的启动阶段未覆盖；零事件不能证明启动期间没有读取。"]
    if args.mode == "gadget":
        notes.append("[runtime] shell/app UID 非 0 只证明本轮未升权路径；不是设备绝无 su 或量产安全性证明。")
        if profile.get("ro.build.type") != "user" or profile.get("ro.debuggable") != "0":
            notes.append("[runtime] userdebug/可调试镜像只是受限非 root 模拟，不是锁定量产 user 设备实测。")
    if runtime["capture_failed"]:
        notes.append("[runtime] 本轮采集存在失败检查，不能视为完整设备验收：" +
                     ", ".join(runtime["capture_failed"]))
    bundle["gaps"] = list(bundle.get("gaps") or []) + notes
    text = json.dumps(bundle, ensure_ascii=False, indent=2, sort_keys=True)
    # Keep evidence_bundle.py's existing no-trailing-newline hash convention.
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    atomic_text(bundle_path, text + "\n")
    atomic_text(bundle_path.with_name(bundle_path.name + ".sha256"), digest + "\n")
    sidecar = {**runtime, "ai_requested": not args.skip_ai, "bundle_sha256": digest,
               "bundle_hash_convention": "UTF-8 pretty sorted JSON, no trailing newline",
               "bundle_file_sha256": hashlib.sha256(bundle_path.read_bytes()).hexdigest()}
    write_json(bundle_path.parent / "run-capabilities.json", sidecar)
    return runtime


def generate_artifacts(adb, args, apk: Path, out: Path, checks: list, profile: dict):
    capture_checks = [dict(item) for item in checks]
    target, session = out / "out", out / "session"
    target.mkdir(exist_ok=True)
    check_cancel(args)
    dump = permission_snapshot(adb, out, "after")
    check_cancel(args)
    permissions = requested_permissions(dump)
    permission_file = target / "requested-permissions.txt"
    permission_file.write_text("\n".join(permissions) + "\n", encoding="utf-8")
    checks.append({"name": "requested_permissions_nonempty", "exit_code": 0 if permissions else 1,
                   "source": "dumpsys requested permissions declaration block",
                   "declared_count": len(permissions)})

    def check(name, command, timeout=600, optional=False):
        check_cancel(args)
        code = run(command, out / f"{name}.log", timeout=timeout, env=adb.environment())
        checks.append({"name": name, "exit_code": code, "optional": optional})
        check_cancel(args)
        return code

    policy = target / "policy"
    check("policy_from_apk", [PY, str(MOBILE / "policy/policy_fetch.py"),
                              "--from-apk", str(apk), "--store", str(policy), "--tag", "apk"],
          optional=True)
    correlate = [PY, str(MOBILE / "analyze/correlate_mobile.py"), "--session", str(session),
                 "--package", PKG, "--permissions", str(permission_file),
                 "--app-category", args.app_category, "--policy-store", str(policy),
                 "--out", str(target / "findings.jsonl"), "--summary", str(target / "summary.json")]
    if check("correlate", correlate):
        return
    bundle = [PY, str(MOBILE / "ai/evidence_bundle.py"), "--session", str(session),
              "--findings", str(target / "findings.jsonl"), "--package", PKG,
              "--app-category", args.app_category, "--policy-store", str(policy),
              "--apk-sha256", hashlib.sha256(apk.read_bytes()).hexdigest(),
              "--device", profile.get("ro.build.fingerprint") or "unknown-device",
              "--out", str(target / "bundle.json")]
    if check("bundle", bundle):
        return
    check_cancel(args)
    bind_runtime(target / "bundle.json", args, profile, capture_checks)
    ai = target / "ai"
    if not args.skip_ai:
        check("ai_review", [PY, str(MOBILE / "ai/ai_review.py"), "--bundle", str(target / "bundle.json"),
                            "--out-dir", str(ai)], timeout=1800)
    if getattr(args, "skip_report", False):
        return  # Workbench publishes its own task-bound report as a separate operation.
    report = [PY, str(MOBILE / "report/report_mobile.py"), "--bundle", str(target / "bundle.json"),
              "--session", out.name, "--out", str(target / "mobile-report.pdf")]
    if ai.exists():
        report += ["--ai-out-dir", str(ai)]
    check("report", report)


def finish(out: Path, checks: list, metadata: dict) -> int:
    failed = [item["name"] for item in checks if item.get("exit_code") != 0 and not item.get("optional")]
    optional_failed = [item["name"] for item in checks
                       if item.get("exit_code") != 0 and item.get("optional")]
    data = {**metadata, "passed": not failed, "checks": checks, "failed": failed,
            "optional_failed": optional_failed, "package": PKG, "session": out.name,
            "failure_artifacts_retained": True}
    write_json(out / "verification.json", data)
    # Points to the latest attempt, not to a success claim; always inspect verification.json.
    (ROOT / "output/latest-mobile-device.txt").write_text(str(out), encoding="utf-8")
    print(json.dumps({"status": "passed" if not failed else "failed", "out": str(out),
                      "mode": metadata["mode"], "checks": len(checks), "failed": failed},
                     ensure_ascii=False, indent=2))
    return 1 if failed else 0
