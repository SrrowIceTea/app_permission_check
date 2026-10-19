"""Incremental host-only audit of official domestic APKs. 仅用于授权本地静态分析，不安装运行。"""
from __future__ import annotations
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time
import zipfile
from core.static import analysis, toolchain
from mobile.analyze.risk_rating import assess_risk

ROOT = Path(__file__).resolve().parents[2]
FLAGS = {"debuggable": "debuggable", "usesCleartextTraffic": "uses_cleartext_traffic", "allowBackup": "allow_backup"}
IDENTIFIER = re.compile(r"^[A-Za-z0-9_-]{1,160}$")


def now():
    return datetime.now(timezone.utc).isoformat()


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(path.name + ".tmp")
    temp.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temp.replace(path)


def parse_manifest_flags(xmltree):
    """Only application attributes: missing/resource-valued flags remain unknown."""
    values = {key: None for key in FLAGS.values()}
    details = {key: {"state": "not_explicit"} for key in values}
    apps = [(index, len(match.group(1))) for index, line in enumerate(xmltree.splitlines())
            if (match := re.match(r"^(\s*)E: application\b", line))]
    if len(apps) != 1:
        return values, details, [{"kind": "application_node_unavailable", "count": len(apps)}]
    start, depth = apps[0]
    for line in xmltree.splitlines()[start + 1:]:
        if re.match(r"^\s*E:", line):
            break  # Attributes of activity/service descendants are not application properties.
        match = re.match(r"^(\s*)A: (?:android:|http://schemas.android.com/apk/res/android:)([A-Za-z]+)(?:\(0x[0-9a-fA-F]+\))?=(.*)$", line)
        if not match or len(match.group(1)) <= depth or match.group(2) not in FLAGS:
            continue
        key, raw = FLAGS[match.group(2)], match.group(3).strip()
        typed = re.sub(r"^\(type 0x12\)", "", raw).strip().lower()
        value = True if typed in ("true", "0xffffffff", "0x1", "1", "-1") else False if typed in ("false", "0x0", "0x00000000", "0") else None
        values[key] = value
        details[key] = {"state": "explicit" if value is not None else "unresolved", "raw": raw}
    unknown = [key for key, value in values.items() if value is None]
    gaps = [{"kind": "manifest_flags_unknown", "attributes": unknown,
             "detail": "未显式声明或值无法解析；未推断系统默认值及资源引用"}] if unknown else []
    return values, details, gaps


def scan_worker(apk, folder, rules_version):
    folder.mkdir(parents=True, exist_ok=True)
    proc = subprocess.run([toolchain.android_build_tool("aapt2"), "dump", "xmltree", "--file",
                           "AndroidManifest.xml", str(apk)], capture_output=True, text=True,
                          encoding="utf-8", errors="replace", timeout=30)
    (folder / "manifest-xmltree.txt").write_text(proc.stdout + proc.stderr, encoding="utf-8")
    if proc.returncode:
        flags, details, gaps = ({key: None for key in FLAGS.values()}, {},
                               [{"kind": "manifest_xmltree_failed", "detail": proc.stderr[-500:]}])
    else:
        flags, details, gaps = parse_manifest_flags(proc.stdout)
    save(folder / "manifest-flags.json", {"values": flags, "details": details, "gaps": gaps})
    raw = analysis.scan_static(apk, ROOT / "mobile/rules/rules_mobile.db", rules_version, folder)
    with zipfile.ZipFile(apk) as archive:
        dex_names = sorted(name for name in archive.namelist() if re.fullmatch(r"classes\d*\.dex", name))
    facts = json.loads((folder / "dexfacts.json").read_text(encoding="utf-8"))
    dex_gaps = raw.get("dex_gaps", [])
    covered = set(facts.get("per_dex_lines", {}))
    if set(dex_names) != covered:
        dex_gaps = [*dex_gaps, {"kind": "dex_coverage_incomplete", "expected": dex_names, "parsed": sorted(covered)}]
    return {"state": "partial" if dex_gaps or raw.get("apk_gaps") else "done",
            "whole_dex_scanned": not dex_gaps, "dex_count": len(dex_names), "dex_names": dex_names,
            "parsed_dex_names": sorted(covered), "rules_evaluated": raw.get("rules_evaluated"),
            "permissions": raw.get("apk", {}).get("permissions", []), "apk": raw.get("apk", {}),
            "candidate_count": len(raw.get("findings", [])), "findings": raw.get("findings", []),
            "unhandled_rule_types": raw.get("unhandled_rule_types", []),
            "manifest_flags": flags, "manifest_flag_details": details,
            "gaps": [*raw.get("apk_gaps", []), *dex_gaps, *gaps,
                     {"kind": "static_rule_scope", "unhandled_rule_types": raw.get("unhandled_rule_types", []),
                      "detail": "规则库被遍历；动态与政策类谓词未由静态扫描执行，候选不等于泄露"}],
            "decompile": {"state": "not_run"}}


def ready_entries(manifest):
    entries = json.loads(manifest.read_text(encoding="utf-8-sig"))
    if not isinstance(entries, list):
        raise ValueError("corpus manifest must be an array")
    ready = [entry for entry in entries if entry.get("download_status") == "downloaded"
             and entry.get("artifact_checks", {}).get("signature") is True]
    ids = [entry.get("sample_id") for entry in ready]
    if any(not isinstance(sid, str) or not IDENTIFIER.fullmatch(sid) for sid in ids) or len(ids) != len(set(ids)):
        raise ValueError("invalid or duplicate sample ID")
    return ready


def run_worker(apk, folder, rules_version, timeout):
    folder.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    command = [sys.executable, "-m", "mobile.lab.domestic_static", "--worker", str(apk),
               "--out", str(folder), "--rules-version", rules_version]
    kwargs = {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP} if os.name == "nt" else {"start_new_session": True}
    proc = subprocess.Popen(command, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, encoding="utf-8", errors="replace", **kwargs)
    timed_out = False
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        if os.name == "nt":
            subprocess.run(["taskkill", "/PID", str(proc.pid), "/T", "/F"], capture_output=True, timeout=20)
        else:
            os.killpg(proc.pid, signal.SIGKILL)
        stdout, stderr = proc.communicate(timeout=20)
    (folder / "stdout.log").write_text(stdout, encoding="utf-8")
    (folder / "stderr.log").write_text(stderr, encoding="utf-8")
    save(folder / "worker-exit.json", {"exit_code": proc.returncode, "timeout_seconds": timeout,
                                      "timed_out": timed_out, "elapsed_seconds": round(time.monotonic() - started, 3)})
    result = folder / "worker-result.json"
    flag_path = folder / "manifest-flags.json"
    flags = json.loads(flag_path.read_text(encoding="utf-8")) if flag_path.exists() else {}
    if timed_out:
        return {"state": "failed", "whole_dex_scanned": False, "candidate_count": None,
                "manifest_flags": flags.get("values", {}), "manifest_flag_details": flags.get("details", {}),
                "gaps": [{"kind": "static_timeout", "detail": f"单 APK 静态扫描超过 {timeout} 秒"}, *flags.get("gaps", [])]}
    if proc.returncode or not result.exists():
        return {"state": "failed", "whole_dex_scanned": False, "candidate_count": None,
                "manifest_flags": flags.get("values", {}), "manifest_flag_details": flags.get("details", {}),
                "gaps": [{"kind": "static_worker_failed", "detail": stderr[-1000:]}, *flags.get("gaps", [])]}
    return json.loads(result.read_text(encoding="utf-8"))


def scan_entry(entry, corpus, out, rules_version, timeout, worker=run_worker):
    sid = entry["sample_id"]
    folder = out / "samples" / sid
    previous = folder / "result.json"
    if previous.exists():
        result = json.loads(previous.read_text(encoding="utf-8"))
        if result.get("apk_sha256") != entry.get("sha256"):
            raise ValueError(f"{sid}: a different APK already has saved evidence; use a new batch")
        return result
    started = now()
    folder.mkdir(parents=True, exist_ok=True)
    try:
        apk = Path(entry["apk_path"]).resolve()
        if not apk.is_relative_to(corpus.resolve()) or not apk.is_file():
            raise ValueError("APK is not a file inside the selected corpus")
        with apk.open("rb") as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
        if digest != entry.get("sha256"):
            raise ValueError("APK SHA256 no longer matches signed corpus inventory")
        static = worker(apk, folder / "static", rules_version, timeout)
        actual_package = static.get("apk", {}).get("package")
        if actual_package and actual_package != entry.get("package"):
            raise ValueError("static package identity differs from corpus inventory")
    except Exception as error:
        static = {"state": "failed", "whole_dex_scanned": False, "candidate_count": None,
                  "gaps": [{"kind": "static_input_failed", "detail": str(error)}]}
    stages = {name: {"state": "not_run", "reason": "本批次仅做主机静态分析，未安装或运行应用"}
              for name in ("install", "launch", "trigger", "observe")}
    stages["static"] = {"state": static["state"]}
    result = {"sample_id": sid, "dataset": "国内真实应用观察集", "case_id": entry.get("name", sid),
              "variant": entry.get("version_name"), "package": entry.get("package"), "version_name": entry.get("version_name"),
              "version_code": entry.get("version_code"), "target_sdk": entry.get("target_sdk"),
              "min_sdk": static.get("apk", {}).get("min_sdk", entry.get("min_sdk")),
              "apk_sha256": entry.get("sha256"), "source_url": entry.get("source_url"),
              "official_page": entry.get("official_page"), "domestic_basis": entry.get("domestic_basis"),
              "category": entry.get("category"), "artifact_checks": entry.get("artifact_checks"),
              "original_truth": None, "stages": stages, "event_count": None, "verdict": "not_run",
              "reason": "静态候选与清单配置已单列；动态目标事件未测试，不能据此判断应用无风险",
              "started_at": started, "completed_at": now(), "static_summary": {k: v for k, v in static.items() if k != "findings"},
              "findings": static.get("findings", []), "manifest_flags": static.get("manifest_flags", {}),
              "manifest_flag_details": static.get("manifest_flag_details", {}), "observations": {},
              "gaps": static.get("gaps", []), "evidence_path": f"samples/{sid}/result.json",
              "ai_review": {"status": "not_run", "reason": "国内观察集尚未调用模型研判"}}
    result["risk_assessment"] = assess_risk(result)
    save(previous, result)
    return result


def run_batch(manifest, out, rules_version="36", timeout=120, jobs=2, sample_ids=None):
    manifest, out = manifest.resolve(), out.resolve()
    if not out.is_relative_to((ROOT / "output").resolve()) or not out.name.startswith("root-benchmark-"):
        raise ValueError("output must be a root-benchmark-* directory inside project output")
    entries = ready_entries(manifest)
    if sample_ids:
        unknown = set(sample_ids) - {entry["sample_id"] for entry in entries}
        if unknown:
            raise ValueError(f"requested samples are not verified corpus entries: {sorted(unknown)}")
        entries = [entry for entry in entries if entry["sample_id"] in sample_ids]
    out.mkdir(parents=True, exist_ok=True)
    path = out / "batch.json"
    batch = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {
        "schema_version": 1, "batch_id": out.name, "created_at": now(),
        "environment": {"mode": "host-static-analysis-only", "root": None, "device_execution": False,
                        "apk_modified": False, "rules_android_version": rules_version},
        "dataset": {"name": "国内真实应用观察集", "manifest": str(manifest), "ground_truth": "not_provided"}, "samples": []}
    batch.update(status="running", planned_sample_count=len(entries))
    indexed = {sample["sample_id"]: sample for sample in batch["samples"]}
    save(path, batch)
    with ThreadPoolExecutor(max_workers=jobs) as pool:
        tasks = {pool.submit(scan_entry, entry, manifest.parent, out, rules_version, timeout): entry for entry in entries}
        for task in as_completed(tasks):
            result = task.result()
            indexed[result["sample_id"]] = result
            batch["samples"] = sorted(indexed.values(), key=lambda item: item["sample_id"])
            save(path, batch)
            print(json.dumps({"sample_id": result["sample_id"], "static": result["stages"]["static"]["state"],
                              "score": result["risk_assessment"]["score"], "candidates": result["static_summary"].get("candidate_count")}), flush=True)
    batch.update(status="completed", completed_at=now())
    save(path, batch)
    return batch


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=ROOT / "output/domestic-apk-corpus-20261018/manifest.json")
    parser.add_argument("--out", type=Path, default=ROOT / "output/root-benchmark-domestic-20261018")
    parser.add_argument("--worker", type=Path)
    parser.add_argument("--rules-version", default="36")
    parser.add_argument("--timeout", type=int, default=120)
    parser.add_argument("--jobs", type=int, choices=(1, 2), default=2)
    parser.add_argument("--sample", action="append", help="Verified corpus sample ID; repeat to select a retry subset")
    args = parser.parse_args()
    if not 1 <= args.timeout <= 1800:
        parser.error("timeout must be between 1 and 1800 seconds")
    if args.worker:
        save(args.out / "worker-result.json", scan_worker(args.worker, args.out, args.rules_version))
    else:
        run_batch(args.manifest, args.out, args.rules_version, args.timeout, args.jobs, args.sample)


if __name__ == "__main__":
    main()
