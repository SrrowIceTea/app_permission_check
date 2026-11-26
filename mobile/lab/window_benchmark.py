"""Replay the Android ID controls with the mobile correlator. 仅用于授权测试。"""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

from core.privacy.semantics import obtained_reads

ROOT = Path(__file__).resolve().parents[2]
PACKAGE = "com.vscanner.privacydemo"
OBSERVATION = "fixture_native_log"
WINDOWS = (5000, 10000, 30000, 60000, 120000)
STEPS = {"read_only": ("read-a",), "immediate": ("read-a", "send-a"),
         "delayed": ("read-a", "send-a"), "cross_batch": ("read-a", "read-b", "send-a")}
# 后台与断网补传对照（追加，不改旧四组）：步骤里的 wifi_off/wifi_on 是环境动作，不是 Activity 触发。
OFFLINE_STEPS = {
    "bg_read_only": ("bg-read-a",),
    "bg_send": ("bg-read-a", "bg-send-a"),
    "offline_resend": ("bg-read-a", "bg-offline-send-a", "wifi_off", "wifi_on", "bg-flush-a"),
}
INPUTS = ("reads.jsonl", "flows.jsonl", "egress.jsonl", "actor.json", "receipts.json", "steps.json",
          "hook-driver-verification.json", "collector-health.json")
ALL_STEPS = {**STEPS, **OFFLINE_STEPS}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def load(path):
    return json.loads(path.read_text(encoding="utf-8"))


def rows(path):
    with path.open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def save(path, value):
    with path.open("x", encoding="utf-8") as handle:
        json.dump(value, handle, ensure_ascii=False, indent=2)
        handle.write("\n")


def check(condition, message):
    if not condition:
        raise ValueError(message)


def bind_reads(folder, token, pid, steps, actor):
    reads = obtained_reads(rows(folder / "reads.jsonl"), "android_id")
    marks = [row for row in actor if row["event"] == "read"]
    check(len(reads) == len(marks) == len(steps) and len({r["evt_id"] for r in reads}) == len(reads),
          "Android ID 主读取数量或事件编号不符")
    bound = {}
    for step, mark in zip(steps, marks, strict=True):
        batch = step["step"][-1]
        check(mark["batch"] == batch and 0 < mark["start_ms"] <= mark["end_ms"], "读取动作回执失序")
        candidates = [row for row in reads if row.get("session_id") == token and row.get("src") == "privacy"
                      and row.get("hook") == OBSERVATION and row.get("observation_run") == token
                      and row.get("fixture_batch") == batch
                      and row.get("pid") == pid and row.get("value_hash") == mark["value_sha256"][:16]
                      and mark["start_ms"] <= row.get("ts", -1) <= mark["end_ms"]
                      and step["start_ms"] <= row.get("host_received_ts", -1) <= step["end_ms"]]
        check(len(candidates) == 1 and candidates[0] not in bound.values(), "无法唯一绑定读取批次和 Hook 事件")
        bound[batch] = candidates[0]
    return bound


def truth(folder, case, manifest):
    token = manifest["session_id"]
    hook = load(folder / "hook-driver-verification.json")
    check(hook.get("passed") is True and hook.get("package") == PACKAGE and type(hook.get("pid")) is int,
          "采集驱动缺少健康退出记录")
    collector = load(folder / "collector-health.json")
    check(collector.get("session_id") == token and collector.get("status") == "completed"
          and collector.get("errors") == [], "流量采集器缺少健康退出记录")
    events = rows(folder / "reads.jsonl")
    starts = [row for row in events if row.get("ev") == "START" and row.get("src") == "privacy"]
    check(all(row.get("session_id") == token for row in events)
          and len(starts) == 1 and starts[0].get("pkg") == PACKAGE and starts[0].get("pid") == hook["pid"]
          and starts[0].get("whitelist") == [PACKAGE] and starts[0].get("hook") == OBSERVATION
          and any(row.get("ev") == "ARMED" and row.get("src") == "privacy" and row.get("hook") == OBSERVATION
                  for row in events)
          and not any(row.get("ev") in ("SCRIPT_ERROR", "CAPTURE_ERROR") for row in events), "读取会话或 Hook 健康异常")
    steps, actor = load(folder / "steps.json"), load(folder / "actor.json")
    check(tuple(step["step"] for step in steps) == STEPS[case]
          and all(step["start_ms"] <= step["end_ms"] for step in steps)
          and all(left["end_ms"] <= right["start_ms"] for left, right in zip(steps, steps[1:]))
          and all(a.get("run") == token and a.get("pid") == hook["pid"] for a in actor)
          and [a["event"] for a in actor] == [s["step"].split("-")[0] for s in steps], "动作记录或 APK 进程不一致")
    bound = bind_reads(folder, token, hook["pid"], [s for s in steps if s["step"].startswith("read-")], actor)
    flows = rows(folder / "flows.jsonl")
    receipts = load(folder / "receipts.json")
    if case == "read_only":
        check(not flows and not receipts, "只读负控存在实际请求")
        return bound, set(), set(), {}
    check(len(flows) == len(receipts) == 1, "发送轮须有一条归因流及独立回执")
    flow, receipt, action = flows[0], receipts[0], actor[-1]
    raw = (folder / "body.bin").read_bytes()
    checksum, body = sha(raw), json.loads(raw)
    payload = flow["request_payload"]
    check(body["run"] == token and body["source_batch"] == "a" == action["batch"]
          and receipt["sha256"] == action["body_sha256"] == payload["raw_sha256"] == checksum
          and sha(payload["text"].encode()) == checksum and sha(body["android_id"].encode())[:16] == bound["a"]["value_hash"]
          and receipt["status"] == flow["status_code"] == action["http_status"] == 200
          and receipt["path"] == flow["path"] == "/collect" and flow["method"] == "POST"
          and flow.get("session_id") == token and flow.get("package") == PACKAGE
          and flow.get("host") == "127.0.0.1" and flow.get("attribution") == "single_package_fallback"
          and steps[-1]["start_ms"] <= receipt["received_ms"] <= steps[-1]["end_ms"], "收件正文、动作和代理原始流不一致")
    flow_ms = flow.get("host_received_ts") if flow.get("host_received_ts") is not None else flow["ts"]
    deltas = {batch: flow_ms - read["host_received_ts"] for batch, read in bound.items()}
    check(0 < deltas["a"] < 5000 if case == "immediate" else 30000 < deltas["a"] < 60000,
          "实测延迟不在预定的短/长对照范围")
    if case == "cross_batch":
        check(bound["a"]["value_hash"] == bound["b"]["value_hash"] and 0 < deltas["b"] < 5000,
              "同值不同批负控未成立")
    positive = {(bound["a"]["src"], bound["a"]["evt_id"], flow["src"], flow["evt_id"])}
    negative = {(bound["b"]["src"], bound["b"]["evt_id"], flow["src"], flow["evt_id"])} if "b" in bound else set()
    return bound, positive, negative, {"receipt_ms": receipt["received_ms"], "delays_ms": deltas,
                                       "collector_attribution": flow["attribution"]}


def pairs_from(path):
    return {(p["read_src"], p["read_event_id"], p["flow_src"], p["flow_event_id"])
            for row in rows(path) if row.get("data_type") == "android_id"
            and row.get("evidence_kind") == "read_then_egress" for p in row["pairs"]
            if p["content_match_basis"] == "value_hash_in_payload"}


def replay(source, out):
    suite = load(source / "suite.json")
    rules = source / "rules.db"
    check(suite["package"] == PACKAGE and suite["rules_sha256"] == sha(rules.read_bytes())
          and suite["hook_sha256"] == sha((source / "hook.bundle.js").read_bytes()), "规则库、Hook 或 APK 范围不符")
    check(set(suite["cases"]) == set(STEPS) and len(set(suite["cases"].values())) == len(STEPS), "四组须使用独立的会话")
    out.mkdir(parents=True, exist_ok=False)
    case_results = {}
    for case, token in suite["cases"].items():
        folder = source / case
        manifest_file = folder / "manifest.json"
        manifest = load(manifest_file)
        required = set(INPUTS) | ({"body.bin"} if case != "read_only" else set())
        check(manifest["session_id"] == token and manifest["apk_sha256"] == suite["apk_sha256"]
              and manifest["hook_sha256"] == suite["hook_sha256"]
              and manifest["passed"] is True and set(manifest["sha256"]) == required
              and all(sha((folder / name).read_bytes()) == checksum for name, checksum in manifest["sha256"].items()),
              "采集身份、健康记录或原始文件摘要不一致")
        reads, positive, negative, timing = truth(folder, case, manifest)
        results = []
        for ms in WINDOWS:
            findings = out / f"{case}-{ms}-findings.jsonl"
            command = [sys.executable, str(ROOT / "mobile/analyze/correlate_mobile.py"), "--session", str(folder),
                       "--package", PACKAGE, "--rules", str(rules), "--device-api", str(suite["device_api"]),
                       "--window-override-ms", str(ms), "--out", str(findings),
                       "--summary", str(out / f"{case}-{ms}-summary.json")]
            done = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, encoding="utf-8", timeout=60)
            (out / f"{case}-{ms}.log").write_text(done.stdout + done.stderr, encoding="utf-8")
            check(done.returncode == 0, f"移动关联器失败，查看 {case}-{ms}.log")
            actual = pairs_from(findings)
            results.append({"window_ms": ms, "true_positive": len(actual & positive),
                            "false_negative": len(positive - actual), "cross_batch": len(actual & negative),
                            "outside_reference": len(actual - positive - negative),
                            "matched_pairs": [list(pair) for pair in sorted(actual)]})
        case_results[case] = {"session_id": token, "manifest_sha256": sha(manifest_file.read_bytes()),
                              "read_ids": {batch: row["evt_id"] for batch, row in reads.items()},
                              "reference_positive": sorted(positive), "reference_negative": sorted(negative),
                              "receipt_and_delays": timing, "windows": results}
    check(suite["rules_sha256"] == sha(rules.read_bytes()), "重放期间规则库摘要变化")
    report = {"status": "passed", "sample_origin": "owned_fixture", "independent_app_cases": 0,
              "read_observation": OBSERVATION,
              "hook_sha256": suite["hook_sha256"],
              "rules_sha256": suite["rules_sha256"], "apk_sha256": suite["apk_sha256"], "cases": case_results}
    save(out / "verification.json", report)
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    arguments = parser.parse_args(argv)
    try:
        replay(arguments.source.resolve(), arguments.out.resolve())
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        print(f"mobile_window_replay_failed: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
