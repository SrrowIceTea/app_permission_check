"""后台读取与断网补传对照的判据与五档重放。仅用于授权测试。

旧四组 truth()/replay() 保持不动；本模块校验新增三组的后台来源、断网区间
零回执、缓存批次令牌绑定，并复用移动关联器重放五档窗口。
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from core.privacy.semantics import obtained_reads
from mobile.lab.window_benchmark import (
    OFFLINE_STEPS, ROOT, WINDOWS, check, load, pairs_from, rows, save, sha,
)

OBSERVATION = "fixture_native_log"
PACKAGE = "com.vscanner.privacydemo"


def _read_events(folder, token):
    events = rows(folder / "reads.jsonl")
    starts = [r for r in events if r.get("ev") == "START" and r.get("src") == "privacy"]
    check(all(r.get("session_id") == token for r in events) and len(starts) == 1
          and not any(r.get("ev") in ("SCRIPT_ERROR", "CAPTURE_ERROR") for r in events),
          "读取会话健康异常")
    return obtained_reads(events, "android_id")


def truth_offline(folder, case, manifest):
    token = manifest["session_id"]
    hook = load(folder / "hook-driver-verification.json")
    check(hook.get("passed") is True and hook.get("package") == PACKAGE, "采集驱动健康异常")
    collector = load(folder / "collector-health.json")
    check(collector.get("session_id") == token and collector.get("status") == "completed"
          and collector.get("errors") == [], "流量采集器健康异常")
    steps, actor = load(folder / "steps.json"), load(folder / "actor.json")
    check(tuple(s["step"] for s in steps) == OFFLINE_STEPS[case], "后台对照组步骤失序")
    reads = _read_events(folder, token)
    read_marks = [a for a in actor if a["event"] == "read"]
    check(len(reads) == len(read_marks) == 1, "后台对照须恰好一条主读取")
    mark, read = read_marks[0], reads[0]
    check(mark.get("origin") == "background" and mark.get("thread", "").startswith("owned-bg-read")
          and read.get("fixture_origin") == "background"
          and read.get("fixture_thread", "").startswith("owned-bg-read")
          and read.get("value_hash") == mark["value_sha256"][:16], "后台读取来源或值哈希不符")
    env = [a for a in actor if a["event"] in ("enqueue", "offline_failed", "flush_start", "flush_send", "flush_done")]
    receipts = load(folder / "receipts.json")
    flows = rows(folder / "flows.jsonl")
    if case == "bg_read_only":
        check(not flows and not receipts, "后台只读负控存在外发")
        return {read["evt_id"]}, set(), {}, {}
    if case == "bg_send":
        check(len(flows) == len(receipts) == 1 and not env, "后台即时发送须一条流一条回执且无入队")
        flow, receipt, action = flows[0], receipts[0], [a for a in actor if a["event"] == "send"][0]
        raw = (folder / "body-0.bin").read_bytes()
        body = json.loads(raw)
        check(body["run"] == token and body["source_batch"] == "a" and body.get("origin") == "background"
              and sha(body["android_id"].encode())[:16] == read["value_hash"]
              and receipt["sha256"] == flow["request_payload"]["raw_sha256"] == sha(raw)
              and receipt["status"] == flow["status_code"] == action["http_status"] == 200
              and flow.get("session_id") == token and flow.get("package") == PACKAGE,
              "后台发送正文、回执或归因不一致")
        positive = {(read["src"], read["evt_id"], flow["src"], flow["evt_id"])}
        return {read["evt_id"]}, positive, {}, {}
    # offline_resend：断网失败入队 → 恢复后补传，恰好一条回执带批次令牌。
    check(any(a["event"] == "enqueue" and a["cached_batches"] == 1 for a in actor)
          and any(a["event"] == "offline_failed" for a in actor)
          and any(a["event"] == "flush_start" and a["cached_batches"] == 1 for a in actor)
          and any(a["event"] == "flush_send" for a in actor)
          and any(a["event"] == "flush_done" for a in actor), "断网入队或补传动作缺失")
    offline_env = load(folder / "offline-window.json")
    o_start, o_end = offline_env["offline_start_ms"], offline_env["online_confirmed_ms"]
    check(o_start < o_end and not any(o_start <= r["received_ms"] < o_end for r in receipts),
          "断网区间出现接收端回执")
    check(len(flows) == len(receipts) == 1, "补传须恰好一条归因流与独立回执")
    raw = (folder / "body-0.bin").read_bytes()
    body, receipt, flow = json.loads(raw), receipts[0], flows[0]
    check(body["run"] == token and body["source_batch"] == "a"
          and sha(body["android_id"].encode())[:16] == read["value_hash"]
          and body.get("source_batch_tokens") == ["a"]
          and receipt["sha256"] == flow["request_payload"]["raw_sha256"] == sha(raw)
          and sha(flow["request_payload"]["text"].encode()) == sha(raw)
          and receipt["status"] == flow["status_code"] == 200
          and receipt["path"] == flow["path"] == "/collect"
          and flow.get("session_id") == token and flow.get("package") == PACKAGE
          and o_end <= receipt["received_ms"], "补传正文、批次令牌或回执不一致")
    positive = {(read["src"], read["evt_id"], flow["src"], flow["evt_id"])}
    timing = {"receipt_ms": receipt["received_ms"],
              "offline_interval_ms": o_end - o_start,
              "source_batch_tokens": body["source_batch_tokens"]}
    return {read["evt_id"]}, positive, timing, {}


def replay_offline(source, out):
    suite = load(source / "suite.json")
    rules = source / "rules.db"
    check(suite["package"] == PACKAGE and suite["rules_sha256"] == sha(rules.read_bytes())
          and suite["hook_sha256"] == sha((source / "hook.bundle.js").read_bytes()), "规则库或 Hook 范围不符")
    check(set(suite["cases"]) == set(OFFLINE_STEPS)
          and len(set(suite["cases"].values())) == len(OFFLINE_STEPS), "后台对照组须独立会话")
    out.mkdir(parents=True, exist_ok=False)
    results = {}
    for case, token in suite["cases"].items():
        folder, manifest_file = source / case, source / case / "manifest.json"
        manifest = load(manifest_file)
        required = set(OFFLINE_INPUTS) - {"offline-window.json"}
        if case == "offline_resend":
            required.add("offline-window.json")
        if case != "bg_read_only":
            required.add("body.bin")
        check(manifest["session_id"] == token and manifest["apk_sha256"] == suite["apk_sha256"]
              and manifest["hook_sha256"] == suite["hook_sha256"] and manifest["passed"] is True
              and set(manifest["sha256"]) == required
              and all(sha((folder / n).read_bytes()) == c for n, c in manifest["sha256"].items()),
              "采集身份或原始文件摘要不一致")
        reads, positive, timing = truth_offline(folder, case, manifest)[:3]
        windows = []
        for ms in WINDOWS:
            findings = out / f"{case}-{ms}-findings.jsonl"
            cmd = [sys.executable, str(ROOT / "mobile/analyze/correlate_mobile.py"),
                   "--session", str(folder), "--package", PACKAGE, "--rules", str(rules),
                   "--device-api", str(suite["device_api"]), "--window-override-ms", str(ms),
                   "--out", str(findings), "--summary", str(out / f"{case}-{ms}-summary.json")]
            done = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, encoding="utf-8", timeout=60)
            (out / f"{case}-{ms}.log").write_text(done.stdout + done.stderr, encoding="utf-8")
            check(done.returncode == 0, f"关联器失败: {case}-{ms}")
            actual = pairs_from(findings)
            windows.append({"window_ms": ms, "true_positive": len(actual & positive),
                            "false_negative": len(positive - actual),
                            "outside_reference": len(actual - positive)})
        results[case] = {"session_id": token, "read_ids": sorted(reads), "timing": timing, "windows": windows}
    report = {"status": "passed", "sample_origin": "owned_fixture", "read_observation": OBSERVATION,
              "independent_app_cases": 0, "hook_sha256": suite["hook_sha256"],
              "rules_sha256": suite["rules_sha256"], "apk_sha256": suite["apk_sha256"], "cases": results}
    save(out / "verification.json", report)
    return report


OFFLINE_INPUTS = ("reads.jsonl", "flows.jsonl", "egress.jsonl", "actor.json", "receipts.json", "steps.json",
                  "hook-driver-verification.json", "collector-health.json", "offline-window.json")


def main(argv=None):
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        replay_offline(args.source.resolve(), args.out.resolve())
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        print(f"mobile_offline_replay_failed: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
