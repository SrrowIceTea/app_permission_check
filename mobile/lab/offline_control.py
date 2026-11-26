"""后台读取与断网补传对照的判据与五档重放。仅用于授权测试。

旧四组 truth()/replay() 保持不动；本模块校验新增三组的后台来源、断网可达性、
断网区间零回执、缓存批次令牌绑定，并复用移动关联器重放五档窗口。

断网三段的证据链（缺一不可）：
1. `bg-probe-before` 可达 → 发送前网络正常；
2. `bg-probe-offline` 不可达（且接收端全程在监听）→ 断网真实生效；
3. `bg-probe-after` 可达 → 网络已恢复，补传成功才归因于恢复而非旁路。
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
PROBE_STAGES = ("before", "offline", "after")


def case_inputs(case):
    """采集侧与重放侧共用的封存文件集合，避免两处各算一遍。"""
    names = set(OFFLINE_INPUTS)
    if case != "offline_resend":
        names.discard("offline-window.json")
    if case != "bg_read_only":
        names.add("body.bin")
    return names


def _health(folder, token):
    hook = load(folder / "hook-driver-verification.json")
    check(hook.get("passed") is True and hook.get("package") == PACKAGE
          and type(hook.get("pid")) is int, "采集驱动缺少健康退出记录")
    collector = load(folder / "collector-health.json")
    check(collector.get("session_id") == token and collector.get("status") == "completed"
          and collector.get("errors") == [], "流量采集器缺少健康退出记录")
    events = rows(folder / "reads.jsonl")
    starts = [r for r in events if r.get("ev") == "START" and r.get("src") == "privacy"]
    check(all(r.get("session_id") == token for r in events)
          and len(starts) == 1 and starts[0].get("pkg") == PACKAGE
          and starts[0].get("pid") == hook["pid"]
          and starts[0].get("whitelist") == [PACKAGE]
          and starts[0].get("hook") == OBSERVATION
          and any(r.get("ev") == "ARMED" and r.get("src") == "privacy"
                  and r.get("hook") == OBSERVATION for r in events)
          and not any(r.get("ev") in ("SCRIPT_ERROR", "CAPTURE_ERROR") for r in events),
          "读取会话或 Hook 健康异常")
    return hook, events


def truth_offline(folder, case, manifest):
    token = manifest["session_id"]
    hook, events = _health(folder, token)
    reads = obtained_reads(events, "android_id")
    steps, actor = load(folder / "steps.json"), load(folder / "actor.json")
    check(tuple(s["step"] for s in steps) == OFFLINE_STEPS[case]
          and all(s["start_ms"] <= s["end_ms"] for s in steps)
          and all(left["end_ms"] <= right["start_ms"] for left, right in zip(steps, steps[1:])),
          "后台对照组步骤失序")
    check(all(a.get("run") == token and a.get("pid") == hook["pid"] for a in actor),
          "动作记录与 APK 进程不一致")
    marks = [a for a in actor if a["event"] == "read"]
    check(len(reads) == len(marks) == 1, "后台对照须恰好一条主读取")
    mark, read = marks[0], reads[0]
    check(mark.get("origin") == "background" and str(mark.get("thread") or "").startswith("owned-bg-read")
          and read.get("fixture_origin") == "background"
          and str(read.get("fixture_thread") or "").startswith("owned-bg-read")
          and read.get("value_hash") == mark["value_sha256"][:16], "后台读取来源或值哈希不符")
    flows, receipts = rows(folder / "flows.jsonl"), load(folder / "receipts.json")
    if case == "bg_read_only":
        check(not flows and not receipts, "后台只读负控存在外发")
        return {read["evt_id"]}, set(), {}, {}
    if case == "bg_send":
        check(len(flows) == len(receipts) == 1, "后台即时发送须一条流一条回执")
        check(not [a for a in actor if a["event"] in
                   ("enqueue", "offline_failed", "flush_start", "flush_send", "flush_done")],
              "后台即时发送不应产生入队动作")
        action = [a for a in actor if a["event"] == "send"]
        check(len(action) == 1, "后台即时发送缺动作记录")
        raw = (folder / "body.bin").read_bytes()
        body = json.loads(raw)
        check(body["run"] == token and body["source_batch"] == "a" and body.get("origin") == "background"
              and sha(body["android_id"].encode())[:16] == read["value_hash"]
              and flow_identity(flows[0], token)
              and receipt_binding(receipts[0], flows[0], raw, action[0]), "后台发送正文、回执或归因不一致")
        positive = {(read["src"], read["evt_id"], flows[0]["src"], flows[0]["evt_id"])}
        return {read["evt_id"]}, positive, {}, {}
    return _offline_resend(folder, token, read, steps, actor, flows, receipts)


def _offline_resend(folder, token, read, steps, actor, flows, receipts):
    by = {step["step"]: step for step in steps}
    probes = {a.get("stage"): a for a in actor if a["event"] == "probe"}
    check(set(probes) == set(PROBE_STAGES)
          and probes["before"].get("reachable") is True
          and probes["offline"].get("reachable") is False
          and probes["after"].get("reachable") is True, "断网可达性探针未成立")
    # 顺序由采集编排保证：每个步骤都要等到自己的动作记录落盘才触发下一步，
    # 所以"断网 → 探针不可达 → 发送失败 → 恢复 → 探针可达 → 补传"的先后
    # 由 OFFLINE_STEPS 的顺序 + 逐步骤等待共同成立。这里不再比较设备 ts 与宿主
    # 步骤时间（两套时钟有百毫秒级偏差，跨时钟比大小会假失败）。
    enqueue = [a for a in actor if a["event"] == "enqueue"]
    failed = [a for a in actor if a["event"] == "offline_failed"]
    sent = [a for a in actor if a["event"] == "flush_send"]
    check(len(enqueue) == 1 and enqueue[0]["cached_batches"] == 1, "断网发送未入队或入队条数不为 1")
    check(len(failed) == 1, "断网发送未记录失败")
    check(len(sent) == 1, "补传未恰好发送一次")
    window = load(folder / "offline-window.json")
    o_start, o_end = window["offline_start_ms"], window["online_confirmed_ms"]
    check(by["net_off"]["start_ms"] <= o_start <= by["net_off"]["end_ms"]
          and by["bg-probe-after"]["start_ms"] <= o_end <= by["bg-probe-after"]["end_ms"],
          "断网区间采样点不在状态确认窗口内")
    check(o_start < o_end and not any(o_start <= r["received_ms"] < o_end for r in receipts),
          "断网区间出现接收端回执")
    check(len(flows) == len(receipts) == 1, "补传须恰好一条归因流与独立回执")
    raw = (folder / "body.bin").read_bytes()
    body, receipt, flow = json.loads(raw), receipts[0], flows[0]
    check(body["run"] == token and body["source_batch"] == "a"
          and sha(body["android_id"].encode())[:16] == read["value_hash"]
          and body.get("source_batch_tokens") == ["a"]
          and flow_identity(flow, token)
          and receipt_binding(receipt, flow, raw, sent[0])
          and flow.get("host") in ("127.0.0.1", "10.0.2.2")
          and o_end <= receipt["received_ms"], "补传正文、批次令牌或回执不一致")
    positive = {(read["src"], read["evt_id"], flow["src"], flow["evt_id"])}
    timing = {"receipt_ms": receipt["received_ms"], "offline_interval_ms": o_end - o_start,
              "source_batch_tokens": body["source_batch_tokens"]}
    return {read["evt_id"]}, positive, timing, {}


def flow_identity(flow, token):
    return flow.get("session_id") == token and flow.get("package") == PACKAGE


def receipt_binding(receipt, flow, raw, action):
    payload = flow["request_payload"]
    return (receipt["sha256"] == action["body_sha256"] == payload["raw_sha256"] == sha(raw)
            and sha(payload["text"].encode()) == sha(raw)
            and receipt["status"] == flow["status_code"] == action["http_status"] == 200
            and receipt["path"] == flow["path"] == "/collect" and flow["method"] == "POST"
            and flow.get("package") == PACKAGE)


def assert_windows(case, positive_count, windows):
    """五档期望表：没有断言的 passed 等于没跑。"""
    check(len(windows) == len(WINDOWS), f"{case}: 窗口档数不符")
    for row in windows:
        ms, tp, fn, out = row["window_ms"], row["true_positive"], row["false_negative"], row["outside_reference"]
        check(tp + fn == positive_count, f"{case}-{ms}: 命中与漏配之和 != {positive_count}")
        check(out == 0, f"{case}-{ms}: 出现基准之外的配对 {out}")
        if case == "bg_read_only":
            check(tp == 0, f"{case}-{ms}: 负控出现配对")
        elif case == "bg_send":
            check(tp == 1 and fn == 0, f"{case}-{ms}: 后台即时发送未在窗口内配对")
        elif case == "offline_resend":
            if ms == WINDOWS[0]:
                check(tp == 0, f"{case}-{ms}: 断网+补传周期必然超出 5 秒窗")
            elif ms >= 30000:
                check(tp == 1 and fn == 0, f"{case}-{ms}: 补传未在宽窗口内配对")
            # 10 秒档取决于断网/恢复耗时，允许命中或漏配，但必须自洽（上面已校验）。
        else:
            raise ValueError(f"未知对照: {case}")


def replay_offline(source, out):
    check(out.exists() is False, "输出目录已存在")
    suite = load(source / "suite.json")
    rules = source / "rules.db"
    check(rules.is_file() and suite["rules_sha256"] == sha(rules.read_bytes())
          and suite["hook_sha256"] == sha((source / "hook.bundle.js").read_bytes()),
          "规则库或 Hook 范围不符")
    check(set(suite["cases"]) == set(OFFLINE_STEPS)
          and len(set(suite["cases"].values())) == len(OFFLINE_STEPS), "后台对照组须独立会话")
    out.mkdir(parents=True, exist_ok=False)
    results = {}
    for case, token in suite["cases"].items():
        folder, manifest_file = source / case, source / case / "manifest.json"
        manifest = load(manifest_file)
        required = case_inputs(case)
        check(manifest["session_id"] == token and manifest["apk_sha256"] == suite["apk_sha256"]
              and manifest["hook_sha256"] == suite["hook_sha256"] and manifest["passed"] is True
              and set(manifest["sha256"]) == required, "采集身份或封存文件集合不一致")
        for name, digest in manifest["sha256"].items():
            check(sha((folder / name).read_bytes()) == digest, f"封存文件摘要不一致: {name}")
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
        assert_windows(case, len(positive), windows)
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
