#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""隔离实验：spawn 注入能不能把 keylog 装上？

背景（2026-10-18 实测 4 轮 F-Droid）：attach 模式下 keylog 时有时无（2/4 拿到）。
失败轮的现象是 `tls_meta ARMED` 了但 `SSL_new` 一次都没触发——应用的 TLS 连接
在钩子装载**之前**就建好了，之后只是在旧连接上 SSL_read。调整装配顺序无效
（改序后仍是 1/2）。假设：spawn 在应用第一条指令前就位，能稳定拿到 keylog。

本脚本只做这一件事，不动 device_run_thirdparty 的既有流程：
  抓包 → force-stop → spawn 注入 → 等应用自己发请求 → 停包 → 解 keylog 行数

跑法：python mobile/tools/_exp_spawn_keylog.py [--seconds 45]
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import pcap_capture                      # noqa: E402
import pcap_http                         # noqa: E402
from thirdparty_env import adb, start_hook, stop_hook   # noqa: E402

PKG = "org.fdroid.fdroid"
ROOT = HERE.parent.parent


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seconds", type=int, default=45)
    ap.add_argument("--out", default="output/_exp-spawn")
    args = ap.parse_args()

    out = Path(args.out).resolve()
    session = out / "session"
    session.mkdir(parents=True, exist_ok=True)
    log = out / "pcap.log"

    print("[1] force-stop（spawn 必须从一个没跑的进程开始）", flush=True)
    adb("shell", "am", "force-stop", PKG, timeout=60)
    time.sleep(2)

    print("[2] 起抓包", flush=True)
    rec = pcap_capture.PcapRecorder()
    ok, note = rec.start(log, args.seconds + 60)
    print(f"    start={ok} {note}", flush=True)
    if not ok:
        return 1

    print("[3] spawn 注入 hook_all", flush=True)
    script = ROOT / "mobile" / "hooks" / "dist" / "hook_all.bundle.js"
    proc = start_hook(script, session, "hook_all", out / "hook-all.log",
                      args.seconds, PKG, spawn=True)
    try:
        proc.wait(timeout=args.seconds + 60)
    except Exception:
        stop_hook(proc, out / "hook-all.log")
    print(f"    hook rc={proc.returncode}", flush=True)

    print("[4] 停抓包", flush=True)
    pcap_path = rec.stop(out / "capture.pcap", out / "pcap-stop.log")
    print(f"    pcap={pcap_path}", flush=True)

    print("[5] 结果", flush=True)
    logtxt = (out / "hook-all.log").read_text(encoding="utf-8", errors="replace")
    nk, labels = pcap_http.keylog_from_events(session, out / "keys.log")
    res = {
        "spawn": True,
        "hook_rc": proc.returncode,
        "keylog_installed": logtxt.count("KEYLOG_INSTALLED"),
        "tls_keylog_events": logtxt.count("TLS_KEYLOG"),
        "ssl_new_hook_armed": "SSL_new@" in logtxt,
        "keylog_lines": nk,
        "labels": labels,
        "pcap_bytes": pcap_path.stat().st_size if pcap_path else 0,
    }
    if pcap_path:
        st = pcap_http.decode(pcap_path, out / "http_messages.jsonl",
                              out / "bodies", out / "keys.log" if nk else None)
        res["http"] = {k: st[k] for k in ("messages", "h1_messages", "h2_messages",
                                          "bodies", "keylog_lines",
                                          "tls_undecrypted_app_data")
                       if k in st}
    (out / "result.json").write_text(json.dumps(res, ensure_ascii=False, indent=2) + "\n",
                                     encoding="utf-8")
    print(json.dumps(res, ensure_ascii=False, indent=2), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
