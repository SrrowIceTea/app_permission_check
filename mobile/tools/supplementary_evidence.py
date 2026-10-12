#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""补充证据索引 —— 把「钩子之外」的旁路证据汇总成一份可读清单。

仅用于授权测试（自有设备 / 已授权的公开第三方样本）。

**这不是新证据**：证据本体是 session/ 下的原始 JSONL，本文件只是它们的索引与计数。
之所以单独生成，是因为下面这几路证据**不进入 bundle / 不参与规则求值**：

  * egress_tp.jsonl   第三方专用出站钩子（libcore 汇聚点 + URI/URL 构造）的事件；
  * tls.jsonl         TLS 绕过钩子的挂载与命中（第三方专用裁剪版）；
  * conns.jsonl       设备侧连接采样（设备端每轮重解 pid，读**该进程命名空间**的
                      /proc/<pid>/net/tcp{,6}，逐行带 uid）；
  * egress.jsonl      vehicle/hooks 出站钩子（只挂 java.net.Socket.connect）。

其中 conns.jsonl 是**与客户端库无关**的地面真相：它回答"钩子零事件"到底是
"真的没外发"还是"外层栈没被覆盖"。少了它，这两种情况在报告里长得一模一样。

用法:
  python supplementary_evidence.py --session <会话目录> --out <交付目录> \
      --out-file <交付目录>/out/supplementary-evidence.json
"""
from __future__ import annotations

import argparse
import collections
import json
import sys
from pathlib import Path


def read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    out = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


def event_counts(events: list[dict]) -> dict:
    return dict(sorted(collections.Counter(e.get("ev") for e in events).items(),
                       key=lambda kv: str(kv[0])))


def summarize(session: Path, out_dir: Path, package: str, app_uid: int | None = None) -> dict:
    sources: dict[str, dict] = {}

    # 1) 第三方出站钩子：摘出真正的外发线索（URL / 连接），丢掉 START/ARMED 这类噪声。
    tp = read_jsonl(session / "egress_tp.jsonl")
    urls, conns, misses = [], [], []
    for e in tp:
        if e.get("ev") == "EGRESS_URL":
            urls.append({"ts": e.get("ts"), "via": e.get("via"), "url": e.get("url")})
        elif e.get("ev") == "EGRESS_CONNECT":
            conns.append({"ts": e.get("ts"), "via": e.get("via"),
                          "host": e.get("target_host"), "port": e.get("target_port"),
                          "ip": e.get("target_ip"), "outcome": e.get("outcome")})
        elif e.get("ev") in ("HOOK_MISS", "ERROR"):
            misses.append({"ev": e.get("ev"), "where": e.get("where"), "msg": e.get("msg")})
    sources["egress_tp"] = {"file": "session/egress_tp.jsonl", "events": event_counts(tp),
                            "urls": urls, "connections": conns, "hook_misses": misses,
                            "note": "挂到 libcore 汇聚点；不经 java.net.Socket.connect 重写路径"}

    # 2) vehicle/hooks 出站钩子（只挂 Socket.connect）：用作对照，说明"钩错层"长什么样。
    eg = read_jsonl(session / "egress.jsonl")
    sources["egress_vehicle/hooks"] = {"file": "session/egress.jsonl", "events": event_counts(eg),
                                "note": "只挂 java.net.Socket.connect；被 conscrypt 子类重写后抓不到"}

    # 3) TLS 绕过：只摘挂载结果与命中，原文仍以 JSONL 为准。
    tls = read_jsonl(session / "tls.jsonl")
    tls_hits = [{"ts": e.get("ts"), "ev": e.get("ev"), "target": e.get("target"),
                 "detail": e.get("detail")}
                for e in tls if e.get("ev") in ("PINNING_BYPASS", "PINNING_ARMED",
                                                "TM_CLASS_HOOKED", "ERROR")]
    sources["tls"] = {"file": "session/tls.jsonl", "events": event_counts(tls),
                      "highlights": tls_hits,
                      "note": "第三方裁剪版：去掉会触发 ART abort 的 HttpsURLConnection 主机名钩子"}

    # 4) 设备侧连接采样：与客户端库无关的地面真相。
    cp = read_jsonl(session / "conns.jsonl")
    # **非 root ≠ 应用**：同一命名空间里还有 network_stack(1073)、上一次安装残留的旧 uid、
    # 走代理的系统组件等。给了 --app-uid 就只认它；没给就只报"非 root"并写明口径——
    # 绝不把两者并成一句"应用有 N 条外发"，那会**高估**。
    by_uid = collections.Counter(c.get("uid") for c in cp)
    if app_uid is not None:
        app_rows = [c for c in cp if c.get("uid") == app_uid]
        others = collections.Counter(c.get("uid") for c in cp
                                     if c.get("uid") not in (0, None, app_uid))
        subject = f"应用（uid={app_uid}）"
    else:
        app_rows = [c for c in cp if c.get("uid") not in (0, None)]
        others = collections.Counter()
        subject = "非 root（未指定 --app-uid，口径可能含其它进程）"
    sources["device_conns"] = {
        "file": "session/conns.jsonl", "events": event_counts(cp),
        "endpoints": [{"ts": c.get("ts"), "pid": c.get("pid"), "uid": c.get("uid"),
                       "remote": f"{c.get('remote_ip')}:{c.get('remote_port')}",
                       "state": c.get("state"), "hits": c.get("hits")} for c in cp],
        "endpoints_by_uid": {str(k): n for k, n in sorted(by_uid.items(),
                                                          key=lambda kv: str(kv[0]))},
        "app_endpoints": len(app_rows),
        "other_non_root_by_uid": {str(k): n for k, n in sorted(others.items(),
                                                               key=lambda kv: str(kv[0]))},
        "conclusion": (f"窗口内观测到 {len(app_rows)} 条{subject}的连接：确有外发，"
                       "钩子零事件属**覆盖缺口**，不是没有外发。" if app_rows else
                       f"窗口内**未观测到{subject}的连接**；这只说明本窗口没采到，"
                       "不等于没有外发，见 caveat。"),
        "note": "设备端每轮重解 pid，读**目标进程命名空间**的 /proc/<pid>/net/tcp{,6}，"
                "20ms 级采样；回答'钩子零事件'是没外发还是没覆盖"}
    if not app_rows:
        sources["device_conns"]["caveat"] = (
            "未采到应用连接。**这不等于没有外发**：窗口内应用可能还没发起请求（本样本按 15 分钟"
            "限流，缓存还新鲜时就不取数）；请求可能落在采样窗之外；应用在采样窗内重启过，"
            "而重启瞬间的 socket 会漏（pid 每 PIDOF_EVERY 轮才重解一次）。")

    # 5) UI 动作：说明探索到了哪些界面路径（没触达的路径就不可能产生事件）。
    ui_path = out_dir / "ui-actions.json"
    if ui_path.exists():
        try:
            ui = json.loads(ui_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            ui = {}
        actions = ui.get("actions") or []
        sources["ui_actions"] = {
            "file": "ui-actions.json", "total": len(actions),
            "by_action": dict(sorted(collections.Counter(a.get("action") for a in actions).items(),
                                     key=lambda kv: str(kv[0]))),
            "sequence": [{"n": i + 1, "action": a.get("action"), "target": a.get("target"),
                          "note": a.get("note")} for i, a in enumerate(actions)],
            "note": "每次点击的点击前/后 XML 在 ui/ 目录；未触达的界面路径不会产生事件"}

    return {
        "kind": "supplementary-evidence-index",
        "package": package,
        "warning": "本文件是索引，不是证据本体。证据本体是 session/ 下的原始 JSONL。",
        "not_in_bundle": ["egress_tp", "tls", "device_conns", "ui_actions",
                          "egress_vehicle/hooks"],
        "sources": sources,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--session", required=True)
    ap.add_argument("--out-dir", required=True, help="交付目录（用于找 ui-actions.json）")
    ap.add_argument("--package", required=True)
    ap.add_argument("--app-uid", type=int, default=None,
                    help="应用 uid；给了才能把「应用外发」和「其它非 root」分开统计")
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    session = Path(args.session)
    if not session.is_dir():
        sys.exit(f"[fatal] 会话目录不存在: {session}")
    data = summarize(session, Path(args.out_dir), args.package, args.app_uid)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
                   encoding="utf-8")
    print(json.dumps({"status": "ok", "out": str(out),
                      "sources": {k: v.get("events", v.get("total"))
                                  for k, v in data["sources"].items()}},
                     ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
