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

# JSONL 一律走 core.io_utils（§8.2 B-2）：
# **不能用 str.splitlines()**——它会在 JSON 字符串里的 U+0085/U+2028 处切分，
# 而 mitm 落盘的 flow 记录带着 latin-1 解码出的正文，这两类字符常见。
# 实测 `flows.jsonl` 一条记录里 59 个 U+0085，splitlines 会把整份文件切成碎片。
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from core.io_utils import load_jsonl_counting  # noqa: E402


def read_jsonl(path: Path) -> list[dict]:
    rows, skipped = load_jsonl_counting(path)
    if skipped:
        print(f"[warn] {path.name} 有 {skipped} 行无法解析，已跳过（索引计数为下界）",
              file=sys.stderr)
    return rows


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
    # 采样覆盖率：0 条连接有两种完全不同的原因——「应用安静」与「整段没采到进程」。
    # 只有 conns.summary.json 里的 pid_miss_samples 能把它们分开（2026-10-19 实测：
    # 01 号样本有 INTERNET 权限却 0 行，此前无法自证是哪种）。
    cov_file = session / "conns.summary.json"
    if cov_file.exists():
        try:
            cov = json.loads(cov_file.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            cov = {}
        if cov:
            # **必须显式判 `is True`**（2026-10-20 修）：原来写 `is not False`，
            # 于是 covered 为 None（sidecar 被强杀没写完整 / 旧格式缺字段）时也走
            # "0 条连接可视为确实没有连接"这条分支，把**没采到**说成**没外发**。
            # sidecar 丢失在本项目是实测发生过的（conn_probe 头部注释记了 07/08 号）。
            # 另外该结论要限定到 TCP：采样器不读 UDP/QUIC。
            if cov.get("covered") is True:
                cov_note = ("采样取得进程后未丢失；TCP 层 0 条连接可视为「窗口内确实没有 TCP 连接」。"
                            "注：本采样器只读 tcp/tcp6，UDP 与 QUIC(HTTP/3) 不在观测范围内，"
                            "故不能据此断言「应用未外发」。")
            elif cov.get("covered") is None:
                cov_note = ("覆盖率 sidecar 未给出 covered（缺失/损坏/旧格式）："
                            "本轮 0 条连接**不能**作为「应用未联网」的依据。")
            elif cov.get("pid_lost_after_start") is not None:
                cov_note = ("covered=false：取得进程后又丢失（崩溃/被杀），中段存在覆盖缺口。"
                            "本轮 0 条连接**不能**作为「应用未联网」的依据。")
            elif cov.get("pid_miss_markers") or cov.get("pid_miss_samples"):
                cov_note = ("covered=false（旧格式 sidecar，只有缺失标记数）：无法区分"
                            "「启动前的预期空窗」与「启动后丢失」，本轮 0 条连接不可作结论。")
            else:
                cov_note = ("covered=false：一行都没采到（窗口过短或设备端脚本未运行）。"
                            "本轮 0 条连接不可作结论。")
            sources["device_conns"]["sampling_coverage"] = {
                # `pid_absent_before_start`：采样早于 `am start`，开头取不到进程属预期；
                # `pid_lost_after_start`：取得进程后又消失，才是真正的中段覆盖缺口。
                # 旧样本只有 `pid_miss_markers`/`pid_miss_samples`（两者混计），一并透出。
                "pid_absent_before_start": cov.get("pid_absent_before_start"),
                "pid_lost_after_start": cov.get("pid_lost_after_start"),
                "pid_miss_markers": cov.get("pid_miss_markers"),
                "covered": cov.get("covered"),
                "coverage_basis": cov.get("coverage_basis"),
                # 新增（2026-10-20）：把"读过的进程"和"有连接的进程"分开透出。
                # 只看 endpoints/pids 会把"应用本轮没有 TCP 连接"读成"没覆盖到进程"。
                "pid_resolved": cov.get("pid_resolved"),
                "pids_seen": cov.get("pids_seen"),
                "pids": cov.get("pids"),
                "no_target_conn_note": cov.get("no_target_conn_note"),
                "rows": cov.get("rows"), "endpoints": cov.get("endpoints"),
                "note": cov_note,
            }
    if not app_rows:
        sources["device_conns"]["caveat"] = (
            "未采到应用连接。**这不等于没有外发**：窗口内应用可能还没发起请求（本样本按 15 分钟"
            "限流，缓存还新鲜时就不取数）；请求可能落在采样窗之外；应用在采样窗内重启过，"
            "而重启瞬间的 socket 会漏（pid 每 PIDOF_EVERY 轮才重解一次）。")

    # 5) pcap → 完整 HTTP 报文（2026-10-18）：hook 给的是 SSL_read/write 分片，
    #    这一路是**消息级**的真相（tshark 重组 + 解 gzip/chunked）。不进 bundle，
    #    但必须在索引里出现——不出现就等于报告里不存在。
    hm = read_jsonl(out_dir / "http_messages.jsonl")
    if hm or (out_dir / "http-stats.json").exists():
        st = {}
        if (out_dir / "http-stats.json").exists():
            try:
                st = json.loads((out_dir / "http-stats.json").read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                st = {}
        reqs = [m for m in hm if m.get("kind") == "request"]
        bodies = [m for m in hm if (m.get("body") or {}).get("len")]
        sources["http_messages"] = {
            "file": "http_messages.jsonl",
            "messages": len(hm), "requests": len(reqs), "with_body": len(bodies),
            "by_proto": dict(sorted(collections.Counter(
                m.get("proto") or "h1" for m in hm).items())),
            "truncated": sum(1 for m in hm
                             if any(g.endswith("_truncated") for g in (m.get("gaps") or []))),
            "stats": st,
            "urls": sorted({m.get("url") or (str(m.get("host") or "") + str(m.get("uri") or ""))
                            for m in reqs if m.get("url") or m.get("host")})[:200],
            "note": "由 capture.pcap + NSS keylog 经 tshark 解出：TCP 重组、TLS 解密、"
                    "chunked 分帧、gzip 解压都是 tshark 做的；body 原文在 bodies/ 下。"
                    "h1 与 h2 各解一趟（h2 的头在 http2.header.* 里，不是 http.request.*）。"
                    "带 *_truncated 的 body 是抓包在流中途结束，明文是**部分**的，不要当完整正文用。"
                    "零报文时先看 stats.error（多为 keylog 没装上）",
        }

    # 6) 代理看见但归因不到应用的流（2026-10-19）：区分"应用没外发"与
    #    "外发了但 egress 钩子没覆盖"。旧实现把这类流直接丢弃，交付物上两者同形。
    #
    #    系统连通性探测（`connectivitycheck.gstatic.com/generate_204` 等）必须**拆出去**：
    #    它们是设备在联网、不是应用在外发。混在一起会让"条数 > 0"恒成立，
    #    于是「应用未外发」这个结论永远写不出来（01 号样本当场踩到）。
    ua = read_jsonl(session / "flows-unattributed.jsonl")
    sys_probe = [f for f in ua if f.get("system_probe")]
    ua_real = [f for f in ua if not f.get("system_probe")]
    if ua_real:
        sources["flows_unattributed"] = {
            "file": "session/flows-unattributed.jsonl", "flows": len(ua_real),
            "hosts": dict(sorted(collections.Counter(
                str(f.get("host")) for f in ua_real).most_common(20))),
            "note": "代理确凿收到了这些请求，但 egress 钩子没有对应事件（覆盖缺口）。"
                    "它们**不进** flows.jsonl，避免被误当成已归因证据；"
                    "条数 > 0 时不能写「应用未外发」。",
        }
    if sys_probe:
        sources["flows_system_probe"] = {
            "file": "session/flows-unattributed.jsonl", "flows": len(sys_probe),
            "hosts": dict(sorted(collections.Counter(
                str(f.get("host")) for f in sys_probe).most_common(20))),
            "note": "操作系统自身的连通性探测（generate_204 等），不属于被测应用的外发。"
                    "**不计入** flows_unattributed，不能拿它否定「应用未外发」。",
        }

    # 6a) 上游**连接建立失败**（2026-10-19）：只出现在 mitmproxy 文本日志里的
    #     `error establishing server connection: [WinError 121]`，此前结构化产物一条都没有。
    #     `error(flow)` 钩子在 HTTP/2 多路复用连接整条失败时不会为每条流派发，
    #     所以 `flows-unanswered.jsonl` 兜不住——02 号样本 3 次 121 全丢。
    ce = read_jsonl(session / "flows-connect-errors.jsonl")
    if ce:
        sources["connect_errors"] = {
            "file": "session/flows-connect-errors.jsonl", "events": len(ce),
            "by_kind": dict(sorted(collections.Counter(
                str(f.get("failure_kind") or "unclassified") for f in ce).items())),
            "targets": dict(sorted(collections.Counter(
                str(f.get("server_address")) for f in ce).most_common(20))),
            "note": "代理**尝试连接**这些上游但失败了：请求可能根本没发出。"
                    "不能据此说「应用外发了什么」，同样**不能**当作「应用未外发」。",
        }

    # 6b) 有请求但没拿到响应（2026-10-19 加分类）：`failure` 是原始异常串，
    #     光看它会把「上游黑洞」读成「应用主动断开」——实测两者都写成 "client disconnected"。
    #     分类口径见 core/collector/addon.classify_upstream_failure。
    un = read_jsonl(session / "flows-unanswered.jsonl")
    if un:
        kinds = collections.Counter(str(f.get("failure_kind") or "unclassified") for f in un)
        sources["flows_unanswered"] = {
            "file": "session/flows-unanswered.jsonl", "flows": len(un),
            "by_kind": dict(sorted(kinds.items())),
            "hosts": dict(sorted(collections.Counter(
                str(f.get("host")) for f in un).most_common(20))),
            "slowest_connect_ms": max(
                [f["connect_ms"] for f in un if isinstance(f.get("connect_ms"), int)] or [0]),
            "note": "应用确实发出了请求，但没拿到响应——这些**不能**写成「没有外发」。"
                    "upstream_timeout/upstream_refused 是环境侧不可达（多为目标被封或丢包），"
                    "不是应用行为；client_abort 才是应用自己中途放弃。"
                    "两类都不能推出「数据没发出去」：字节可能已经发到对端。",
        }

    # 7) UI 动作：说明探索到了哪些界面路径（没触达的路径就不可能产生事件）。
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
                          "http_messages", "egress_vehicle/hooks"],
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
