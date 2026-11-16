#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""pcap → 完整 HTTP 报文（调用 tshark，不自己写重组）。

## 这一层解决什么

`hook_native_ssl.js` 给的是 `SSL_read`/`SSL_write` 的**分片**：一次调用可能只有半个
body，且没有连接标识。本模块把重组/解压/分帧全部外包给 Wireshark：

    tshark -r cap.pcap -o tls.keylog_file:keys.log -Y "http.request or http.response" -T json

tshark 负责的部分（都是它现成的能力，我们一行都没写）：
  - TCP 流重组（乱序、重传、跨段）
  - TLS 1.2 `CLIENT_RANDOM` / TLS 1.3 `CLIENT_*_TRAFFIC_SECRET` 解密
  - HTTP/1.1 `Content-Length` / `Transfer-Encoding: chunked` 分帧
  - `Content-Encoding: gzip/deflate/br` 解压（`http.decompress_body`，默认开）
  - 解出 ALPN 后自动把 TLS 载荷交给 HTTP/2 解析器（不写 `-d` 也行）

## 输入

- `--pcap`：`pcap_capture.py` 抓的文件
- `--keylog`：NSS keylog 文本（每行 `CLIENT_RANDOM <client_random> <secret>`）。
  `keylog_from_events()` 可以直接从本仓库的 `tls_meta.jsonl` 生成。
- 没有 keylog 也能跑：tshark 仍会重组**明文 HTTP**（80 端口、或应用自己降级的明文）。

## 输出

- `--out`：JSONL，一条消息一行（`kind=request|response`）
- `--bodies-dir`：完整 body 落盘为独立文件（`http.file_data` 可能是二进制）

读不到 body 的原因会写进每条的 `gaps`（例如 `no_keylog` / `encrypted` / `truncated`），
**不把"没解出来"写成"没有 body"**。
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(HERE))
from pcap_tshark import FRIDA_LOOPBACK, find_tshark, keylog_from_events, _as_text, _parse_hex, _run_tshark  # noqa: E402
from pcap_http2 import decode_h2  # noqa: E402

_FIELDS = [
    "frame.number", "frame.time_epoch", "ip.src", "ip.dst", "ipv6.src", "ipv6.dst",
    "tcp.srcport", "tcp.dstport", "tcp.stream",
    "http.request.method", "http.host", "http.request.uri", "http.request.full_uri",
    "http.response.code", "http.response.phrase", "http.content_type",
    "http.content_encoding", "http.content_length", "http.file_data",
    "http.request_in", "http.response_in", "tls.handshake.extensions_alpn_str",
]


def decode(pcap: Path, out_jsonl: Path, bodies_dir: Path,
           keylog: Path | None = None, tshark: str | None = None,
           max_body: int = 4 * 1024 * 1024, *, http_port: int | None = None) -> dict:
    """跑 tshark 并把结果落成 JSONL。返回统计（**含失败原因**）。"""
    stats: dict = {"tshark": tshark or find_tshark(), "ok": False, "messages": 0,
                   "requests": 0, "responses": 0, "bodies": 0, "bytes": 0,
                   "keylog_lines": 0, "tls_encrypted_without_body": 0, "error": None}
    if not stats["tshark"]:
        stats["error"] = "未找到 tshark（装 Wireshark 或设 VSCAN_TSHARK）"
        return stats
    if not pcap.exists() or pcap.stat().st_size <= 24:
        stats["error"] = f"pcap 不存在或为空：{pcap}"
        return stats
    if keylog and keylog.exists():
        stats["keylog_lines"] = sum(1 for ln in keylog.read_text(
            encoding="utf-8", errors="replace").splitlines() if ln.strip())

    if http_port is not None and (type(http_port) is not int or not 1 <= http_port <= 65535):
        raise ValueError("Invalid HTTP fixture port")
    stats["http_decode_as_port"] = http_port
    extra = (["-d", f"tcp.port=={http_port},http"] if http_port is not None else [])
    extra += ["-Y", f"(http.request or http.response) and not ({FRIDA_LOOPBACK})", "-T", "json"]
    for f in _FIELDS:
        extra += ["-e", f]
    rc, out, err = _run_tshark(stats["tshark"], pcap, keylog, extra)
    if rc != 0 and not out.strip():
        stats["error"] = f"tshark rc={rc}: {err.strip()[:300]}"
        return stats

    try:
        packets = json.loads(out) if out.strip() else []
    except json.JSONDecodeError as exc:
        stats["error"] = f"tshark JSON 解析失败：{exc}"
        return stats

    bodies_dir.mkdir(parents=True, exist_ok=True)
    out_jsonl.parent.mkdir(parents=True, exist_ok=True)
    records: list[dict] = []
    counter = [0]
    for pkt in packets:
        layers = (pkt.get("_source") or {}).get("layers") or {}
        row = {k: _as_text(layers.get(k)) for k in _FIELDS}
        is_req = bool(row["http.request.method"])
        is_resp = bool(row["http.response.code"])
        if not (is_req or is_resp):
            continue
        counter[0] += 1
        n = counter[0]
        rec: dict = {
            "ts": float(row["frame.time_epoch"] or 0) or time.time(),
            "frame": row["frame.number"],
            "kind": "request" if is_req else "response",
            "proto": "h1",
            "src": f"{row['ip.src'] or row['ipv6.src']}:{row['tcp.srcport']}",
            "dst": f"{row['ip.dst'] or row['ipv6.dst']}:{row['tcp.dstport']}",
            "tcp_stream": row["tcp.stream"],
            "alpn": row["tls.handshake.extensions_alpn_str"],
            "gaps": [],
        }
        if is_req:
            rec.update({"method": row["http.request.method"], "host": row["http.host"],
                        "uri": row["http.request.uri"],
                        "url": row["http.request.full_uri"]})
        else:
            rec.update({"status": int(row["http.response.code"] or 0),
                        "phrase": row["http.response.phrase"]})
        if row["http.content_type"]:
            rec["content_type"] = row["http.content_type"]
        if row["http.content_encoding"]:
            rec["content_encoding"] = row["http.content_encoding"]

        data = _parse_hex(row["http.file_data"])
        if data:
            if len(data) > max_body:
                rec["gaps"].append(f"body_truncated_at_{max_body}")
                data = data[:max_body]
            h = hashlib.sha256(data).hexdigest()
            name = f"{n:05d}_{h[:12]}.bin"
            (bodies_dir / name).write_bytes(data)
            rec["body"] = {"file": name, "len": len(data), "sha256": h}
            try:
                txt = data.decode("utf-8")
                rec["body"]["text_head"] = txt[:400]
                rec["body"]["is_text"] = True
            except UnicodeDecodeError:
                rec["body"]["is_text"] = False
        else:
            # 有响应头但没有 body：要么本来就没有（204/304），要么没解出来。
            # 这里只标注，不替数据下结论。
            if is_resp and row["http.response.code"] not in ("204", "304", ""):
                rec["gaps"].append("no_body_bytes")
        records.append(rec)

    # 第二趟：HTTP/2（实测现代客户端 11/12 条连接协商成 h2，只解 h1 会漏掉绝大多数）
    h2 = decode_h2(stats["tshark"], pcap, keylog, records, bodies_dir, counter, max_body)
    stats["h2_streams"] = h2.get("h2_streams", 0)
    stats["h2_messages"] = h2.get("h2_messages", 0)
    if h2.get("error"):
        stats["h2_error"] = h2["error"]

    records.sort(key=lambda r: r.get("ts") or 0)
    with out_jsonl.open("w", encoding="utf-8") as fh:
        for r in records:
            fh.write(json.dumps(r, ensure_ascii=False) + "\n")

    n = len(records)
    stats["messages"] = n
    stats["requests"] = sum(1 for r in records if r["kind"] == "request")
    stats["responses"] = sum(1 for r in records if r["kind"] == "response")
    stats["bodies"] = sum(1 for r in records if (r.get("body") or {}).get("len"))
    stats["bytes"] = sum((r.get("body") or {}).get("len", 0) for r in records)
    # 下面这些只能从 records 反算：h1 循环里那些 += 在算术上是对的，但
    # "有头没 body"要横跨 h1/h2 两种协议，单在 h1 里数会漏掉 h2 的响应。
    stats["h1_messages"] = sum(1 for r in records if r.get("proto") == "h1")
    stats["h2_messages"] = sum(1 for r in records if r.get("proto") == "h2")
    stats["tls_encrypted_without_body"] = sum(
        1 for r in records if "no_body_bytes" in (r.get("gaps") or []))
    stats["bodies_truncated"] = sum(
        1 for r in records
        if any(g.endswith("_truncated") for g in (r.get("gaps") or [])))

    stats["ok"] = n > 0
    if n == 0:
        stats["error"] = "tshark 未识别到业务 HTTP 报文"

    # 没有 keylog 时必须回答一个问题：是"真没流量"，还是"有 TLS 但解不开"？
    # 这两者在 messages 计数上长得一模一样（都只剩明文那几条），而后者会让报告
    # 把"看不见"写成"没有"——实测一轮 e2e 就是这样：2 条报文、检查通过，
    # 其实是 App 的 TLS 连接在 tls_meta 装钩子之前就建好了，keylog 一行没拿到。
    # 只在缺 keylog 时多跑一趟，正常情况下不付这个代价。
    if not stats["keylog_lines"]:
        rc2, out2, _ = _run_tshark(
            stats["tshark"], pcap, None,
            ["-Y", "tls.app_data", "-T", "fields", "-e", "frame.number"])
        cnt = len([ln for ln in out2.splitlines() if ln.strip()]) if rc2 == 0 else None
        stats["tls_undecrypted_app_data"] = cnt
        if cnt:
            verdict = f"有 {cnt} 帧 TLS 应用数据未解密（keylog 未装上），明文报文只是全部流量的一部分"
            stats["error"] = f"{stats['error']}；{verdict}" if stats["error"] else verdict
    return stats


def main() -> int:
    ap = argparse.ArgumentParser(description="pcap → 完整 HTTP 报文（复用 tshark）")
    ap.add_argument("--pcap", required=True)
    ap.add_argument("--out", required=True, help="输出 JSONL")
    ap.add_argument("--bodies-dir", default=None, help="body 落盘目录（默认 out 同级 bodies/）")
    ap.add_argument("--keylog", default=None, help="NSS keylog 文本")
    ap.add_argument("--session", default=None, help="会话目录：从中自动抽取 keylog")
    ap.add_argument("--stats", default=None, help="统计写这里（JSON）")
    ap.add_argument("--http-port", type=int, choices=range(1, 65536), metavar="PORT",
                    help="指定自有明文 HTTP 夹具端口")
    args = ap.parse_args()

    out = Path(args.out).resolve()
    bodies = Path(args.bodies_dir) if args.bodies_dir else out.parent / "bodies"
    keylog = Path(args.keylog) if args.keylog else None
    stats_extra: dict = {}
    if keylog is None and args.session:
        keylog = out.parent / "keys.log"
        n, labels = keylog_from_events(Path(args.session), keylog)
        stats_extra = {"keylog_from_session": n, "keylog_labels": labels}

    stats = decode(Path(args.pcap).resolve(), out, bodies, keylog, http_port=args.http_port)
    stats.update(stats_extra)
    text = json.dumps(stats, ensure_ascii=False, indent=2)
    if args.stats:
        Path(args.stats).write_text(text + "\n", encoding="utf-8")
    print(text)
    return 0 if stats["ok"] or stats["error"] is None else 1


if __name__ == "__main__":
    raise SystemExit(main())
