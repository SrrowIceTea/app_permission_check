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
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(ROOT))
# JSONL 分行只认 LF（理由见 core/io_utils.split_jsonl_lines）：tls_meta 事件里
# 可能夹着 base64/正文片段，splitlines() 会在 U+0085 处切断，keylog 行随之丢光。
from core.io_utils import split_jsonl_lines  # noqa: E402

_CANDIDATES = [
    r"C:\Program Files\Wireshark\tshark.exe",
    r"C:\Program Files (x86)\Wireshark\tshark.exe",
]


def find_tshark() -> str | None:
    """按 VSCAN_TSHARK → PATH → 常见安装目录 找 tshark。找不到返回 None。

    不猜版本、不自动下载：抓不到就如实报缺口，由安装步骤解决。
    """
    p = os.environ.get("VSCAN_TSHARK")
    if p and Path(p).exists():
        return p
    which = shutil.which("tshark")
    if which:
        return which
    for c in _CANDIDATES:
        if Path(c).exists():
            return c
    return None


def keylog_from_events(session: Path, out: Path) -> tuple[int, str]:
    """从会话事件里抽取 NSS keylog 行，写成 tshark 认的文本。

    来源优先级：`tls_meta.jsonl`（分流后）→ `reads.jsonl`（合并模式未分流）。
    两者都可能存在，按行去重——同一连接重复握手会重复打点。
    """
    lines: list[str] = []
    seen: set[str] = set()
    for name in ("tls_meta.jsonl", "reads.jsonl"):
        f = session / name
        if not f.exists():
            continue
        for raw in split_jsonl_lines(f.read_text(encoding="utf-8", errors="replace")):
            if not raw:
                continue
            try:
                ev = json.loads(raw)
            except json.JSONDecodeError:
                continue
            if ev.get("ev") != "TLS_KEYLOG":
                continue
            line = str(ev.get("line") or "").strip()
            # 收的是 NSS keylog 行：`<LABEL> <client_random> <secret>`。
            # 只按结构校验（3 段、前两段是 hex）——**不要**用正则去枚举标签，
            # TLS 1.3 的 `CLIENT_HANDSHAKE_TRAFFIC_SECRET` 之类会漏，而且写错一个
            # 字符就会静默返回 0 行（本文件第一版就是这么挂的）。
            parts = line.split()
            if len(parts) != 3 or line in seen:
                continue
            if not all(re.fullmatch(r"[0-9a-fA-F]+", p) for p in parts[1:]):
                continue
            seen.add(line)
            lines.append(line)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
    labels = sorted({ln.split(" ")[0] for ln in lines})
    return len(lines), ",".join(labels)


_FIELDS = [
    "frame.number", "frame.time_epoch", "ip.src", "ip.dst", "tcp.srcport", "tcp.dstport",
    "http.request.method", "http.host", "http.request.uri", "http.request.full_uri",
    "http.response.code", "http.response.phrase", "http.content_type",
    "http.content_encoding", "http.content_length", "http.file_data",
    "http.request_in", "http.response_in", "tls.handshake.extensions_alpn_str",
]


def _run_tshark(tshark: str, pcap: Path, keylog: Path | None,
                extra: list[str], timeout: int = 600) -> tuple[int, str, str]:
    cmd = [tshark, "-r", str(pcap), "-n",
           "-o", "http.decompress_body:TRUE",
           "-o", "http.desegment_body:TRUE",
           "-o", "tcp.desegment_tcp_streams:TRUE"]
    if keylog and keylog.exists() and keylog.stat().st_size:
        cmd += ["-o", f"tls.keylog_file:{keylog}"]
    cmd += extra
    r = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8",
                       errors="replace", timeout=timeout)
    return r.returncode, r.stdout or "", r.stderr or ""


def _as_text(v) -> str:
    if v is None:
        return ""
    if isinstance(v, list):
        return ",".join(_as_text(x) for x in v)
    return str(v)


def _parse_hex(v: str) -> bytes | None:
    """`http.file_data` 在 `-T json` 里是 hex 串（无分隔）。非 hex 返回 None。"""
    s = re.sub(r"[^0-9a-fA-F]", "", v)
    if not s or len(s) % 2:
        return None
    try:
        return bytes.fromhex(s)
    except ValueError:
        return None


_H2_FIELDS = [
    "frame.number", "frame.time_epoch", "ip.src", "ip.dst", "tcp.srcport", "tcp.dstport",
    "tcp.stream", "http2.type", "http2.streamid", "http2.header.count",
    "http2.header.name", "http2.header.value",
    "http2.body.reassembled.data", "http2.data.data", "tls.handshake.extensions_alpn_str",
]


def _as_list(v) -> list[str]:
    if v is None:
        return []
    if isinstance(v, list):
        return [_as_text(x) for x in v]
    return [_as_text(v)]


def _inflate_gzip(data: bytes) -> tuple[bytes, str]:
    """gzip 解压，**容忍截断**——抓包常在流中途结束。

    返回 (明文, 状态)，状态是 ok / truncated / failed。

    为什么要自己调 zlib 而不是 `gzip.decompress`：后者遇到不完整的流直接抛
    `EOFError`（实测真包里就有，`Compressed file ended before the end-of-stream
    marker was reached`），一条消息当场就没了；而截断前解出来的明文往往已经够用
    （JSON 前缀、密钥、URL 都在前面）。解出来的东西配上 `gzip_truncated` 标注，
    比"什么都没有"诚实得多。
    """
    import zlib
    d = zlib.decompressobj(16 + zlib.MAX_WBITS)
    try:
        out = d.decompress(data) + d.flush()
    except zlib.error:
        return b"", "failed"
    return out, ("ok" if d.eof else "truncated")


def _inflate_deflate(data: bytes) -> tuple[bytes, str]:
    import zlib
    for wbits in (zlib.MAX_WBITS, -zlib.MAX_WBITS):   # 有的服务端给裸 deflate
        d = zlib.decompressobj(wbits)
        try:
            out = d.decompress(data) + d.flush()
        except zlib.error:
            continue
        return out, ("ok" if d.eof else "truncated")
    return b"", "failed"


def decode_h2(tshark: str, pcap: Path, keylog: Path | None,
              out: list[dict], bodies_dir: Path, counter: list[int],
              max_body: int = 4 * 1024 * 1024) -> dict:
    """第二趟：HTTP/2。

    为什么要单独一趟：Wireshark 的 h2 解析器把头部放在 `http2.header.name/value`，
    不像 h1 那样有 `http.request.*` 字段——只按 `http.request or http.response` 过滤会
    **一条 h2 都看不见**，而实测 F-Droid 一轮 12 条连接里 11 条 ALPN 协商成了 `h2`。

    三个必须踩过才知道的坑（都实测过）：

    1. **分组键要带方向**：h2 的请求和响应共用同一个 (连接, streamid)。只按
       (tcp.stream, streamid) 分组会把两边塞进一组，`:method` 先到就顶掉 `:status`，
       结果"有请求没响应"。→ 键是 (tcp.stream, streamid, 源 ip:port)。
    2. **`-e` 提取是"包级"的**：一个 TCP 段里常塞着 SETTINGS+HEADERS+DATA 三个 h2 帧，
       `http2.streamid` 会给成 `["0","1","1"]`。`-T json` 的完整树又会把同名节点覆盖掉
       （只剩最后一帧）。→ 用 `http2.type` 与 `http2.streamid` **逐帧同序成数组**这一点
       做下标对齐，头个数由 `http2.header.count` 给。
    3. **h2 没有 `decompress_body`**：h1 那条配置管不到这里。body 取
       `http2.body.reassembled.data`（原始字节），gzip 自己解——这样解没解压是可验证的；
       `http2.data.data` 是 Wireshark 已经解压过的，只作兜底。
    """
    info = {"h2_streams": 0, "h2_messages": 0, "h2_orphans": 0, "h2_ambiguous": 0, "error": None}
    extra = ["-Y", "http2", "-T", "json"]
    for f in _H2_FIELDS:
        extra += ["-e", f]
    rc, text, err = _run_tshark(tshark, pcap, keylog, extra)
    if rc != 0 and not text.strip():
        info["error"] = f"tshark(h2) rc={rc}: {err.strip()[:200]}"
        return info
    try:
        packets = json.loads(text) if text.strip() else []
    except json.JSONDecodeError as exc:
        info["error"] = f"tshark(h2) JSON 解析失败：{exc}"
        return info

    groups: dict[tuple, dict] = {}
    for pkt in packets:
        L = (pkt.get("_source") or {}).get("layers") or {}
        stream = _as_text(L.get("tcp.stream"))
        if not stream:
            continue
        src = f"{_as_text(L.get('ip.src'))}:{_as_text(L.get('tcp.srcport'))}"
        dst = f"{_as_text(L.get('ip.dst'))}:{_as_text(L.get('tcp.dstport'))}"
        types = _as_list(L.get("http2.type"))
        sids = _as_list(L.get("http2.streamid"))
        counts = _as_list(L.get("http2.header.count"))
        names = _as_list(L.get("http2.header.name"))
        vals = _as_list(L.get("http2.header.value"))
        ts = float(_as_text(L.get("frame.time_epoch")) or 0)
        frame = _as_text(L.get("frame.number"))
        alpn = _as_text(L.get("tls.handshake.extensions_alpn_str"))
        raw_body = _as_text(L.get("http2.body.reassembled.data"))
        ws_body = _as_text(L.get("http2.data.data"))

        aligned = len(types) == len(sids)
        if not aligned:
            info["h2_ambiguous"] += 1
        hdr_n = val_n = cnt_n = 0
        for i, ftype in enumerate(types):
            sid = sids[i] if i < len(sids) else (sids[0] if len(sids) == 1 else "")
            if not sid or sid == "0":
                continue                      # 连接级帧（SETTINGS/PING/GOAWAY）
            key = (stream, sid, src)
            g = groups.setdefault(key, {"hdr": {}, "body": None, "body_from": "",
                                        "ts": 0.0, "src": src, "dst": dst,
                                        "alpn": "", "frame": ""})
            g["ts"] = g["ts"] or ts
            g["frame"] = g["frame"] or frame
            g["alpn"] = g["alpn"] or alpn
            if ftype == "1":                  # HEADERS
                n = int(counts[cnt_n] or 0) if cnt_n < len(counts) else 0
                for k in range(n):
                    if hdr_n + k < len(names):
                        g["hdr"].setdefault(names[hdr_n + k].lower(),
                                            vals[val_n + k] if val_n + k < len(vals) else "")
                hdr_n += n
                val_n += n
                cnt_n += 1
            elif ftype == "0":                # DATA
                if raw_body and len(raw_body) >= len(g["body"] or ""):
                    g["body"], g["body_from"] = raw_body, "raw"
                elif ws_body and not g["body"]:
                    g["body"], g["body_from"] = ws_body, "ws"

    info["h2_streams"] = len({(s, i) for s, i, _ in groups})
    for (stream, sid, _src), g in groups.items():
        h = g["hdr"]
        if ":method" in h:
            kind, method, status = "request", h[":method"], None
        elif ":status" in h:
            kind, method, status = "response", None, int(h[":status"] or 0)
        else:
            # 抓包起点落在流中间：只看见 DATA、看不见头。计数但不编造。
            info["h2_orphans"] += 1
            continue
        counter[0] += 1
        rec = {"ts": g["ts"], "frame": g["frame"], "kind": kind, "proto": "h2",
               "stream": f"{stream}/{sid}", "src": g["src"], "dst": g["dst"],
               "alpn": g["alpn"] or "h2", "gaps": []}
        if kind == "request":
            rec.update({"method": method, "host": h.get(":authority", ""),
                        "uri": h.get(":path", ""),
                        "url": f"{h.get(':scheme', 'https')}://{h.get(':authority', '')}{h.get(':path', '')}"})
        else:
            rec.update({"status": status})
        if h.get("content-type"):
            rec["content_type"] = h["content-type"]
        if h.get("content-encoding"):
            rec["content_encoding"] = h["content-encoding"]

        data = _parse_hex(g["body"]) if g["body"] else None
        if data:
            enc = (h.get("content-encoding") or "").lower()
            if g["body_from"] == "ws":
                # 实测：Wireshark 对 h2 的 DATA **自己按 content-encoding 解压**
                # （`Content-encoded entity body (gzip): 52 bytes -> 375 bytes`），
                # `-o http.decompress_body` 管不到这儿，也不需要。不能再解一次。
                rec["body_from"] = "wireshark"
                # 但得防"某个版本没解"：留 gzip 魔数就是没解，别把压缩字节当明文。
                if data[:2] == b"\x1f\x8b":
                    plain, how = _inflate_gzip(data)
                    if how == "failed":
                        rec["gaps"].append("body_still_compressed")
                    else:
                        data = plain
                        rec["decompressed"] = f"gzip:{how}"
                        if how == "truncated":
                            rec["gaps"].append("gzip_truncated")
            elif "gzip" in enc:
                plain, how = _inflate_gzip(data)
                if how == "failed":
                    rec["gaps"].append("gzip_decompress_failed")
                else:
                    data = plain
                    rec["decompressed"] = f"gzip:{how}"
                    if how == "truncated":
                        rec["gaps"].append("gzip_truncated")
            elif "deflate" in enc:
                plain, how = _inflate_deflate(data)
                if how == "failed":
                    rec["gaps"].append("deflate_decompress_failed")
                else:
                    data = plain
                    rec["decompressed"] = f"deflate:{how}"
                    if how == "truncated":
                        rec["gaps"].append("deflate_truncated")
            elif enc:
                # br/zstd 之类本机没现成解码器：如实标注，别把压缩字节当明文
                rec["gaps"].append(f"undecoded_content_encoding:{enc}")
            if len(data) > max_body:
                rec["gaps"].append(f"body_truncated_at_{max_body}")
                data = data[:max_body]
            hh = hashlib.sha256(data).hexdigest()
            name = f"{counter[0]:05d}_{hh[:12]}.bin"
            (bodies_dir / name).write_bytes(data)
            rec["body"] = {"file": name, "len": len(data), "sha256": hh}
            try:
                rec["body"]["text_head"] = data.decode("utf-8")[:400]
                rec["body"]["is_text"] = True
            except UnicodeDecodeError:
                rec["body"]["is_text"] = False
        elif kind == "response" and status not in (204, 304):
            rec["gaps"].append("no_body_bytes")
        out.append(rec)
        info["h2_messages"] += 1
    return info


def decode(pcap: Path, out_jsonl: Path, bodies_dir: Path,
           keylog: Path | None = None, tshark: str | None = None,
           max_body: int = 4 * 1024 * 1024) -> dict:
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

    extra = ["-Y", "http.request or http.response", "-T", "json"]
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
            "src": f"{row['ip.src']}:{row['tcp.srcport']}",
            "dst": f"{row['ip.dst']}:{row['tcp.dstport']}",
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
        stats["error"] = ("tshark 解出 0 条 HTTP 消息（keylog 已装但可能不匹配该连接）"
                          if stats["keylog_lines"] else
                          "tshark 解出 0 条 HTTP 消息，且没有 keylog：TLS 载荷未解密")

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
    args = ap.parse_args()

    out = Path(args.out).resolve()
    bodies = Path(args.bodies_dir) if args.bodies_dir else out.parent / "bodies"
    keylog = Path(args.keylog) if args.keylog else None
    stats_extra: dict = {}
    if keylog is None and args.session:
        keylog = out.parent / "keys.log"
        n, labels = keylog_from_events(Path(args.session), keylog)
        stats_extra = {"keylog_from_session": n, "keylog_labels": labels}

    stats = decode(Path(args.pcap).resolve(), out, bodies, keylog)
    stats.update(stats_extra)
    text = json.dumps(stats, ensure_ascii=False, indent=2)
    if args.stats:
        Path(args.stats).write_text(text + "\n", encoding="utf-8")
    print(text)
    return 0 if stats["ok"] or stats["error"] is None else 1


if __name__ == "__main__":
    raise SystemExit(main())
