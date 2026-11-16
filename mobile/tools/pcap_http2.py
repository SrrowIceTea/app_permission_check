"""Decode HTTP/2 frames emitted by tshark. 仅用于授权测试。"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from pcap_tshark import FRIDA_LOOPBACK, _as_text, _parse_hex, _run_tshark


_H2_FIELDS = [
    "frame.number", "frame.time_epoch", "ip.src", "ip.dst", "ipv6.src", "ipv6.dst",
    "tcp.srcport", "tcp.dstport",
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
        except zlib.error:  # noqa: BLE001 - 尝试另一种 DEFLATE 封装，两种都失败时报告解压失败
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
    extra = ["-Y", f"http2 and not ({FRIDA_LOOPBACK})", "-T", "json"]
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
        src = f"{_as_text(L.get('ip.src') or L.get('ipv6.src'))}:{_as_text(L.get('tcp.srcport'))}"
        dst = f"{_as_text(L.get('ip.dst') or L.get('ipv6.dst'))}:{_as_text(L.get('tcp.dstport'))}"
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
               "stream": f"{stream}/{sid}", "tcp_stream": stream, "src": g["src"], "dst": g["dst"],
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
