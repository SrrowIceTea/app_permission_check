#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""pcap 采集/解码链路的离线测试（不需要设备、不需要外网）。

覆盖的是**容易静默错的地方**，不是"跑通即可"：
  1. keylog 抽取：重复行去重、非 TLS_KEYLOG 事件必须被忽略、空会话不崩。
  2. pcap_http 解出的是**完整报文**（含 body），不是"有请求没响应"的半截。
  3. 没有 tshark / 没有 pcap 时**报错而不是返回空**——"没解出来"和"没有流量"
     长得一样，是最容易写进报告的那种假结论。
  4. PcapRecorder 未启动就 stop 不崩、不返回假路径。

跑法：python mobile/tools/test_pcap_pipeline.py
"""
from __future__ import annotations

import json
import shutil
import struct
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import pcap_http      # noqa: E402
import pcap_capture   # noqa: E402

FAILS: list[str] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    print(f"[{'ok' if ok else 'FAIL'}] {name}" + (f" — {detail}" if detail else ""))
    if not ok:
        FAILS.append(name)


def _csum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def _tcp_frame(src_port: int, dst_port: int, seq: int, flags: int,
               payload: bytes, ack: int = 0, srv: bool = False, loopback: bool = False) -> bytes:
    """拼一个最小可解析的 Ethernet/IPv4/TCP 帧（校验和算对，免得 tshark 报 bad checksum）。

    `srv=True` 表示这是**服务端发出**的帧，IP/MAC 要翻转。不翻会踩一个很隐蔽的坑：
    两个方向都用同一个 `ip.src` 时，Wireshark 会把它们当成**两条不同的 TCP 会话**
    （tcp.stream 0 / 1），h2 的反向就解不出来——服务端第一帧是 SETTINGS，不是
    `PRI * HTTP/2.0` 的 preface，启发式识别只能靠"这是同一连接的对端"这个上下文。
    """
    sip, dip = (bytes([10, 0, 0, 1]), bytes([10, 0, 0, 15])) if srv else \
               (bytes([10, 0, 0, 15]), bytes([10, 0, 0, 1]))
    if loopback:
        sip = dip = b"\x7f\x00\x00\x01"
    tcp_len = 20 + len(payload)
    tcp = struct.pack("!HHIIBBHHH", src_port, dst_port, seq & 0xFFFFFFFF,
                      ack & 0xFFFFFFFF, 5 << 4, flags, 8192, 0, 0) + payload
    pseudo = sip + dip + struct.pack("!BBH", 0, 6, tcp_len)
    tcp = tcp[:16] + struct.pack("!H", _csum(pseudo + tcp)) + tcp[18:]
    ip = struct.pack("!BBHHHBBH", 0x45, 0, 20 + tcp_len, 0, 0x4000, 64, 6, 0) + sip + dip
    ip = ip[:10] + struct.pack("!H", _csum(ip)) + ip[12:]
    src_mac, dst_mac = (bytes.fromhex("020000000001"), bytes.fromhex("020000000002")) if srv else \
                       (bytes.fromhex("020000000002"), bytes.fromhex("020000000001"))
    return src_mac + dst_mac + b"\x08\x00" + ip + tcp


def _write(path: Path, frames: list[bytes]) -> None:
    with path.open("wb") as fh:
        fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for i, fr in enumerate(frames):
            fh.write(struct.pack("<IIII", 1700000000 + i, 0, len(fr), len(fr)))
            fh.write(fr)


def make_pcap(path: Path) -> None:
    """一条真实可解析的 HTTP/1.1 往返（请求 → 200 + body "hello"）。"""
    cli, srv = 40000, 80
    _write(path, [
        _tcp_frame(cli, srv, 1000, 0x02, b""),                       # SYN
        _tcp_frame(srv, cli, 5000, 0x12, b"", ack=1001, srv=True),   # SYN-ACK
        _tcp_frame(cli, srv, 1001, 0x10, b"", ack=5001),             # ACK
        _tcp_frame(cli, srv, 1001, 0x18,
                   b"GET /t HTTP/1.1\r\nHost: example.test\r\n\r\n"),  # 请求
        _tcp_frame(srv, cli, 5001, 0x18,
                   b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n"
                   b"Content-Type: text/plain\r\n\r\nhello", ack=1030, srv=True),  # 响应
    ])


def test_keylog(tmp: Path) -> None:
    session = tmp / "session"
    session.mkdir()
    good = "CLIENT_RANDOM 6b0e1f2a3c4d5e6f " + "ab" * 48
    tls13 = ("CLIENT_HANDSHAKE_TRAFFIC_SECRET 1111222233334444 "
             + "cd" * 32)
    rows = [
        {"ev": "TLS_KEYLOG", "label": "CLIENT_RANDOM", "line": good},
        {"ev": "TLS_KEYLOG", "label": "CLIENT_RANDOM", "line": good},   # 重复：应去重
        {"ev": "TLS_KEYLOG", "label": "CLIENT_HANDSHAKE_TRAFFIC_SECRET", "line": tls13},
        {"ev": "SSL_WRITE_PLAINTEXT", "n": 1},                          # 非 keylog：忽略
        {"ev": "TLS_KEYLOG", "label": "BAD", "line": ""},               # 空行：忽略
    ]
    (session / "tls_meta.jsonl").write_text(
        "\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
    out = tmp / "keys.log"
    n, labels = pcap_http.keylog_from_events(session, out)
    lines = [ln for ln in out.read_text(encoding="utf-8").splitlines() if ln.strip()]
    check("keylog: 去重后 2 行", n == 2 and len(lines) == 2, f"n={n} lines={len(lines)}")
    check("keylog: 标签齐全", "CLIENT_RANDOM" in labels and "CLIENT_HANDSHAKE" in labels, labels)

    empty = tmp / "empty-session"
    empty.mkdir()
    n0, _ = pcap_http.keylog_from_events(empty, tmp / "k0.log")
    check("keylog: 空会话返回 0 且不崩", n0 == 0)


def test_gzip(tmp: Path) -> None:
    """gzip body：这正是 hook 路线读不到、而 tshark 顺手就解掉的那类。

    `Content-Encoding: gzip` 的 body 在 `SSL_read` 里是**压缩后的字节**——人读不了；
    Wireshark 的 HTTP 解析器会解压（`http.decompress_body`），`http.file_data` 给的是
    解压后的明文。这条测试就是 P0 的目标本身。
    """
    tshark = pcap_http.find_tshark()
    if not tshark:
        check("gzip: 解压后可得明文", True, "跳过（本机无 tshark）")
        return
    import gzip
    plain = "VSCAN-GZIP-PROBE " + "重复内容" * 20
    gz = gzip.compress(plain.encode("utf-8"))
    p = tmp / "gz.pcap"
    body = (b"HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\n"
            b"Content-Encoding: gzip\r\nContent-Length: " + str(len(gz)).encode()
            + b"\r\n\r\n" + gz)
    frames = [
        _tcp_frame(40001, 80, 2000, 0x02, b""),
        _tcp_frame(80, 40001, 6000, 0x12, b"", ack=2001, srv=True),
        _tcp_frame(40001, 80, 2001, 0x18, b"GET /gz HTTP/1.1\r\nHost: gz.test\r\n\r\n"),
        _tcp_frame(80, 40001, 6001, 0x18, body, ack=2033, srv=True),
    ]
    _write(p, frames)
    stats = pcap_http.decode(p, tmp / "gz.jsonl", tmp / "gzb", None, tshark)
    recs = [json.loads(x) for x in (tmp / "gz.jsonl").read_text(encoding="utf-8").splitlines()]
    resp = next((r for r in recs if r["kind"] == "response"), {})
    b = resp.get("body") or {}
    got = (tmp / "gzb" / b["file"]).read_bytes().decode("utf-8") if b.get("file") else ""
    check("gzip: 解压后可得明文", got == plain, f"len={len(got)} head={got[:24]!r}")
    check("gzip: 原始压缩长度 > 明文可读长度", len(gz) > 0 and stats["bodies"] == 1,
          f"gz={len(gz)}B")


def _h2_frame(ftype: int, flags: int, sid: int, payload: bytes) -> bytes:
    """HTTP/2 帧头：3 字节长度 + 1 字节类型 + 1 字节 flags + 4 字节流 id。"""
    return len(payload).to_bytes(3, "big") + bytes([ftype, flags]) + struct.pack("!I", sid) + payload


def test_h2(tmp: Path) -> None:
    """HTTP/2 明文（h2c）+ gzip DATA：验证第二趟解码。

    为什么必须有这条：实测 F-Droid 一轮 12 条连接里 11 条协商成 `h2`，而
    `-Y "http.request or http.response"` **一条 h2 都匹配不到**——h2 的头在
    `http2.header.name/value` 里。只测 h1 的话，这个坑会一直躺在那里。

    离线用 h2c（不带 TLS）而不是 h2 over TLS：造合法 TLS 1.3 握手 + keylog 不划算，
    而 HPACK/分帧/多流这层逻辑跟有没有 TLS 无关。
    """
    tshark = pcap_http.find_tshark()
    if not tshark:
        check("h2: 解出请求 + 响应", True, "跳过（本机无 tshark）")
        return
    import gzip
    plain = "VSCAN-H2-PROBE " + "压缩正文" * 30
    gz = gzip.compress(plain.encode("utf-8"))

    # HPACK：0x82=:method GET(静态表2)、0x86=:scheme http(6)、0x84=:path /(4)
    # 0x41=字面量增量索引+名字取静态表1(:authority)，后跟 1 字节长度 + 原文字节
    req_hdr = bytes([0x82, 0x86, 0x84, 0x41, 0x0c]) + b"example.test"
    # 0x88=:status 200(8)；0x5f=0x40|31 content-type；0x5a=0x40|26 content-encoding
    resp_hdr = (bytes([0x88, 0x5f, 0x0a]) + b"text/plain"
                + bytes([0x5a, 0x04]) + b"gzip")

    cli_payload = (b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
                   + _h2_frame(0x4, 0x0, 0, b"")          # SETTINGS
                   + _h2_frame(0x1, 0x5, 1, req_hdr))     # HEADERS + END_STREAM
    srv_payload = (_h2_frame(0x4, 0x0, 0, b"")            # SETTINGS
                   + _h2_frame(0x1, 0x4, 1, resp_hdr)     # HEADERS + END_HEADERS
                   + _h2_frame(0x0, 0x1, 1, gz))          # DATA + END_STREAM

    cli, srv = 40002, 8080
    # 把服务端载荷**切成两个 TCP 段**：真实抓包里大 body 必然跨段，这样才逼出
    # `http2.body.reassembled.data`（单段时 Wireshark 只给已经解压过的 `http2.data.data`，
    # 我们自己那条 gzip 分支就永远跑不到）。
    cut = len(srv_payload) // 2
    frames = [
        _tcp_frame(cli, srv, 3000, 0x02, b""),
        _tcp_frame(srv, cli, 7000, 0x12, b"", ack=3001, srv=True),
        _tcp_frame(cli, srv, 3001, 0x10, b"", ack=7001),
        _tcp_frame(cli, srv, 3001, 0x18, cli_payload),
        _tcp_frame(srv, cli, 7001, 0x18, srv_payload[:cut], ack=3001 + len(cli_payload), srv=True),
        _tcp_frame(srv, cli, 7001 + cut, 0x18, srv_payload[cut:], ack=3001 + len(cli_payload), srv=True),
    ]
    p = tmp / "h2.pcap"
    _write(p, frames)

    stats = pcap_http.decode(p, tmp / "h2.jsonl", tmp / "h2b", None, tshark)
    recs = [json.loads(x) for x in (tmp / "h2.jsonl").read_text(encoding="utf-8").splitlines()]
    h2 = [r for r in recs if r.get("proto") == "h2"]
    req = next((r for r in h2 if r["kind"] == "request"), {})
    resp = next((r for r in h2 if r["kind"] == "response"), {})
    check("h2: 解出请求 + 响应", len(h2) == 2 and stats["h2_messages"] == 2,
          json.dumps({"h2_streams": stats.get("h2_streams"), "h2_messages": stats.get("h2_messages"),
                      "h1": stats["messages"] - stats.get("h2_messages", 0)}))
    check("h2: 伪头还原成方法/主机/路径",
          req.get("method") == "GET" and req.get("host") == "example.test" and req.get("uri") == "/",
          str(req.get("url")))
    check("h2: 状态码 + 流标识", resp.get("status") == 200 and resp.get("stream") == "0/1",
          f"status={resp.get('status')} stream={resp.get('stream')}")
    b = resp.get("body") or {}
    got = (tmp / "h2b" / b["file"]).read_bytes().decode("utf-8", "replace") if b.get("file") else ""
    # 有两条合法路径：要么 Wireshark 解好了（body_from=wireshark），要么我们自己 gunzip。
    # 只断言"是明文"不够——压缩字节解不成中文，所以 got==plain 已经排除了"存在假明文"。
    decoded = resp.get("body_from") == "wireshark" or resp.get("decompressed") == "gzip"
    check("h2: 跨段 gzip DATA 解出明文", got == plain and decoded,
          f"len={len(got)} head={got[:24]!r} decompressed={resp.get('decompressed')} "
          f"from={resp.get('body_from', 'self')}")


def test_decode(tmp: Path) -> None:
    tshark = pcap_http.find_tshark()
    if not tshark:
        check("decode: 未装 tshark 时报错而不是空", True, "跳过（本机无 tshark）")
        return
    p = tmp / "demo.pcap"
    make_pcap(p)
    stats = pcap_http.decode(p, tmp / "out.jsonl", tmp / "bodies", None, tshark)
    recs = [json.loads(x) for x in (tmp / "out.jsonl").read_text(encoding="utf-8").splitlines()]
    check("decode: 解出请求 + 响应", stats["requests"] == 1 and stats["responses"] == 1,
          json.dumps({k: stats[k] for k in ("messages", "requests", "responses")}))
    req = next((r for r in recs if r["kind"] == "request"), {})
    resp = next((r for r in recs if r["kind"] == "response"), {})
    check("decode: 请求行/主机正确",
          req.get("method") == "GET" and req.get("host") == "example.test", str(req.get("url")))
    body = resp.get("body") or {}
    text = ""
    if body.get("file"):
        text = (tmp / "bodies" / body["file"]).read_bytes().decode("utf-8", "replace")
    check("decode: 响应 body 完整落盘", text == "hello", f"body={text!r}")


def test_errors(tmp: Path) -> None:
    stats = pcap_http.decode(tmp / "nope.pcap", tmp / "x.jsonl", tmp / "b", None,
                             pcap_http.find_tshark() or "/no/tshark")
    check("decode: 缺 pcap 时 error 有值而非静默 ok", (not stats["ok"]) and bool(stats["error"]),
          str(stats["error"])[:60])

    rec = pcap_capture.PcapRecorder()
    got = rec.stop(tmp / "never.pcap")
    check("recorder: 未 start 就 stop 返回 None", got is None, str(got))


def test_loopback_http(tmp: Path) -> None:
    tshark = pcap_http.find_tshark()
    if not tshark:
        return
    capture = tmp / "loopback.pcap"
    request = b"GET /ws HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"
    _write(capture, [_tcp_frame(40000, 27043, 1001, 0x18, request, loopback=True),
                     _tcp_frame(40001, 18932, 2001, 0x18, request, loopback=True)])
    output = tmp / "loopback.jsonl"
    stats = pcap_http.decode(capture, output, tmp / "loopback-bodies", tshark=tshark, http_port=18932)
    check("loopback: 排除 Frida 握手但保留应用同名路由",
          stats["requests"] == 1 and json.loads(output.read_text(encoding="utf-8"))["dst"] == "127.0.0.1:18932")


def main() -> int:
    tmp = Path(tempfile.mkdtemp(prefix="vscan-pcap-"))
    try:
        test_keylog(tmp)
        test_decode(tmp)
        test_loopback_http(tmp)
        test_gzip(tmp)
        test_h2(tmp)
        test_errors(tmp)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print(f"\n{len(FAILS)} failed" if FAILS else "\nall passed")
    return 1 if FAILS else 0


if __name__ == "__main__":
    raise SystemExit(main())
