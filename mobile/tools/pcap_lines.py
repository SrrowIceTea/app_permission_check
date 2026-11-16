#!/usr/bin/env python3
"""Decode newline-delimited cleartext TCP, including NMEA and JSON. 仅用于授权测试。"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from pcap_tshark import FRIDA_LOOPBACK, _run_tshark, find_tshark
from tcp_line_reassembly import Segment, complete_lines

_FIELDS = (
    "frame.number", "frame.time_epoch", "ip.src", "ipv6.src", "ip.dst", "ipv6.dst",
    "tcp.srcport", "tcp.dstport", "tcp.stream", "tcp.seq_raw", "tcp.flags.syn",
    "tcp.payload", "frame.protocols",
)
_NMEA = re.compile(r"^\$(?P<talker>[A-Z]{2})(?P<sentence>[A-Z0-9]{3}),")
_HTTP_START = re.compile(r"^(?:[A-Z]{3,7} \S+ HTTP/1\.[01]|HTTP/1\.[01] \d{3})")
# ELM327 / OBD-II：`ATZ` 这类命令、`41 0C 1A F8` 这类应答、`010C` 这类 PID 请求。
# 车载诊断几乎都走这套"CR 结束 + 可打印大写十六进制"的行协议，不认它等于整车诊断场景全盲
# （2026-11-15 AndrOBD 实测：688 条请求在报告里 0 行）。
_ELM_AT = re.compile(r"^(?:AT|ST)[A-Z0-9@!_.\-]{1,16}$")
_ELM_STATUS = frozenset({
    "OK", "?", "NO DATA", "SEARCHING...", "SEARCHING…", "STOPPED",
    "BUFFER FULL", "ERROR", "UNABLE TO CONNECT", "CAN ERROR", "BUS INIT: ...OK",
})
_OBD_HEX = re.compile(r"^[0-9A-F]{2}(?: [0-9A-F]{2}){0,31}$")
_OBD_PID = re.compile(r"^(?:0[0-9A-F]|[1-9A-F][0-9A-F])(?:[0-9A-F]{2}){1,7}$")
_MAX_LINE = 64 * 1024
_MAX_BYTES = 64 * 1024 * 1024


def _checksum(body: str) -> str:
    acc = 0
    for ch in body:
        acc ^= ord(ch)
    return f"{acc:02X}"


def classify(line: str) -> dict:
    # ELM327 在每条应答后发 `>` 提示符；切成行以后它会粘在下一句前面（`>ATZ`）。
    text = line.strip("\r\n").lstrip(">").strip()
    if not text:
        return {"proto": "empty"}
    match = _NMEA.match(text)
    if match:
        body, star, check = text.rpartition("*")
        if not star:
            body = text
        got = _checksum(body[1:])
        want = check.upper() if re.fullmatch(r"[0-9a-fA-F]{2}", check) else None
        return {"proto": "nmea", **match.groupdict(), "checksum": want,
                "checksum_computed": got, "checksum_ok": got == want if want else None}
    if text[:1] in "{[":
        try:
            json.loads(text)
            return {"proto": "json"}
        except (ValueError, RecursionError):
            return {"proto": "text", "json_invalid": True}
    if text in _ELM_STATUS:
        return {"proto": "obd", "obd_kind": "status"}
    if _ELM_AT.match(text):
        return {"proto": "obd", "obd_kind": "at"}
    if _OBD_HEX.match(text):
        return {"proto": "obd", "obd_kind": "hex"}
    if _OBD_PID.match(text):
        return {"proto": "obd", "obd_kind": "pid"}
    printable = sum(ch.isprintable() for ch in text) / len(text)
    return {"proto": "text" if printable >= 0.9 else "binary"}


def _assemble(rows, stats, max_lines, stream_allow=None):
    candidates = defaultdict(list)
    syns = defaultdict(set)
    excluded = set()
    total_bytes = 0
    for raw in rows:
        parts = raw.split("\t")
        if len(parts) != len(_FIELDS):
            stats["malformed_rows"] += 1
            continue
        frame, ts, ip, ip6, peer, peer6, srcp, dstp, stream, seq, syn, payload, protocols = parts
        if not stream or (stream_allow is not None and stream not in stream_allow):
            continue
        if {"http", "http2", "tls"} & set(protocols.split(":")):
            excluded.add(stream)
            continue
        if not (ip or ip6) or not (peer or peer6) or not srcp.isdigit() or not dstp.isdigit():
            stats["malformed_rows"] += 1
            continue
        try:
            seqno = int(seq)
            timestamp = float(ts)
            data = bytes.fromhex(payload.replace(":", ""))
        except ValueError:
            stats["malformed_rows"] += 1
            continue
        key = (stream, f"{ip or ip6}:{srcp}", f"{peer or peer6}:{dstp}", int(srcp), int(dstp))
        if syn in ("1", "True"):
            seqno = (seqno + 1) & (2**32 - 1)
            syns[key].add(seqno)
        if data:
            total_bytes += len(data)
            if total_bytes > _MAX_BYTES:
                stats["truncated_at"] = "byte_limit"
                break
            candidates[key].append(Segment(seqno, data, frame, timestamp))

    records = []
    for key, segments in candidates.items():
        stream, src, dst, srcp, dstp = key
        if stream in excluded:
            continue
        sequence = syns.get(key, set())
        if len(sequence) > 1:
            stats["conflicting_streams"] += 1
            continue
        for data, first, last in complete_lines(
                segments, next(iter(sequence), None), max_line=_MAX_LINE, diagnostics=stats):
            try:
                text = data.decode("utf-8")
            except UnicodeDecodeError:
                stats["binary_payloads"] += 1
                continue
            if _HTTP_START.match(text):
                excluded.add(stream)
                break
            info = classify(text)
            if info["proto"] == "binary":
                stats["binary_payloads"] += 1
            elif info["proto"] != "empty":
                records.append({"ts": last.ts, "first_ts": first.ts, "frame": last.frame,
                                "first_frame": first.frame, "kind": "line", "src": src, "dst": dst,
                                "tcp_stream": stream, "line": text, "src_port": srcp,
                                "dst_port": dstp, **info})
    stats["http_streams_skipped"] = len(excluded)
    records = sorted((row for row in records if row["tcp_stream"] not in excluded),
                     key=lambda row: (int(row["frame"]), int(row["first_frame"])))
    if len(records) > max_lines:
        stats["truncated_at"] = max_lines
    return records[:max_lines]


def extract(pcap: Path, out_jsonl: Path, tshark: str | None = None,
            max_lines: int = 20000, stream_allow: set[str] | None = None) -> dict:
    stats = {"tshark": tshark or find_tshark(), "ok": False, "lines": 0,
             "streams": 0, "by_proto": {}, "checksum_bad": 0, "partial_lines": 0,
             "binary_payloads": 0, "stream_gaps": 0, "conflicting_streams": 0,
             "malformed_rows": 0, "http_streams_skipped": 0, "truncated_at": None, "error": None}
    if not stats["tshark"]:
        stats["error"] = "未找到 tshark（装 Wireshark 或设 VSCAN_TSHARK）"
        return stats
    if not pcap.exists() or pcap.stat().st_size <= 24:
        stats["error"] = f"pcap 不存在或为空：{pcap}"
        return stats

    query = f"(tcp.len > 0 or tcp.flags.syn == 1) and not (icmp or icmpv6 or ({FRIDA_LOOPBACK}))"
    extra = ["-Y", query, "-T", "fields", "-E", "occurrence=f"]
    for field in _FIELDS:
        extra += ["-e", field]
    rc, text, err = _run_tshark(stats["tshark"], pcap, None, extra)
    if rc:
        stats["error"] = f"tshark rc={rc}: {err.strip()[:300]}"
        return stats
    records = _assemble(text.splitlines(), stats, max_lines, stream_allow)
    out_jsonl.parent.mkdir(parents=True, exist_ok=True)
    with out_jsonl.open("w", encoding="utf-8") as handle:
        for rec in records:
            handle.write(json.dumps(rec, ensure_ascii=False) + "\n")
    stats.update(lines=len(records), streams=len({row["tcp_stream"] for row in records}),
                 by_proto=dict(Counter(row["proto"] for row in records)),
                 checksum_bad=sum(row.get("checksum_ok") is False for row in records),
                 ok=bool(records))
    if not records:
        stats["error"] = "未找到可确认边界的 UTF-8 TCP 文本行"
    return stats


def load(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").split("\n") if line.strip()]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--pcap", required=True, type=Path)
    ap.add_argument("--out", required=True, type=Path)
    ap.add_argument("--stats", type=Path)
    args = ap.parse_args()
    stats = extract(args.pcap.resolve(), args.out.resolve())
    text = json.dumps(stats, ensure_ascii=False, indent=2)
    if args.stats:
        args.stats.write_text(text + "\n", encoding="utf-8")
    print(text)
    return 0 if stats["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
