"""Reassemble bounded TCP byte ranges into complete lines. 仅用于授权测试。"""
from bisect import bisect_right
from dataclasses import dataclass

_MASK = 2**32 - 1


@dataclass(frozen=True)
class Segment:
    seq: int
    payload: bytes
    frame: str
    ts: float


def _offset(seq, anchor):
    return ((seq - anchor + 2**31) & _MASK) - 2**31


def _separator(data):
    """选行分隔符：有 LF 就按 LF（CRLF 也归它），整段一个 LF 都没有时才退到 CR。

    为什么不能只认 LF：ELM327 / 多数 AT 命令口**只发 CR**，一条会话里没有任何
    `\\n`。只按 LF 切，这段流会被当成"永远没有边界的半行"，统计里只留下
    `partial_lines`，报告端表现为"没有可确认边界的文本行"。
    2026-11-15 实测：AndrOBD 走 TCP 连假 ELM327，回执端收到 688 条请求、
    pcap 里 4051 个载荷包，解码结果 0 行。
    """
    if b"\n" in data:
        return b"\n"
    if b"\r" in data:
        return b"\r"
    return b"\n"


def _lines(data, cuts, owners, clean_head, max_line, diagnostics):
    sep = _separator(data)
    head = 0
    if not clean_head:
        head = data.find(sep) + 1
        diagnostics["partial_lines"] += 1
        if head == 0:
            return
    while head < len(data):
        tail = data.find(sep, head)
        if tail < 0:
            diagnostics["partial_lines"] += 1
            break
        if tail - head > max_line:
            diagnostics["partial_lines"] += 1
        else:
            first_index = bisect_right(cuts, head)
            last_index = bisect_right(cuts, tail)
            first = owners[first_index]
            last = max(owners[first_index:last_index + 1], key=lambda seg: seg.ts)
            yield bytes(data[head:tail]).removesuffix(b"\r"), first, last
        head = tail + 1


def complete_lines(segments, first_payload_seq, *, max_line, diagnostics):
    """Sort by sequence, deduplicate overlaps, and drop fragments on both sides of a hole."""
    if not segments:
        return []
    anchor = segments[0].seq if first_payload_seq is None else first_payload_seq
    ordered = sorted(segments, key=lambda seg: _offset(seg.seq, anchor))
    records = []
    data = bytearray()
    cuts, owners = [], []
    start = _offset(ordered[0].seq, anchor)
    clean_head = first_payload_seq is not None and start == 0

    for seg in ordered:
        rel = _offset(seg.seq, anchor) - start
        if rel > len(data):
            diagnostics["stream_gaps"] += 1
            records.extend(_lines(data, cuts, owners, clean_head, max_line, diagnostics))
            start += rel
            clean_head = False
            data.clear()
            cuts.clear()
            owners.clear()
            rel = 0
        overlap = min(len(data) - rel, len(seg.payload))
        if overlap and data[rel:rel + overlap] != seg.payload[:overlap]:
            diagnostics["conflicting_streams"] += 1
            return []
        if overlap < len(seg.payload):
            data.extend(seg.payload[overlap:])
            cuts.append(len(data))
            owners.append(seg)

    records.extend(_lines(data, cuts, owners, clean_head, max_line, diagnostics))
    return records
