"""Extract transport metadata from the device pcap. 仅用于授权测试。"""
from pcap_tshark import FRIDA_LOOPBACK, _run_tshark


def transport_packets(tshark, pcap):
    fields = ("frame.number", "frame.time_epoch", "ip.src", "ip.dst",
              "ipv6.src", "ipv6.dst", "tcp.srcport", "tcp.dstport",
              "tcp.stream", "udp.srcport", "udp.dstport", "frame.protocols", "tcp.seq_raw")
    # ICMP errors include a quoted IP header which can match Wireshark's UDP/TCP fields.
    query = (f"(udp or (tcp.flags.syn == 1 and tcp.flags.ack == 0))"
             f" and not (icmp or icmpv6 or ({FRIDA_LOOPBACK}))")
    argv = ["-Y", query, "-T", "fields", "-E", "occurrence=f"]
    for field in fields:
        argv.extend(("-e", field))
    rc, output, error = _run_tshark(tshark, pcap, None, argv)
    if rc:
        raise RuntimeError(f"tshark 传输层解码失败（{rc}）：{error.strip()[:300]}")
    records = []
    malformed = 0
    for line in output.splitlines():
        columns = line.split("\t")
        if len(columns) != len(fields):
            malformed += 1
            continue
        frame, ts, src, dst, src6, dst6, tcp_src, tcp_dst, stream, udp_src, udp_dst, protocols, seq = columns
        if not ts or not (src or src6) or not (dst or dst6):
            malformed += 1
            continue
        tcp = bool(tcp_src and tcp_dst)
        records.append({
            "frame": frame, "ts": float(ts),
            "src": f"{src or src6}:{tcp_src or udp_src}",
            "dst": f"{dst or dst6}:{tcp_dst or udp_dst}",
            "transport": "tcp" if tcp else "udp", "tcp_stream": stream or None,
            "tcp_seq": seq or None,
            "quic": "quic" in protocols.split(":"),
        })
    return records, malformed
