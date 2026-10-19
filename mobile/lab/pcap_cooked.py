"""Linux cooked PCAP headers; read-only, 仅用于授权测试。

Header layouts: https://github.com/the-tcpdump-group/libpcap/blob/master/pcap/sll.h
All multi-byte fields are network byte order, independent of PCAP file endian.
"""
from __future__ import annotations

import struct


def unwrap_cooked(data: bytes, linktype: int, out: dict) -> bytes:
    """Strip SLL/SLL2 while preserving observed interface and direction metadata."""
    if linktype == 113:
        if len(data) < 16:
            raise ValueError("linux_sll_header_truncated")
        packet_type, hardware_type, address_length, _, ethertype = struct.unpack(
            "!HHH8sH", data[:16])
        size = 16
    elif linktype == 276:
        if len(data) < 20:
            raise ValueError("linux_sll2_header_truncated")
        ethertype, reserved, ifindex, hardware_type, packet_type, address_length, _ = struct.unpack(
            "!HHIHBB8s", data[:20])
        out.update(ifindex=ifindex, sll2_reserved=reserved)
        size = 20
    else:
        raise ValueError("unsupported_linktype")
    out.update(ethertype=ethertype, cooked_packet_type=packet_type,
               cooked_hardware_type=hardware_type, cooked_address_length=address_length)
    if ethertype not in (0x0800, 0x86DD):
        raise ValueError("unsupported_ethertype")
    return data[size:]
