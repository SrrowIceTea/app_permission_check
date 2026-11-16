"""Socket attribution regressions. 仅用于授权测试。"""
import unittest
import http_attribution as attribution

UID = 1010276
LOCAL = "10.0.2.15"
PEER = "192.0.2.20"


def packet(*, ts=100, stream="1", peer=PEER, protocol="tcp", kind="request", quic=False):
    return {"src": f"{LOCAL}:40000", "dst": f"{peer}:443", "ts": ts,
            "kind": kind, "transport": protocol, "tcp_stream": stream, "quic": quic}


def socket(**fields):
    return dict({"local_ip": LOCAL, "local_port": 40000, "remote_ip": PEER,
                 "remote_port": 443, "uid": UID, "family": "tcp", "socket_inode": 23}, **fields)


class SocketAttributionTests(unittest.TestCase):
    def test_bracketed_inode_matches_request_and_response(self):
        req = packet()
        reply = packet(kind="response")
        reply["src"], reply["dst"] = reply["dst"], reply["src"]
        result = attribution.attribute([req, reply],
                                       [socket(ts=99920), socket(ts=100080)], UID)
        self.assertEqual(2, result["attributed"])

    def test_port_reuse_and_legacy_rows_never_claim_the_flow(self):
        for rows in (
            [socket(ts=99920), socket(ts=100080, socket_inode=29)],
            [socket(ts=99920), socket(ts=100080), socket(ts=100010, uid=UID+1)],
            [socket(ts=99920, remote_ip="192.0.2.21"), socket(ts=100080, remote_ip="192.0.2.21")],
            [{"uid": UID, "local_port": 40000}],
        ):
            with self.subTest(rows=rows):
                self.assertEqual(0, attribution.attribute([packet()], rows, UID)["attributed"])

    def test_tcp_short_connection_needs_exact_syn_stream_and_uid(self):
        opening = packet()
        msg, unrelated = packet(ts=101), packet(ts=101, stream="2")
        ops = [socket(transport="tcp", operation="connect", started_ms=99999,
                      ended_ms=100003, pid=45, fd=3)]
        outcome = attribution.attribute([msg, unrelated], [], UID, packets=[opening], operations=ops)
        self.assertEqual(1, outcome["attributed"])
        self.assertEqual("tcp_stream_socket_call_time", msg["attribution"])
        self.assertFalse(unrelated["attributed"])
        self.assertEqual(0, attribution.attribute([msg], [], None, packets=[opening], operations=ops)["attributed"])

    def test_udp_counts_quic_and_preserves_metadata_for_the_exact_datagram(self):
        datagram = packet(protocol="udp", quic=True)
        stray = packet(protocol="udp", quic=False, peer="192.0.2.21")
        ops = [socket(transport="udp", operation="send", started_ms=99999,
                      ended_ms=100001, pid=12, fd=5, local_ip="::ffff:10.0.2.15")]
        out = attribution.attribute([], [], UID, packets=[datagram, stray], operations=ops)
        self.assertEqual((2, 1, 1), (out["udp_total"], out["udp_attributed"], out["quic_attributed"]))
        self.assertEqual("outgoing", out["datagrams"][0]["direction"])
        self.assertEqual(0, out["attributed"])


class LineAttributionTests(unittest.TestCase):
    """监听型外发的归属（2026-11-15 gpsdRelay）：应用是监听方，没有 connect 事件。"""

    def _line(self, *, src_port, dst_port, ts=100.0, src=LOCAL, dst=PEER):
        return {"ts": ts, "src": f"{src}:{src_port}", "dst": f"{dst}:{dst_port}",
                "src_port": src_port, "dst_port": dst_port, "proto": "nmea",
                "line": "$GPRMC,x", "tcp_stream": "7"}

    def test_socket_bracket_beats_listen_port(self):
        listen = socket(local_port=18960, remote_ip="0.0.0.0", remote_port=0, state="LISTEN")
        # 括号要求**两侧**采样都落在 175ms 内（SAMPLE_MAX_GAP_MS）：单侧采样时
        # max(before, after) 是 inf，会被判成"没有括号"——这是既有语义，不是本轮改的。
        before = socket(local_port=18960, remote_port=59147, state="ESTABLISHED", ts=99950)
        after = socket(local_port=18960, remote_port=59147, state="ESTABLISHED", ts=100050)
        rows = [self._line(src_port=18960, dst_port=59147)]
        out = attribution.attribute_lines(rows, [listen, before, after], UID)
        self.assertEqual(1, out["from_app"])
        self.assertEqual({"socket_inode_bracket": 1}, out["by_basis"])
        self.assertEqual("from_app", rows[0]["direction"])

    def test_listen_port_remains_a_candidate(self):
        listen = socket(local_port=18960, remote_ip="0.0.0.0", remote_port=0, state="LISTEN")
        rows = [self._line(src_port=18960, dst_port=59147)]
        out = attribution.attribute_lines(rows, [listen], UID)
        self.assertEqual(0, out["from_app"])
        self.assertEqual(1, out["candidate_from_app"])
        self.assertFalse(rows[0]["attributed"])
        self.assertEqual({"listen_port": 1}, out["by_basis"])
        self.assertEqual([18960], out["listen_ports"])
        self.assertEqual(0, out["uid_verified"])

    def test_inbound_direction_is_not_counted_as_egress(self):
        listen = socket(local_port=18960, remote_ip="0.0.0.0", remote_port=0, state="LISTEN")
        rows = [self._line(src_port=59147, dst_port=18960)]
        out = attribution.attribute_lines(rows, [listen], UID)
        self.assertEqual((0, 0, 0), (out["attributed"], out["from_app"], out["to_app"]))
        self.assertEqual("to_app", rows[0]["candidate_direction"])

    def test_complete_syn_and_bracket_carry_identity_to_later_line(self):
        rows = [self._line(src_port=18960, dst_port=59147),
                self._line(src_port=18960, dst_port=59147, ts=110)]
        conns = [socket(local_port=18960, remote_port=59147, ts=ts) for ts in (99950, 100050)]
        packet = self._line(src_port=59147, dst_port=18960, src=PEER, dst=LOCAL, ts=99)
        packet.update(transport="tcp", tcp_seq="30")
        result = attribution.attribute_lines(rows, conns, UID, packets=[packet])
        self.assertEqual(2, result["from_app"])
        self.assertEqual("tcp_stream_socket_inode", rows[1]["attribution"])
        self.assertEqual(0, attribution.attribute_lines(
            [self._line(src_port=18960, dst_port=59147, ts=110)], conns, UID,
            packets=[packet])["from_app"])

    def test_foreign_port_is_unattributed(self):
        listen = socket(local_port=18960, remote_ip="0.0.0.0", remote_port=0, state="LISTEN")
        rows = [self._line(src_port=40000, dst_port=443)]
        out = attribution.attribute_lines(rows, [listen], UID)
        self.assertEqual(0, out["attributed"])
        self.assertEqual("unattributed", rows[0]["attribution"])
        self.assertEqual("unknown", rows[0]["direction"])


if __name__ == "__main__":
    unittest.main()
