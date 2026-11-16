"""行协议提取的离线测试（不碰设备）。仅用于授权测试。"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import pcap_lines  # noqa: E402
from tcp_line_reassembly import Segment, complete_lines
from test_pcap_pipeline import _tcp_frame, _write


def _nmea(body: str, checksum: str | None = None) -> str:
    if checksum is None:
        acc = 0
        for ch in body:
            acc ^= ord(ch)
        checksum = f"{acc:02X}"
    return f"${body}*{checksum}"


class ClassifyTest(unittest.TestCase):
    def test_valid_nmea_checksum(self):
        line = _nmea("GPRMC,122107,A,3954.5399,N,11623.8200,E,15.00,0.00,151126,0.0,W")
        info = pcap_lines.classify(line)
        self.assertEqual("nmea", info["proto"])
        self.assertEqual(("GP", "RMC"), (info["talker"], info["sentence"]))
        self.assertTrue(info["checksum_ok"])

    def test_constant_checksum_is_caught(self):
        # gpsdRelay 的实测缺陷：自产句校验和恒为 *47，内容一变就错。
        line = "$GPRMC,122115,A,3954.5399,N,11623.8200,E,15.00,0.00,151126,0.0,W*47"
        info = pcap_lines.classify(line)
        self.assertEqual("nmea", info["proto"])
        self.assertFalse(info["checksum_ok"])
        self.assertNotEqual("47", info["checksum_computed"])

    def test_nmea_without_checksum_is_unknown_not_wrong(self):
        info = pcap_lines.classify("$GPGGA,122107,3954.5399,N,11623.8200,E,1,6,,50.0,M,0.,M,,,")
        self.assertEqual("nmea", info["proto"])
        self.assertIsNone(info["checksum_ok"])

    def test_json_and_text(self):
        self.assertEqual("json", pcap_lines.classify('{"a":1}')["proto"])
        self.assertEqual("text", pcap_lines.classify("hello world")["proto"])

    def test_binaryish_is_not_text(self):
        self.assertEqual("binary", pcap_lines.classify("\x00\x01\x02binary")["proto"])

    def test_empty(self):
        self.assertEqual("empty", pcap_lines.classify("   ")["proto"])


class ExtractFailureTest(unittest.TestCase):
    def test_missing_pcap_reports_error_not_raise(self):
        with tempfile.TemporaryDirectory() as tmp:
            stats = pcap_lines.extract(Path(tmp) / "nope.pcap", Path(tmp) / "out.jsonl")
            self.assertFalse(stats["ok"])
            self.assertIn("pcap", stats["error"])

    def test_load_missing_file_is_empty(self):
        self.assertEqual([], pcap_lines.load(Path("no/such/lines.jsonl")))

    def test_load_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "l.jsonl"
            rows = [{"ts": 1.0, "line": "$GPRMC,x", "proto": "nmea"}]
            path.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
            self.assertEqual(rows, pcap_lines.load(path))


class HttpStreamFilterTest(unittest.TestCase):
    def test_http_request_line_is_recognised(self):
        # 这条正则决定"整条流按 HTTP 排掉"，判错就会把代理流量重复记一遍。
        self.assertTrue(pcap_lines._HTTP_START.match("GET http://x/generate_204 HTTP/1.1"))
        self.assertTrue(pcap_lines._HTTP_START.match("HTTP/1.1 200 OK"))
        self.assertFalse(pcap_lines._HTTP_START.match("$GPRMC,122107,A,1,2"))


class StreamAssemblyTest(unittest.TestCase):
    def test_tshark_reconstructs_long_json_from_a_real_pcap(self):
        if not pcap_lines.find_tshark():
            self.skipTest("需要 tshark")
        text = '{"text":"' + '测' * 500 + '"}'
        payload = (text + "\n").encode()
        with tempfile.TemporaryDirectory() as tmp:
            pcap, out = Path(tmp) / "split.pcap", Path(tmp) / "out.jsonl"
            _write(pcap, [_tcp_frame(40000, 19129, 1000, 0x02, b""),
                          _tcp_frame(40000, 19129, 1001, 0x18, payload[:701]),
                          _tcp_frame(40000, 19129, 1702, 0x18, payload[701:])])
            stats = pcap_lines.extract(pcap, out)
            self.assertEqual(1, stats["lines"])
            self.assertEqual(text, pcap_lines.load(out)[0]["line"])

    def test_split_utf8_and_retransmission_are_reassembled_once(self):
        body = '{"text":"' + '测' * 1000 + '"}'
        raw = (body + "\r\n").encode()
        parts = [Segment(101, raw[:17], "3", 3), Segment(118, raw[17:], "2", 2),
                 Segment(101, raw[:17], "4", 4)]
        counters = {"partial_lines": 0, "stream_gaps": 0, "conflicting_streams": 0}
        records = complete_lines(parts, 101, max_line=65536, diagnostics=counters)
        self.assertEqual([body], [line.decode() for line, _, _ in records])
        self.assertEqual("3", records[0][2].frame)
        self.assertEqual(0, sum(counters.values()))

    def test_gap_discards_fragments_and_restarts_after_newline(self):
        parts = [Segment(21, b"hello\nprefix", "2", 2), Segment(35, b"tail\nnext\n", "4", 4)]
        counters = {"partial_lines": 0, "stream_gaps": 0, "conflicting_streams": 0}
        records = complete_lines(parts, 21, max_line=65536, diagnostics=counters)
        self.assertEqual([b"hello", b"next"], [line for line, _, _ in records])
        self.assertEqual(1, counters["stream_gaps"])

    def test_cr_only_stream_is_split_on_cr(self):
        # AndrOBD → 假 ELM327：整条会话只有 CR，没有 LF。旧实现把 688 条命令
        # 全当成"没有边界的半行"，这里固定住退到 CR 的行为。
        raw = b"ATZ\rELM327 v1.5\r\r>ATE0\rOK\r\r>010C\r41 0C 1A F8\r\r>"
        counters = {"partial_lines": 0, "stream_gaps": 0, "conflicting_streams": 0}
        records = complete_lines([Segment(7, raw, "1", 1.0)], 7, max_line=65536,
                                 diagnostics=counters)
        lines = [line.decode() for line, _, _ in records]
        # 末尾 `>` 后面没有 CR，按"半行"丢弃（partial_lines=1）——这是有意的：
        # 不得把没结束的半行冒充成完整行。
        self.assertEqual(["ATZ", "ELM327 v1.5", "", ">ATE0", "OK", "", ">010C",
                          "41 0C 1A F8", ""], lines)
        self.assertEqual(1, counters["partial_lines"])

    def test_lf_still_wins_when_both_separators_exist(self):
        # CRLF 流不能因为"也有 CR"就被按 CR 切成双倍行。
        raw = b"GET /x HTTP/1.1\r\nHost: h\r\n\r\n"
        counters = {"partial_lines": 0, "stream_gaps": 0, "conflicting_streams": 0}
        records = complete_lines([Segment(1, raw, "1", 1.0)], 1, max_line=65536,
                                 diagnostics=counters)
        lines = [line.decode() for line, _, _ in records]
        self.assertEqual(["GET /x HTTP/1.1", "Host: h", ""], lines)


class ElmClassifyTest(unittest.TestCase):
    def test_at_command_and_reply(self):
        self.assertEqual(("obd", "at"), (pcap_lines.classify("ATZ")["proto"],
                                         pcap_lines.classify("ATZ")["obd_kind"]))
        self.assertEqual("obd", pcap_lines.classify("ATSP0")["proto"])
        self.assertEqual("status", pcap_lines.classify("OK")["obd_kind"])

    def test_hex_reply_and_pid_request(self):
        self.assertEqual("hex", pcap_lines.classify("41 0C 1A F8")["obd_kind"])
        self.assertEqual("pid", pcap_lines.classify("010C")["obd_kind"])
        self.assertEqual("pid", pcap_lines.classify("0902")["obd_kind"])

    def test_prompt_prefix_is_stripped(self):
        info = pcap_lines.classify(">ATE0")
        self.assertEqual("obd", info["proto"])
        self.assertEqual("at", info["obd_kind"])
        self.assertEqual("empty", pcap_lines.classify(">")["proto"])

    def test_plain_words_are_still_text(self):
        # 别把普通文本吞成 obd：判错类型会让 by_proto 统计失真。
        self.assertEqual("text", pcap_lines.classify("hello world")["proto"])
        self.assertEqual("text", pcap_lines.classify("Engine temperature high")["proto"])


if __name__ == "__main__":
    unittest.main()
