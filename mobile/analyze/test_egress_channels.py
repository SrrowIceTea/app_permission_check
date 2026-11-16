"""外发通道汇总的离线测试。仅用于授权测试。"""
import json
import tempfile
import unittest
from pathlib import Path

import summary_sections


def _stats(tmp: str, *, legacy=False, **line) -> Path:
    path = Path(tmp) / "http-stats.json"
    payload = {"messages": 0, "http_messages_attributed": 0}
    if line:
        payload["line_messages"] = sum(line.values())
        payload["line_attribution"] = {
            "total": sum(line.values()), "attributed": sum(line.values()),
            "from_app": line.get("from_app", 0), "to_app": 0,
            "by_basis": {("listen_port" if legacy else "socket_inode_bracket"): line.get("from_app", 0)},
            "by_proto": {"nmea": line.get("from_app", 0)} if line.get("from_app") else {},
            "proto_from_app": {"nmea": line.get("from_app", 0)} if line.get("from_app") else {},
            "listen_ports": [18960] if line.get("from_app") else [],
        }
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


class EgressChannelsTest(unittest.TestCase):
    def test_listening_egress_without_other_channels_is_explicit(self):
        with tempfile.TemporaryDirectory() as tmp:
            channels = summary_sections.egress_channels(
                _stats(tmp, from_app=307), flows=[], egress_events=[])
            self.assertEqual(307, channels["pcap_line_from_app"])
            self.assertEqual([18960], channels["listening_ports"])
            text = " ".join(channels["gaps"])
            # 关键措辞：不能让人把"这条通道为空"读成"没有外发"，也不能读成强归因。
            self.assertIn("确认应用发出 307 行", text)

    def test_proxy_flows_suppress_the_pcap_only_gap(self):
        with tempfile.TemporaryDirectory() as tmp:
            channels = summary_sections.egress_channels(
                _stats(tmp, from_app=307), flows=[{"host": "api.example"}], egress_events=[])
            self.assertNotIn("确认应用发出", " ".join(channels["gaps"]))

    def test_listen_port_only_basis_is_downgraded(self):
        with tempfile.TemporaryDirectory() as tmp:
            channels = summary_sections.egress_channels(
                _stats(tmp, from_app=12, legacy=True), flows=[{"host": "x"}], egress_events=[])
            self.assertEqual(0, channels["pcap_line_from_app"])
            self.assertEqual(12, channels["pcap_line_candidate_from_app"])
            self.assertIn("未进入外发规则", " ".join(channels["gaps"]))

    def test_all_channels_empty_is_reported_as_not_seen(self):
        with tempfile.TemporaryDirectory() as tmp:
            channels = summary_sections.egress_channels(
                _stats(tmp), flows=[], egress_events=[])
            self.assertIn("不是「没有外发」", " ".join(channels["gaps"]))

    def test_missing_stats_file_is_a_gap_not_a_zero(self):
        with tempfile.TemporaryDirectory() as tmp:
            channels = summary_sections.egress_channels(
                Path(tmp) / "http-stats.json", flows=[], egress_events=[])
            self.assertIsNone(channels["pcap_line_from_app"])
            self.assertIn("缺少 http-stats.json", " ".join(channels["gaps"]))


if __name__ == "__main__":
    unittest.main()
