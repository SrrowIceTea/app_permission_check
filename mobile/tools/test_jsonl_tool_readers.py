#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""工具侧 JSONL 读取的守卫：**只按 LF 分行**（2026-10-20）。

仅用于授权测试（自有设备 / 已授权的公开第三方样本）。

为什么要有这一条：JSON 字符串里允许出现 U+0085(NEL)/U+2028/U+2029，而
`str.splitlines()` 把它们**也当换行**。mitm 落盘的 flow 记录里 `response_payload.text`
是 latin-1 解码出的正文，二进制响应里 0x85 遍地都是——实测
`36-ign-geoportail/session/flows.jsonl` 一条 6.7KB 的记录含 **59 个 U+0085**，
用 splitlines() 读会把 34 条记录切成 93 段无法解析的碎片，全部当坏行丢掉。

`core/io_utils` 早已改成只认 LF，但**工具侧还有几处自己手写的读取**；这些位置的
误判方向恰好都是"把采到的读成没采到"：
  * `supplementary_evidence`：旁路证据索引（egress/conns/http）条数变成下界；
  * `fixture_selftest`：批前阳性对照，零事件 = 拒绝出批；
  * `device_run_thirdparty`：`hook_*_armed` / `runtime_events_captured` 判据；
  * `pcap_http.keylog_from_events`：口径统一（这一路的 keylog 行本身是 ASCII hex，
    受影响的实际风险最低，但"同一份文件两种分行口径"不该留在仓库里）。

注意边界：`splitlines()` 只损坏**含分隔符的那一条记录**（它自己被切成不可解析的
碎片），不会连带后面的记录。所以影响是"少几条"，不是"整份读不出来"——但本项目
的判据大量是"有没有 ≥1 条"，少数几条的下限就足以翻转结论。
"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "mobile" / "rules"))   # mobile_rules_inputs 的导入方式

from core.io_utils import load_jsonl_counting, split_jsonl_lines  # noqa: E402

# 三个 Unicode 行分隔符 + 一个会出现在真实正文里的 CRLF
NASTY = "a\u2028b\u0085c\u2029d\r\ne"


class SplitJsonlLinesTest(unittest.TestCase):
    def test_separators_inside_string_do_not_split_records(self):
        rows = [{"text": NASTY}, {"text": NASTY}]
        text = "\n".join(json.dumps(r, ensure_ascii=False) for r in rows) + "\n"
        self.assertEqual(2, len(split_jsonl_lines(text)))
        self.assertGreater(len(text.splitlines()), 2,
                           "自检：splitlines() 必须在这里多切出几段，否则用例没意义")

    def test_crlf_file_parses_without_bad_lines(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "flows.jsonl"
            rows = [{"text": NASTY}]
            path.write_bytes(("\r\n".join(json.dumps(r, ensure_ascii=False) for r in rows)
                              + "\r\n").encode())
            self.assertEqual((rows, 0), load_jsonl_counting(path))


class ToolReaderTest(unittest.TestCase):
    def _write(self, folder: str) -> Path:
        path = Path(folder) / "reads.jsonl"
        path.write_text("\n".join(json.dumps(r, ensure_ascii=False) for r in (
            {"ev": "ARMED", "note": NASTY},
            {"ev": "PRIVACY_READ", "stack": NASTY},
        )) + "\n", encoding="utf-8")
        return path

    def test_supplementary_evidence_reader(self):
        import supplementary_evidence as se  # noqa: PLC0415
        with tempfile.TemporaryDirectory() as folder:
            rows = se.read_jsonl(self._write(folder))
        self.assertEqual(["ARMED", "PRIVACY_READ"], [r["ev"] for r in rows])

    def test_fixture_selftest_reader(self):
        import fixture_selftest as fs  # noqa: PLC0415
        with tempfile.TemporaryDirectory() as folder:
            rows = fs.read_events(self._write(folder))
        self.assertEqual(2, len(rows))

    def test_rules_inputs_reader(self):
        """规则库的输入读取（构建规则库时用）也必须是同一口径。"""
        import mobile_rules_inputs as mri  # noqa: PLC0415
        with tempfile.TemporaryDirectory() as folder:
            rows = mri.read_jsonl(self._write(folder))
        self.assertEqual(2, len(rows))

    def test_keylog_reader_shares_the_same_framing(self):
        """同一份 session 里两种分行口径不该并存：tls_meta 的 keylog 行要读得出来。"""
        import pcap_http  # noqa: PLC0415
        with tempfile.TemporaryDirectory() as folder:
            session = Path(folder)
            (session / "tls_meta.jsonl").write_text("\n".join(json.dumps(r, ensure_ascii=False)
                                                              for r in (
                {"ev": "TLS_META", "detail": NASTY},
                {"ev": "TLS_KEYLOG", "line": "CLIENT_RANDOM " + "ab" * 32 + " " + "cd" * 48},
            )) + "\n", encoding="utf-8")
            keys = session / "keys.log"
            n, _labels = pcap_http.keylog_from_events(session, keys)
            self.assertEqual(1, n)
            self.assertIn("CLIENT_RANDOM", keys.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
