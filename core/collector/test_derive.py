#!/usr/bin/env python3
"""derive.py 离线单测 —— 派生值候选（C1）的编码/摘要/解码三族行为。

仅用于授权测试（已获授权的样本与设备）。

跑法：python -m unittest test_derive   （在 core/collector 目录下）

这一族函数错了**不会报错**，只会静默漏配（该命中没命中）或——更糟——
把垃圾解码当形态（假线索）。所以两边的边界都要钉死：正向可复现、
垃圾不解码、规模上限生效。
"""
from __future__ import annotations

import base64
import gzip
import hashlib
import unittest

import derive


def h16(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()[:16]


IMEI = "490154203237518"


class OnewayTest(unittest.TestCase):
    def test_known_md5_vector(self):
        self.assertEqual(derive.oneway_hexes("abc")["md5"],
                         "900150983cd24fb0d6963f7d28e17f72")

    def test_candidates_are_hash16_of_the_hex_string(self):
        cands = derive.hash16_candidates(IMEI)
        self.assertEqual(cands["md5"], h16(hashlib.md5(IMEI.encode()).hexdigest()))
        self.assertEqual(cands["sha1"], h16(hashlib.sha1(IMEI.encode()).hexdigest()))
        self.assertEqual(cands["sha256"], h16(hashlib.sha256(IMEI.encode()).hexdigest()))

    def test_candidates_differ_from_raw_hash(self):
        """摘要候选 ≠ 原值哈希：这正是它俩能区分「发明文」和「发摘要」的原因。"""
        cands = derive.hash16_candidates(IMEI)
        self.assertNotEqual(cands["raw"] if "raw" in cands else h16(IMEI), cands["md5"])
        self.assertNotIn("raw", cands, "候选只含摘要形态；raw 由读取事件的 value_hash 提供")


class ReversibleTest(unittest.TestCase):
    def test_base64_encoded_imei_decodes(self):
        payload = f"user=x&d={base64.b64encode(IMEI.encode()).decode()}"
        forms = dict(derive.reversible_decodings(payload))
        self.assertIn("b64", forms)
        self.assertEqual(forms["b64"], IMEI)

    def test_hex_encoded_value_decodes(self):
        payload = "raw=" + IMEI.encode().hex()
        forms = dict(derive.reversible_decodings(payload))
        self.assertEqual(forms.get("hex"), IMEI)

    def test_url_encoded_mac_decodes(self):
        mac = "3C:5A:B4:11:22:33"
        payload = f"mac=%33%43%3A%35%41"  # "3C:5A" 的全量百分号编码片段
        forms = dict(derive.reversible_decodings(payload + "&mac2=" + mac.replace(":", "%3A")))
        self.assertIn("url", forms)
        self.assertIn(mac, forms["url"])

    def test_gzip_b64_decodes(self):
        gz = gzip.compress(IMEI.encode())
        payload = "d=" + base64.b64encode(gz).decode()
        forms = dict(derive.reversible_decodings(payload))
        self.assertIn("gzip_b64", forms)
        self.assertEqual(forms["gzip_b64"], IMEI)

    def test_plain_text_yields_nothing(self):
        self.assertEqual(derive.reversible_decodings(
            '{"msg":"hello world, nothing encoded here"}'), [])

    def test_garbage_b64_run_does_not_decode_to_sensitive(self):
        """24+ 位的合法 b64 串很多，解出来是二进制乱码的必须被 printable 关卡拦掉。"""
        junk = base64.b64encode(bytes(range(256)) * 4).decode()  # 二进制 → 解码仍二进制
        out = derive.reversible_decodings("blob " + junk + " end")
        self.assertEqual([f for f, _ in out if f == "b64"], [],
                         "二进制乱码不得通过可打印性检查")

    def test_oversized_text_is_skipped(self):
        self.assertEqual(derive.reversible_decodings("a" * (derive.MAX_TEXT + 1)), [])

    def test_run_count_cap(self):
        """超过 MAX_RUNS 个候选串后停止尝试（不炸不挂）。"""
        run = base64.b64encode(b"A" * 24).decode()
        text = " ".join([run] * (derive.MAX_RUNS + 10))
        self.assertIsInstance(derive.reversible_decodings(text), list)

    def test_never_raises_on_adversarial_input(self):
        for s in ("", "%", "%zz", "====", "%%%", "\x00\xff", "e30=" * 3):
            derive.reversible_decodings(s)  # 不抛异常即通过


if __name__ == "__main__":
    unittest.main(verbosity=2)
