#!/usr/bin/env python3
"""移动打标离线回归 —— 不需要设备、不需要 mitmproxy。

跑法：python -m unittest test_tagging_mobile   （在 mobile/traffic 目录下）

测的是**形态识别与哈希令牌**这两件事本身。测不到的边界如实写在注释里：
「15 位数字究竟是 IMEI 还是 IMSI」形态上无法判定，所以本模块不给出类别断言——
那不是没测，是设计如此。
"""
from __future__ import annotations

import hashlib
import unittest

import tagging_mobile as tm


class FakeMessage:
    def __init__(self, text: str | None = None, raise_on_text: bool = False):
        self._text = text
        self._raise = raise_on_text

    def get_text(self, strict: bool = False):
        if self._raise:
            raise UnicodeDecodeError("utf-8", b"\xff", 0, 1, "boom")
        return self._text


def h16(v: str) -> str:
    return hashlib.sha256(v.encode("utf-8")).hexdigest()[:16]


class ScanBodyTest(unittest.TestCase):
    def test_decode_error_is_reported_not_swallowed(self):
        """解码失败必须与「内容为空」区分开 —— 否则读作"这条流不含敏感字段"。"""
        text, status = tm.scan_body(FakeMessage(raise_on_text=True))
        self.assertEqual(text, "")
        self.assertTrue(status["decode_error"])

    def test_normal_body_reports_length(self):
        text, status = tm.scan_body(FakeMessage("hello 世界"))
        self.assertEqual(text, "hello 世界")
        self.assertFalse(status["decode_error"])
        self.assertEqual(status["chars"], 8)
        self.assertFalse(status["truncated"])

    def test_truncation_is_reported(self):
        long_text = "a" * (tm.MAX_BODY_SCAN + 100)
        text, status = tm.scan_body(FakeMessage(long_text))
        self.assertEqual(len(text), tm.MAX_BODY_SCAN)
        self.assertTrue(status["truncated"])

    def test_none_body_is_empty_not_error(self):
        text, status = tm.scan_body(FakeMessage(None))
        self.assertEqual(text, "")
        self.assertFalse(status["decode_error"])


class TagSensitiveTest(unittest.TestCase):
    def test_digit15_is_shape_only_not_a_category(self):
        """15 位数字可能是 IMEI 也可能是 IMSI —— 不得断言类别。"""
        labels, tokens = tm.tag_sensitive('{"d":"861234567890123"}')
        self.assertIn("digit15_shape", labels)
        dt, strength = tm.TYPE_BY_LABEL["digit15_shape"]
        self.assertIsNone(dt, "15 位形态不得映射到具体类别")
        self.assertEqual(strength, "shape")

    def test_tokens_are_hashes_never_raw_values(self):
        """令牌里绝不能出现原文 —— 报告与 LLM 不该再拿到一份个人信息副本。"""
        raw = "861234567890123"
        labels, tokens = tm.tag_sensitive('{"d":"%s"}' % raw)
        joined = " ".join(tokens)
        self.assertNotIn(raw, joined)
        self.assertIn(f"digit15_shape:{h16(raw)}", tokens)

    def test_token_hash_matches_hook_side_hashing(self):
        """必须与 hook_privacy 的值哈希口径一致（UTF-8 + sha256 前 16 位十六进制），
        否则值级匹配永远对不上，而且是静默对不上。"""
        value = "460001234567890"
        _, tokens = tm.tag_sensitive(value)
        self.assertIn(f"digit15_shape:{h16(value)}", tokens)

    def test_mac_address_shape(self):
        labels, tokens = tm.tag_sensitive("mac=3C:5A:B4:11:22:33")
        self.assertIn("mac_shape", labels)
        self.assertEqual(tm.TYPE_BY_LABEL["mac_shape"][0], "mac_address")

    def test_android_id_shape_is_16_hex(self):
        labels, _ = tm.tag_sensitive("aid=9f2c1ab34de56789")
        self.assertIn("android_id_shape", labels)

    def test_phone_and_id_card(self):
        labels, _ = tm.tag_sensitive("tel 13812345678 id 11010119900307123X")
        self.assertIn("phone_cn_shape", labels)
        self.assertIn("id_card_shape", labels)

    def test_coordinates(self):
        labels, _ = tm.tag_sensitive("loc=39.9042,116.4074")
        self.assertIn("coordinate_shape", labels)

    def test_json_key_line(self):
        labels, _ = tm.tag_sensitive('{"imei":"x","latitude":1.0}')
        self.assertIn("json_key_personal", labels)

    def test_no_digit_bleed_18_digits_matches_idcard_not_digit15(self):
        """18 位数字不应被 15 位规则截走（lookaround 必须生效）。"""
        labels, _ = tm.tag_sensitive("110101199003071234")
        self.assertIn("id_card_shape", labels)
        self.assertNotIn("digit15_shape", labels)

    def test_clean_text_has_no_labels(self):
        labels, tokens = tm.tag_sensitive('{"msg":"hello world"}')
        self.assertEqual(labels, [])
        self.assertEqual(tokens, [])

    def test_empty_text_is_safe(self):
        self.assertEqual(tm.tag_sensitive(""), ([], []))


class TypesForLabelsTest(unittest.TestCase):
    def test_shape_labels_carry_strength(self):
        out = tm.types_for_labels(["mac_shape", "digit15_shape"])
        by_label = {x["label"]: x for x in out}
        self.assertEqual(by_label["mac_shape"]["data_type"], "mac_address")
        self.assertEqual(by_label["mac_shape"]["strength"], "shape")
        self.assertIsNone(by_label["digit15_shape"]["data_type"])

    def test_unknown_label_does_not_crash(self):
        out = tm.types_for_labels(["nope"])
        self.assertEqual(out[0]["strength"], "unknown")


class AddonShimTest(unittest.TestCase):
    def test_tagging_module_has_the_interface_addon_imports(self):
        """addon.py 第 37 行 `from tagging import scan_body, tag_sensitive`——
        接口少一个，报错会发生在 mitmdump 启动时（那时人已经以为开始抓包了）。"""
        for name in ("scan_body", "body_of", "tag_sensitive"):
            self.assertTrue(callable(getattr(tm, name, None)), f"缺少接口 {name}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
