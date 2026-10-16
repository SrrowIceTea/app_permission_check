#!/usr/bin/env python3
"""移动打标离线回归 —— 不需要设备、不需要 mitmproxy。

跑法：python -m unittest test_tagging_mobile   （在 mobile/traffic 目录下）

测的是**形态识别与哈希令牌**这两件事本身。测不到的边界如实写在注释里：
「15 位数字究竟是 IMEI 还是 IMSI」形态上无法判定，所以本模块不给出类别断言——
那不是没测，是设计如此。
"""
from __future__ import annotations

import base64
import gzip
import hashlib
import unittest
from pathlib import Path

import tagging_mobile as tm


def h16(v: str) -> str:
    return hashlib.sha256(v.encode("utf-8")).hexdigest()[:16]


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


class AddonContractTest(unittest.TestCase):
    """`core/collector/addon.py` 按 `VSCAN_TAGGING` 路径加载本文件，契约只剩一个函数。

    为什么在这里测：接口少一个，报错会发生在 mitmdump 启动时——那时人已经以为
    开始抓包了，而"没打上标签"与"这条流不含敏感字段"在报告里长得一模一样。
    用与 addon 相同的加载方式（按文件路径 spec_from_file_location）复核一遍。
    """

    def test_tag_sensitive_is_callable_and_returns_two_str_lists(self):
        self.assertTrue(callable(getattr(tm, "tag_sensitive", None)), "缺少接口 tag_sensitive")
        labels, tokens = tm.tag_sensitive("imei 123456789012345")
        self.assertIsInstance(labels, list)
        self.assertIsInstance(tokens, list)
        self.assertTrue(all(isinstance(x, str) for x in labels + tokens))

    def test_module_loads_standalone_by_path(self):
        """addon 是按路径加载的，模块必须不依赖调用方的 sys.path 才能导入成功。"""
        import importlib.util
        src = Path(__file__).resolve().parent / "tagging_mobile.py"
        spec = importlib.util.spec_from_file_location("vscan_tagging", src)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.assertTrue(callable(module.tag_sensitive))

    def test_tokens_never_contain_the_matched_plaintext(self):
        """移动版的 tokens 是 `标签:sha256前16位`；报告与 LLM 不该再拿到个人信息副本。"""
        secret = "13800138000"
        labels, tokens = tm.tag_sensitive(secret)
        self.assertIn("phone_cn_shape", labels)
        self.assertTrue(tokens, "应当产出令牌")
        for token in tokens:
            self.assertNotIn(secret, token)
            self.assertEqual(token, f"phone_cn_shape:{h16(secret)}")


class DerivedValueTest(unittest.TestCase):
    """C1 派生值匹配的报文侧行为：解码产物进**值级令牌**，不进形态级标签。"""

    IMEI = "490154203237518"

    def test_b64_encoded_imei_yields_value_token(self):
        """读到 IMEI → base64 外发：令牌 = digit15_shape:h16(解码后的原值)。"""
        payload = "d=" + base64.b64encode(self.IMEI.encode()).decode()
        labels, tokens = tm.tag_sensitive(payload)
        self.assertIn(f"digit15_shape:{h16(self.IMEI)}", tokens)
        self.assertIn("derived_b64", labels)
        # 解码产物不给形态级标签：形态结论只来自报文原文。
        self.assertNotIn("digit15_shape", labels)

    def test_urlencoded_json_body_yields_value_token(self):
        """URL 编码的 JSON 体：原文扫描看不到数字（全是 %XX），解码后命中手机号。"""
        import urllib.parse
        phone = "13800138000"
        body = '{"tel":"%s"}' % phone
        payload = urllib.parse.quote(body)
        labels, tokens = tm.tag_sensitive(payload)
        self.assertNotIn("phone_cn_shape", labels)          # 原文扫描无形态结论
        self.assertIn("derived_url", labels)                # 但有派生标记
        self.assertIn(f"phone_cn_shape:{h16(phone)}", tokens)  # 解码后值级命中

    def test_gzip_b64_value_token(self):
        gz = base64.b64encode(gzip.compress(self.IMEI.encode())).decode()
        _, tokens = tm.tag_sensitive("blob=" + gz)
        self.assertIn(f"digit15_shape:{h16(self.IMEI)}", tokens)

    def test_md5_hex_shape_token(self):
        """单向摘要：报文侧只给 `md5_hex_shape:hash16(摘要串)`，与读取侧候选配对。"""
        digest = hashlib.md5(self.IMEI.encode()).hexdigest()
        _, tokens = tm.tag_sensitive("sig=" + digest)
        self.assertIn(f"md5_hex_shape:{h16(digest)}", tokens)

    def test_sha1_and_sha256_hex_shapes(self):
        s1 = hashlib.sha1(b"x").hexdigest()
        s256 = hashlib.sha256(b"x").hexdigest()
        labels, tokens = tm.tag_sensitive(f"{s1} {s256}")
        self.assertIn("sha1_hex_shape", labels)
        self.assertIn("sha256_hex_shape", labels)
        self.assertIn(f"sha1_hex_shape:{h16(s1)}", tokens)
        self.assertIn(f"sha256_hex_shape:{h16(s256)}", tokens)

    def test_digest_labels_never_map_to_a_category(self):
        """摘要/编码形态一律不定类别——32 位 hex 可能是任何东西的哈希。"""
        for label in ("md5_hex_shape", "sha1_hex_shape", "sha256_hex_shape",
                      "derived_b64", "derived_hex", "derived_url", "derived_gzip"):
            dt, strength = tm.TYPE_BY_LABEL[label]
            self.assertIsNone(dt, label)
            self.assertIn(strength, ("hash", "derived"))

    def test_other_15digit_number_does_not_match(self):
        """**反例**（C1 验收判据）：别的 15 位数字不得产出该 IMEI 的值级命中。"""
        other = "123456789012345"
        payload = "d=" + base64.b64encode(self.IMEI.encode()).decode()  # 发的是 IMEI
        _, tokens = tm.tag_sensitive(payload)
        self.assertNotIn(f"digit15_shape:{h16(other)}", tokens)
        # 摘要候选同理：别的值的 md5 串不会命中本 IMEI 的候选。
        other_md5 = hashlib.md5(other.encode()).hexdigest()
        _, tokens2 = tm.tag_sensitive("sig=" + other_md5)
        self.assertNotIn(f"md5_hex_shape:{h16(hashlib.md5(self.IMEI.encode()).hexdigest())}",
                         tokens2)

    def test_raw_behavior_unchanged_for_plain_payload(self):
        """原有行为不回归：明文敏感值的标签与令牌与扩展前一致。"""
        raw = "861234567890123"
        labels, tokens = tm.tag_sensitive('{"d":"%s"}' % raw)
        self.assertIn("digit15_shape", labels)
        self.assertIn(f"digit15_shape:{h16(raw)}", tokens)
        self.assertNotIn("derived_b64", labels)


if __name__ == "__main__":
    unittest.main(verbosity=2)
