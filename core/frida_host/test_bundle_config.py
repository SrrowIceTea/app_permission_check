#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""bundle_config.configure 的离线回归：替换后每个模块的字节长度头必须仍自洽。

为什么值得单测：替换发生在**注入前一刻**，出错不会报错——Frida 只会拒绝加载
（length header mismatch）或让人误读模块，而这两种症状都长得像"钩子没挂上"。
三个占位符的替换值长度各不相同，A1 分档新增的两个尤其要盯住。

跑法：cd core/frida_host && python -m unittest test_bundle_config
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from core.frida_host.bundle_config import (MARKER, NO_STACK_MARKER,  # noqa: E402
                                           WATCH_LIMIT_MARKER, configure)


def pack(modules: list[str]) -> str:
    """把模块列表伪造成 frida-compile 的 📦 bundle 格式。"""
    entries = '\n'.join(f"{len(m.encode('utf-8'))} m{i}.js" for i, m in enumerate(modules))
    return '📦\n' + entries + '\n✄\n' + '\n✄\n'.join(modules)


def parse(body: str) -> list[str]:
    """拆回模块列表，并断言每个长度头与模块字节数一致。"""
    header, rest = body.split('\n✄\n', 1)
    entries, modules = header.splitlines()[1:], rest.split('\n✄\n')
    assert len(entries) == len(modules)
    for entry, module in zip(entries, modules):
        assert len(module.encode('utf-8')) == int(entry.split(' ', 1)[0]), '长度头应自洽'
    return modules


def source() -> str:
    """与真实脚本同形的三处占位符用法（都必须是字符串字面量；
    分档两个走 parseInt 消费——直接字面量比较会被 frida-compile 折叠掉）。"""
    return ('var p = "' + MARKER + '";\n'
            'var lim = parseInt("' + WATCH_LIMIT_MARKER + '", 10);\n'
            'var ns = parseInt("' + NO_STACK_MARKER + '", 10) === 1;\n')


class ConfigureTest(unittest.TestCase):
    def test_all_markers_replaced_and_headers_recomputed(self):
        out = configure(pack([source(), 'no markers here']), ['com.a.b'],
                        watch_limit=8, no_stack=True)
        modules = parse(out)
        self.assertIn('var p = "[\\"com.a.b\\"]";', modules[0])
        self.assertIn('var lim = parseInt("8", 10);', modules[0])
        self.assertIn('var ns = parseInt("1", 10) === 1;', modules[0])
        for marker in (MARKER, WATCH_LIMIT_MARKER, NO_STACK_MARKER):
            self.assertNotIn(marker, modules[0])

    def test_switches_absent_leaves_their_markers(self):
        """旧调用形态（只给包名）不许动分档占位符——车载路径依赖这条。"""
        modules = parse(configure(pack([source()]), ['com.a.b']))
        self.assertNotIn(MARKER, modules[0])
        self.assertIn(WATCH_LIMIT_MARKER, modules[0])
        self.assertIn(NO_STACK_MARKER, modules[0])

    def test_zero_limit_and_false_no_stack_are_explicit(self):
        """0 是合法档位（attach 对照组），要与"没给"区分开；False 同理。"""
        modules = parse(configure(pack([source()]), ['com.a.b'],
                                  watch_limit=0, no_stack=False))
        self.assertIn('var lim = parseInt("0", 10);', modules[0])
        self.assertIn('var ns = parseInt("0", 10) === 1;', modules[0])

    def test_plain_body_without_header(self):
        out = configure('x = parseInt("' + WATCH_LIMIT_MARKER + '", 10);', [], watch_limit=3)
        self.assertEqual(out, 'x = parseInt("3", 10);')

    def test_module_count_mismatch_rejected(self):
        with self.assertRaises(ValueError):
            configure('📦\n4 m0.js\n✄\nabcd\n✄\nefgh', ['com.a.b'])

    def test_wrong_length_header_rejected(self):
        with self.assertRaises(ValueError):
            configure('📦\n4 m0.js\n✄\nabc', ['com.a.b'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
