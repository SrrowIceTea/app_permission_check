#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""启动 Activity 设备解析的离线回归。

测试数据全部来自 2026-10-13 在 VScan_Phone（API 37.2）上的**真实输出**：
  - F-Droid 的两个 LAUNCHER 里第一个（panic.CalculatorActivity）的类已被 R8 裁掉，
    `am start` 报 "Activity class does not exist"，整段设备检测死在 app_started；
  - Fossify 系列走 activity-alias，设备解析返回 `.SplashActivity.Green` 这类别名形态；
  - keepass 的启动页是 FileDatabaseSelectActivity。

只测纯函数 parse_resolved_activity——它不碰 adb，跑在离线回归里；真正的设备解析
（device_main_activity）靠这条链路保底。
"""
from __future__ import annotations

import unittest

from thirdparty_env import parse_resolved_activity

# 设备真值（逐字抄录）
FDROID = """\
priority=0 preferredOrder=0 match=0x108000 specificIndex=-1 isDefault=false
org.fdroid.fdroid/.views.main.MainActivity
"""

FOSSIFY_CAMERA = """\
priority=0 preferredOrder=0 match=0x108000 specificIndex=-1 isDefault=false
org.fossify.camera/.activities.SplashActivity.Green
"""

KEEPASS_FULLY_QUALIFIED = """\
priority=0 preferredOrder=0 match=0x108000 specificIndex=-1 isDefault=false
com.kunzisoft.keepass.libre/com.kunzisoft.keepass.activities.FileDatabaseSelectActivity
"""


class ParseResolvedActivity(unittest.TestCase):
    def test_relative_form(self):
        """短写形态：pkg/.views.main.MainActivity → 取 `.views.main.MainActivity`。"""
        self.assertEqual(parse_resolved_activity(FDROID, "org.fdroid.fdroid"),
                         ".views.main.MainActivity")

    def test_activity_alias_form(self):
        """activity-alias 形态（Fossify 的彩色别名）必须原样保留。"""
        self.assertEqual(parse_resolved_activity(FOSSIFY_CAMERA, "org.fossify.camera"),
                         ".activities.SplashActivity.Green")

    def test_fully_qualified_form(self):
        self.assertEqual(
            parse_resolved_activity(KEEPASS_FULLY_QUALIFIED, "com.kunzisoft.keepass.libre"),
            "com.kunzisoft.keepass.activities.FileDatabaseSelectActivity")

    def test_empty_output_returns_none(self):
        """解析失败要返回 None（调用方回退到批量层给的值），不能抛异常。"""
        for text in ("", "\n", "No activity found\npriority=0 isDefault=false\n"):
            self.assertIsNone(parse_resolved_activity(text, "org.fdroid.fdroid"))

    def test_other_package_lines_are_ignored(self):
        """组件行的包名段不匹配就不认——防御设备上多包共存时输出串台。"""
        self.assertIsNone(parse_resolved_activity(FDROID, "org.fossify.camera"))


if __name__ == "__main__":
    unittest.main()
