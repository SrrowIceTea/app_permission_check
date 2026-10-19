#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""`inherited_text()` 与上游失败分类的离线守卫。

仅用于授权测试（自有设备 / 已授权的公开第三方样本）。

为什么这两个函数需要单测：
  * `inherited_text()` 决定"首启页的 Next/Skip 能不能被选中"。它一旦退化成"取容器内最长
    文本"，在整屏 `clickable=true` 的 Compose 根容器上会把一段正文当按钮标签——症状是
    **照样能点、照样有 taps，但点的是屏幕中心**，`ui_taps_made` 依旧通过，从检查项上看
    不出任何异常。这类"静默点错"只能靠断言钉住。
  * `classify_upstream_failure()` 决定"上游不可达"会不会被记成"应用主动放弃"。实测
    （mitmproxy 12.2.3）两者在 `failure` 字段里**都是 `client disconnected`**，只能靠
    连接耗时区分。归错类，报告就会把环境故障写成应用行为。
"""
from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT))

import thirdparty_ui_flow as flow  # noqa: E402
import ui_trigger as ui            # noqa: E402


def dump(inner: str) -> str:
    return f'<hierarchy rotation="0">{inner}</hierarchy>'


def node(bounds, *, text="", desc="", rid="", cls="android.view.View",
         clickable=False, inner="") -> str:
    tail = f">{inner}</node>" if inner else "/>"
    return (f'<node class="{cls}" text="{text}" resource-id="{rid}" '
            f'content-desc="{desc}" clickable="{"true" if clickable else "false"}" '
            f'enabled="true" bounds="{bounds}"{tail}')


class InheritedTextTest(unittest.TestCase):
    def test_compose_button_container_inherits_child_label(self):
        """11-app-securecamera 的真实形态：clickable 的 View 自身没有文案。"""
        skip_btn = node("[42,2170][194,2296]", clickable=True,
                        inner=node("[82,2206][154,2259]", text="Skip"))
        next_btn = node("[835,2170][1038,2296]", clickable=True,
                        inner=node("[898,2206][975,2259]", text="Next"))
        xml = dump(node("[0,0][1080,2400]", cls="android.widget.FrameLayout",
                        inner=skip_btn + next_btn))
        ns = ui.nodes(xml)
        skip = next(n for n in ns if n["clickable"] and n["bounds"][0] == 42)
        nxt = next(n for n in ns if n["clickable"] and n["bounds"][0] == 835)
        self.assertEqual("Skip", flow.inherited_text(skip, ns))
        self.assertEqual("Next", flow.inherited_text(nxt, ns))
        self.assertEqual("android.view.View", ui.label(skip), "容器自身仍然没有标签")

    def test_text_two_levels_down_is_still_found(self):
        """17-umer0586-sensagram：文案在 +2 层。"""
        inner2 = node("[477,2253][603,2295]", text="Settings")
        inner1 = node("[380,2130][700,2330]", cls="android.view.ViewGroup", inner=inner2)
        xml = dump(node("[0,0][1080,2400]", cls="android.widget.FrameLayout", inner=(
            node("[367,2127][713,2337]", clickable=True, inner=inner1))))
        ns = ui.nodes(xml)
        cand = next(n for n in ns if n["clickable"])
        self.assertEqual("Settings", flow.inherited_text(cand, ns))

    def test_deep_text_beyond_depth_limit_is_ignored(self):
        """第 5 层的文案不是这个按钮的标签。"""
        inner = node("[400,2200][600,2300]", text="TooDeep")
        for _ in range(4):
            inner = node("[390,2190][610,2310]", cls="android.view.ViewGroup", inner=inner)
        xml = dump(node("[0,0][1080,2400]", cls="android.widget.FrameLayout", inner=(
            node("[367,2127][713,2337]", clickable=True, inner=inner))))
        ns = ui.nodes(xml)
        cand = next(n for n in ns if n["clickable"])
        self.assertEqual("", flow.inherited_text(cand, ns))

    def test_full_screen_clickable_with_many_texts_is_refused(self):
        """整屏可点容器 + 多段文案：不是按钮。猜一个中心点没有依据，宁可报无候选。"""
        kids = "".join(node(f"[100,{200 + i * 120}][900,{280 + i * 120}]", text=t)
                       for i, t in enumerate(("Welcome", "Some intro", "Settings")))
        xml = dump(node("[0,0][1080,2400]", clickable=True, inner=kids))
        ns = ui.nodes(xml)
        cand = next(n for n in ns if n["clickable"])
        self.assertEqual("", flow.inherited_text(cand, ns))

    def test_long_paragraph_is_never_a_label(self):
        paras = ("This application collects nothing at all and stores no data, "
                 "please read the full privacy policy for details about retention.")
        xml = dump(node("[0,0][1080,2400]", cls="android.widget.FrameLayout", inner=(
            node("[100,200][900,900]", clickable=True, inner=(
                node("[120,220][880,880]", text=paras))))))
        ns = ui.nodes(xml)
        cand = next(n for n in ns if n["clickable"])
        self.assertEqual("", flow.inherited_text(cand, ns))

    def test_geometric_fallback_when_tree_is_unavailable(self):
        """正则兜底解析没有 parent，退回"中心点落在 bounds 内"。"""
        ns = [
            {"idx": 0, "parent": None, "text": "", "desc": "", "rid": "",
             "cls": "android.view.View", "pkg": "p", "clickable": True,
             "enabled": True, "bounds": (42, 2170, 194, 2296),
             "center": (118, 2233), "area": 152 * 126},
            {"idx": 1, "parent": None, "text": "Skip", "desc": "", "rid": "",
             "cls": "android.widget.TextView", "pkg": "p", "clickable": False,
             "enabled": True, "bounds": (82, 2206, 154, 2259),
             "center": (118, 2232), "area": 72 * 53},
            {"idx": 2, "parent": None, "text": "Outside", "desc": "", "rid": "",
             "cls": "android.widget.TextView", "pkg": "p", "clickable": False,
             "enabled": True, "bounds": (800, 100, 900, 160),
             "center": (850, 130), "area": 100 * 60},
        ]
        self.assertEqual("Skip", flow.inherited_text(ns[0], ns))

    def test_nearest_to_center_wins_over_longer_sibling(self):
        """两个文案都在容器内时，取离中心更近的那个（按钮标签通常居中）。

        容器 [367,2127][713,2337] 的中心是 (540,2232)：
          "Sensors"          落在 (540,2232) —— 正中心，距离 0
          "Sensors and more" 落在 (540,2300) —— 更靠下，距离 68
        取更近的，所以结果必须是短的 "Sensors"；若实现退回"取最长"，这里会拿到长的那条。
        """
        inner = (node("[470,2212][610,2252]", text="Sensors") +
                 node("[380,2280][700,2320]", text="Sensors and more"))
        xml = dump(node("[0,0][1080,2400]", cls="android.widget.FrameLayout", inner=(
            node("[367,2127][713,2337]", clickable=True, inner=inner))))
        ns = ui.nodes(xml)
        cand = next(n for n in ns if n["clickable"])
        self.assertEqual("Sensors", flow.inherited_text(cand, ns))

    def test_pick_candidate_accepts_the_compose_container(self):
        """端到端：候选筛选不再因为标签是 android.view.View 而丢掉它。"""
        xml = dump(node("[0,0][1080,2400]", cls="android.widget.FrameLayout", inner=(
            node("[835,2170][1038,2296]", clickable=True, inner=(
                node("[898,2206][975,2259]", text="Next"))))))
        ns = ui.nodes(xml)
        cand, _key = flow.pick_candidate(ns, set())
        self.assertIsNotNone(cand, "首启页的两个按钮必须能被选中")
        self.assertEqual("Next", cand["label"])
        self.assertTrue(flow.ONBOARD.search(cand["label"]))


class HookWiringTest(unittest.TestCase):
    """入口模块必须真的导出上游连接钩子。

    这条守卫针对一个**静默**失败：mitmproxy 只认脚本模块命名空间里的钩子名。
    `mobile/traffic/addon_mobile.py` 若只转发了 load/request/response/error/done，
    `core/collector/addon.py` 里新加的 `server_connect*` 一个都不会被调用，
    而日志、flows、报告全都正常——只有 `failure_kind` 恒为 None，
    看起来像"本轮没有任何上游失败"。实测过一次这种形态，所以钉在这里。
    """

    def test_entry_module_exports_upstream_hooks(self):
        import importlib.util  # noqa: PLC0415

        with tempfile.TemporaryDirectory() as tmp:
            os.environ.setdefault("VSCAN_PACKAGES", "com.example.probe")
            os.environ["VSCAN_FLOW_LOG"] = str(Path(tmp) / "flows.jsonl")
            os.environ.setdefault("VSCAN_TAGGING", "mobile/traffic/tagging_mobile.py")

            entry = ROOT / "mobile" / "traffic" / "addon_mobile.py"
            spec = importlib.util.spec_from_file_location("addon_mobile_probe", entry)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)

        for name in ("server_connect", "server_connected", "server_connect_error"):
            self.assertTrue(callable(getattr(mod, name, None)),
                            f"addon_mobile.py 没有导出 {name}——该钩子不会被 mitmproxy 调用")


class FailureKindTest(unittest.TestCase):
    """`classify_upstream_failure` 是纯函数，但住在 addon 里，导入需要环境变量。"""

    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        os.environ.setdefault("VSCAN_PACKAGES", "com.example.probe")
        os.environ["VSCAN_FLOW_LOG"] = str(Path(cls._tmp.name) / "flows.jsonl")
        os.environ.setdefault("VSCAN_TAGGING", "mobile/traffic/tagging_mobile.py")
        from core.collector import addon          # noqa: PLC0415
        cls.addon = addon

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def check(self, msg, connect_ms, want):
        got = self.addon.classify_upstream_failure(msg, connect_ms)
        self.assertEqual(want, got, f"{msg!r} @{connect_ms}ms")

    def test_refused_is_refused(self):
        self.check("[WinError 1225] 远程计算机拒绝网络连接。", 1800, "upstream_refused")
        self.check("Connection refused", 300, "upstream_refused")

    def test_timeout_strings(self):
        self.check("[WinError 121] 信号灯超时时间已到", 21000, "upstream_timeout")
        self.check("Connection timed out", None, "upstream_timeout")

    def test_blackhole_exposes_as_client_disconnected(self):
        """这是最关键的一条：字面与"客户端主动断开"完全相同，只能靠耗时区分。"""
        self.check("client disconnected", 21000, "upstream_timeout")
        self.check("client disconnected", 700, "client_abort")

    def test_unknown_stays_other(self):
        self.check("something unexpected", 100, "other")
        self.check(None, None, "other")


if __name__ == "__main__":
    unittest.main(verbosity=2)
