#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""V-Scanner Phase 5 — 违规代码行号的离线回归测试（不需要设备、不需要 APK）。

仅用于授权测试（自有设备与自有 APK）/ For authorized testing on owned devices and APKs only.

    python -m unittest test_codeloc

**为什么值得存在**：行号这东西一旦取错，**不会报错**——它会安静地指到另一个位置，
而报告上看着完全正常。这里钉死的正是几种"看起来取到了、其实取错了"的情形：
合成帧被当成真帧（行号 0）、另一个 App 的帧被算成自己的（targetapp 是 targetapp2 的前缀）、
dexdump 里字段名被当成方法名。
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from core.evidence import codeloc  # noqa: E402
from core.evidence import dexlines  # noqa: E402

A = "com.vscanner.targetapp"
B = "com.vscanner.targetapp2"

# 实测栈（phase3/logs/cap_vhal.jsonl，GEAR_SELECTION 那次读取）。
VHAL_STACK = "\n".join([
    "dalvik.system.VMStack.getThreadStackTrace(Native Method)",
    "java.lang.Thread.getStackTrace(Thread.java:1946)",
    "android.car.hardware.property.CarPropertyManager.getProperty(Native Method)",
    f"{A}.VhalReader.readOne(VhalReader.kt:128)",
    f"{A}.VhalReader.readAll(VhalReader.kt:105)",
    f"{A}.MainActivity.doRead$lambda$9(MainActivity.kt:118)",
    f"{A}.MainActivity.$r8$lambda$QaUb4dwx378mAQV5JYf1oDfmltE(Unknown Source:0)",
    f"{A}.MainActivity$$ExternalSyntheticLambda6.invoke(D8$$SyntheticClass:0)",
    "kotlin.concurrent.ThreadsKt$thread$thread$1.run(Thread.kt:30)",
])

# 实测栈（hook_egress.js 修好截断之后的目标形状：应用帧单列）。
EGRESS_APP_FRAMES = [
    f"{A}.EgressSender.send(EgressSender.kt:64)",
    f"{A}.MainActivity.doEgress$lambda$12(MainActivity.kt:141)",
]


class ParseFrameTest(unittest.TestCase):
    def test_real_frame_parses(self) -> None:
        f = codeloc.parse_frame(f"{A}.VhalReader.readOne(VhalReader.kt:128)")
        self.assertEqual(f["class"], f"{A}.VhalReader")
        self.assertEqual(f["method"], "readOne")
        self.assertEqual(f["file"], "VhalReader.kt")
        self.assertEqual(f["line"], 128)

    def test_lambda_class_name_keeps_method(self) -> None:
        """Kotlin lambda 的类是 `MainActivity$leakVhal$1`，方法名在最后一个点之后。"""
        f = codeloc.parse_frame(f"{A}.MainActivity$leakVhal$1.invoke(MainActivity.kt:99)")
        self.assertEqual(f["class"], f"{A}.MainActivity$leakVhal$1")
        self.assertEqual(f["method"], "invoke")
        self.assertEqual(f["line"], 99)

    def test_native_frame_has_no_line(self) -> None:
        f = codeloc.parse_frame("java.net.Socket.connect(Native Method)")
        self.assertTrue(f["native"])
        self.assertIsNone(f["line"])

    def test_synthetic_frames_have_no_line(self) -> None:
        """"Unknown Source:0" 与 "D8$$SyntheticClass:0" 都**不是**第 0 行。

        它们长得和真帧一样（有类、有方法、有括号），一旦把 0 当成行号，
        报告里就会出现「违规位置：MainActivity.kt:0」这种看着具体、实则没有的定位。
        """
        for raw in (f"{A}.MainActivity.$r8$lambda$QaUb(Unknown Source:0)",
                    f"{A}.MainActivity$$ExternalSyntheticLambda6.invoke(D8$$SyntheticClass:0)"):
            f = codeloc.parse_frame(raw)
            self.assertIsNone(f["line"], f"{raw} 不该被解析出行号")
            self.assertTrue(f["synthetic"])

    def test_unparseable_frame_returns_none(self) -> None:
        self.assertIsNone(codeloc.parse_frame("... 12 more"))


class AppChainTest(unittest.TestCase):
    def test_only_app_frames_kept(self) -> None:
        """只留应用自己的帧——框架帧（okhttp / android.car / kotlin）全部排除。

        **合成帧留着**：`$r8$lambda$…`、`$$ExternalSyntheticLambda…` 是编译器为
        应用自己的 Kotlin lambda 生成的，它们属于应用侧调用链，只是没有行号。
        想去掉它们看 `chain_with_lines`——那是给报告用的那份。
        """
        chain = codeloc.app_chain({"stack": VHAL_STACK}, A)
        self.assertEqual([f["method"] for f in chain],
                         ["readOne", "readAll", "doRead$lambda$9",
                          "$r8$lambda$QaUb4dwx378mAQV5JYf1oDfmltE", "invoke"])
        for frame in chain:
            self.assertTrue(frame["class"].startswith(A + "."))
        self.assertEqual([f["method"] for f in chain if f["line"]],
                         ["readOne", "readAll", "doRead$lambda$9"])

    def test_prefix_package_is_not_matched(self) -> None:
        """`com.vscanner.targetapp` 是 `com.vscanner.targetapp2` 的前缀。

        审计 targetapp 时，targetapp2 的帧**不能**被算进来——否则会把另一个 App
        的代码行写进本 App 的报告里。用 `package + '.'` 前缀而不是子串包含。
        """
        stack = "\n".join([f"{B}.Other.read(Other.kt:7)"])
        self.assertEqual(codeloc.app_chain({"stack": stack}, A), [])

    def test_both_stack_shapes(self) -> None:
        """VHAL 的栈是 `\\n` 字符串，egress 的是数组——两种都要吃。"""
        from_str = codeloc.app_chain({"stack": VHAL_STACK}, A)
        from_list = codeloc.app_chain({"stack": VHAL_STACK.split("\n")}, A)
        self.assertEqual([f["frame"] for f in from_str], [f["frame"] for f in from_list])

    def test_app_frames_field_is_preferred(self) -> None:
        """egress 记录里 `app_frames` 是钩子筛好的，优先用它。"""
        rec = {"stack": ["com.android.okhttp.internal.Platform.connectSocket(Platform.java:182)"],
               "app_frames": EGRESS_APP_FRAMES}
        chain = codeloc.app_chain(rec, A)
        self.assertEqual([f["method"] for f in chain], ["send", "doEgress$lambda$12"])


class LocateTest(unittest.TestCase):
    def test_picks_innermost_real_frame(self) -> None:
        loc = codeloc.locate({"stack": VHAL_STACK}, A, "read", 5)
        self.assertEqual((loc["class"], loc["method"], loc["line"]),
                         (f"{A}.VhalReader", "readOne", 128))
        self.assertEqual(loc["role"], "read")
        self.assertEqual(loc["event_id"], 5)

    def test_chain_keeps_full_app_call_path(self) -> None:
        """整条应用链都要留着：R8 内联会让最内层那一帧未必是开发者写的那行。"""
        loc = codeloc.locate({"stack": VHAL_STACK}, A, "read", 5)
        self.assertEqual(len(loc["chain_with_lines"]), 3)

    def test_all_synthetic_yields_chain_but_no_frame(self) -> None:
        stack = "\n".join([
            f"{A}.MainActivity$$ExternalSyntheticLambda6.invoke(D8$$SyntheticClass:0)",
            f"{A}.MainActivity.$r8$lambda$X(Unknown Source:0)",
        ])
        loc = codeloc.locate({"stack": stack}, A, "read", 1)
        self.assertIsNone(loc["line"], "全是合成帧时不该硬凑一个行号")
        self.assertEqual(len(loc["chain"]), 2, "但调用链仍要保留")
        self.assertIn("合成帧", loc["note"])

    def test_no_app_frame_returns_none(self) -> None:
        """纯框架栈（就是修截断之前 egress 的样子）必须返回 None，而不是硬给一个位置。"""
        stack = "\n".join(["java.net.Socket.connect(Native Method)",
                           "com.android.okhttp.internal.Platform.connectSocket(Platform.java:182)"])
        self.assertIsNone(codeloc.locate({"stack": stack}, A, "egress", 3))


class AttachTest(unittest.TestCase):
    def test_manifest_finding_says_why_it_has_no_code(self) -> None:
        """空 code_locs 必须带原因：否则'本来就没有代码'与'工具没找到'分不开。"""
        findings = [{"rule_id": "VSC-P001", "evidence_kind": "manifest_permission"}]
        out = codeloc.attach(findings, [], [], [], A)
        self.assertEqual(out[0]["code_locs"], [])
        self.assertIn("MANIFEST", out[0]["code_loc_note"])

    def test_read_finding_gets_read_loc(self) -> None:
        reads = [{"evt_id": 5, "stack": VHAL_STACK}]
        findings = [{"rule_id": "VSC-R003", "evidence_kind": "read_event", "event_ids": [5]}]
        out = codeloc.attach(findings, reads, [], [], A)
        self.assertEqual(out[0]["code_locs"][0]["line"], 128)
        self.assertEqual(out[0]["code_locs"][0]["role"], "read")

    def test_egress_finding_gets_both_roles(self) -> None:
        reads = [{"evt_id": 5, "stack": VHAL_STACK}]
        flows = [{"evt_id": 1, "ts": 1_000_000}]
        egress = [{"ev": "EGRESS_CONNECT", "evt_id": 3, "package": A,
                   "host_received_ts": 1_000_500, "app_frames": EGRESS_APP_FRAMES}]
        findings = [{"rule_id": "VSC-E003", "evidence_kind": "read_then_egress",
                     "pairs": [{"read_event_id": 5, "flow_event_id": 1}]}]
        out = codeloc.attach(findings, reads, flows, egress, A)
        roles = [loc["role"] for loc in out[0]["code_locs"]]
        self.assertEqual(roles, ["read", "egress"])
        self.assertEqual(out[0]["code_locs"][1]["line"], 64)

    def test_egress_beyond_tolerance_is_not_attached(self) -> None:
        """超过容差的那次连接不是这条流的——宁可不给位置，也不能给错的位置。"""
        flows = [{"evt_id": 1, "ts": 1_000_000}]
        egress = [{"ev": "EGRESS_CONNECT", "evt_id": 3, "package": A,
                   "host_received_ts": 1_000_000 + codeloc.MATCH_TOLERANCE_MS + 1,
                   "app_frames": EGRESS_APP_FRAMES}]
        findings = [{"rule_id": "VSC-E003", "evidence_kind": "read_then_egress",
                     "pairs": [{"read_event_id": 9, "flow_event_id": 1}]}]
        out = codeloc.attach(findings, [], flows, egress, A)
        self.assertEqual(out[0]["code_locs"], [])
        self.assertIn("没有应用侧栈帧", out[0]["code_loc_note"])

    def test_other_packages_egress_is_not_borrowed(self) -> None:
        flows = [{"evt_id": 1, "ts": 1_000_000}]
        egress = [{"ev": "EGRESS_CONNECT", "evt_id": 3, "package": B,
                   "host_received_ts": 1_000_100, "app_frames": [f"{B}.E.send(E.kt:9)"]}]
        findings = [{"rule_id": "VSC-E003", "evidence_kind": "read_then_egress",
                     "pairs": [{"read_event_id": 9, "flow_event_id": 1}]}]
        out = codeloc.attach(findings, [], flows, egress, A)
        self.assertEqual(out[0]["code_locs"], [])

    def test_half_located_finding_records_the_gap(self) -> None:
        """只定位到一半时**必须**记 gap。

        实测撞上过：egress 那一侧因为钩子把栈截断而取不到位置，而 `code_locs` 里
        明明躺着 read 那一侧的位置——列表非空，看上去一切正常，
        读者不会想到另一侧根本没定位到。
        """
        reads = [{"evt_id": 5, "stack": VHAL_STACK}]
        flows = [{"evt_id": 1, "ts": 1_000_000}]
        # 修复前的 egress 事件：栈里全是 okhttp，没有应用帧。
        egress = [{"ev": "EGRESS_CONNECT", "evt_id": 3, "package": A,
                   "host_received_ts": 1_000_100,
                   "stack": ["java.net.Socket.connect(Native Method)",
                             "com.android.okhttp.internal.Platform.connectSocket(Platform.java:182)"]}]
        findings = [{"rule_id": "VSC-E003", "evidence_kind": "read_then_egress",
                     "pairs": [{"read_event_id": 5, "flow_event_id": 1}]}]
        out = codeloc.attach(findings, reads, flows, egress, A)
        self.assertEqual([loc["role"] for loc in out[0]["code_locs"]], ["read"])
        gaps = out[0]["code_loc_gaps"]
        self.assertEqual(len(gaps), 1)
        self.assertEqual(gaps[0]["role"], "egress")
        self.assertIn("没有应用侧帧", gaps[0]["reason"])
        self.assertEqual(codeloc.summarize(out)["findings_with_partial_loc"], ["VSC-E003"])

    def test_missing_egress_event_is_reported(self) -> None:
        """连出站事件都找不到时，理由要和"有事件但没栈"区分开。"""
        flows = [{"evt_id": 1, "ts": 1_000_000}]
        findings = [{"rule_id": "VSC-E003", "evidence_kind": "read_then_egress",
                     "pairs": [{"read_event_id": 9, "flow_event_id": 1}]}]
        out = codeloc.attach(findings, [], flows, [], A)
        reasons = [g["reason"] for g in out[0]["code_loc_gaps"]]
        self.assertTrue(any("没有本包的出站事件" in r for r in reasons), reasons)

    def test_duplicate_pairs_are_deduped(self) -> None:
        reads = [{"evt_id": 5, "stack": VHAL_STACK}]
        findings = [{"rule_id": "VSC-E003", "evidence_kind": "read_then_egress",
                     "pairs": [{"read_event_id": 5, "flow_event_id": 1},
                               {"read_event_id": 5, "flow_event_id": 2}]}]
        out = codeloc.attach(findings, reads, [], [], A)
        self.assertEqual(len(out[0]["code_locs"]), 1)

class DexDumpParseTest(unittest.TestCase):
    """dexdump 解析：这里钉的是一个**会把字段名当成方法名**的坑。"""

    SAMPLE = "\n".join([
        "  Class descriptor  : 'Lcom/vscanner/targetapp/VhalReader;'",
        "  Static fields     -",
        "  Instance fields   -",
        "    #0              : (in Lcom/vscanner/targetapp/VhalReader;)",
        "      name          : 'context'",
        "      type          : 'Landroid/content/Context;'",
        "  Direct methods    -",
        "    #0              : (in Lcom/vscanner/targetapp/VhalReader;)",
        "      name          : 'readOne'",
        "      type          : '(I)V'",
        "      positions     :",
        "        0x0051 line=128",
        "        0x0060 line=129",
        "  source_file_idx   : 5665 (VhalReader.kt)",
    ])

    def test_fields_are_not_indexed_as_methods(self) -> None:
        index: dict = {}
        dexlines.parse_dexdump(self.SAMPLE, index)
        methods = index["com.vscanner.targetapp.VhalReader"]["methods"]
        self.assertIn("readOne", methods)
        self.assertNotIn("context", methods,
                         "字段名被当成方法名收录了——dexdump 里两者格式相同，必须按 section 区分")

    def test_source_file_and_lines_captured(self) -> None:
        index: dict = {}
        dexlines.parse_dexdump(self.SAMPLE, index)
        entry = index["com.vscanner.targetapp.VhalReader"]
        self.assertEqual(entry["file"], "VhalReader.kt")
        self.assertEqual(entry["methods"]["readOne"][0]["lines"], [128, 129])

    def test_verify_rejects_wrong_line_and_missing_method(self) -> None:
        index: dict = {}
        dexlines.parse_dexdump(self.SAMPLE, index)
        cls = "com.vscanner.targetapp.VhalReader"
        self.assertEqual(dexlines.verify(index, cls, "readOne", "VhalReader.kt", 128)["status"],
                         "VERIFIED")
        self.assertEqual(dexlines.verify(index, cls, "readOne", "VhalReader.kt", 999)["status"],
                         "LINE_NOT_IN_METHOD")
        self.assertEqual(dexlines.verify(index, cls, "nope", "VhalReader.kt", 128)["status"],
                         "METHOD_NOT_FOUND")
        self.assertEqual(dexlines.verify(index, "com.a.b", "m", "F.kt", 1)["status"],
                         "CLASS_NOT_FOUND")

    def test_no_index_is_not_a_pass(self) -> None:
        """没有 dex 就是**没核对**，绝不能算通过。"""
        self.assertEqual(dexlines.verify(None, "com.a.B", "m", "F.kt", 1)["status"],
                         "DEX_UNAVAILABLE")


if __name__ == "__main__":
    unittest.main(verbosity=2)
