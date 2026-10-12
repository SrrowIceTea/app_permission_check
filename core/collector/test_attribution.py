#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""V-Scanner Phase 4 — 归因逻辑的离线回归测试（不需要设备、不需要 mitmproxy）。

仅用于授权测试（自有设备与自有 APK）/ For authorized testing on owned devices and APKs only.

    python -m unittest test_attribution -v

**为什么这个测试值得存在**：归因的失败模式全都是静默的——不抛异常，
只是把 `package` 置成 None 或者置成另一个 App。而它依赖的是一个**时序**性质
（事件何时落盘 vs 流何时到达），这种东西在真机上复现成本高、且时快时慢。
把时序抽象成"先写哪些事件再问"就能离线钉死。
"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from attribution import AMBIGUITY_MS, MATCH_TOLERANCE_MS, TimeAttribution  # noqa: E402

A = "com.vscanner.targetapp"
B = "com.vscanner.targetapp2"

# 实测时间线（见 DECISIONS D403）。flow 用的主机时钟，host_received_ts 同。
FLOW_A_TS = 1790172252081
FLOW_B_TS = 1790172257934
EGRESS_A_TS = 1790172252079   # 比它的流早 2ms —— 赶上了
EGRESS_B_TS = 1790172257999   # 比它的流晚 65ms —— 没赶上


def write_events(path: Path, events: list[tuple[int, str]]) -> None:
    with path.open("a", encoding="utf-8") as handle:
        for ts, package in events:
            handle.write(json.dumps(
                {"ev": "EGRESS_CONNECT", "package": package, "host_received_ts": ts}) + "\n")


class AttributionTimingTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "egress_events.jsonl"
        self.attrib = TimeAttribution([self.path])

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_health_and_failed_connections_are_not_candidates(self):
        with self.path.open('w', encoding='utf-8') as handle:
            for record in [dict(ev='ARMED'), dict(ev='EGRESS_CONNECT', outcome='error')]:
                handle.write(json.dumps(dict(record, package=A, host_received_ts=1000)) + '\n')
        self.assertFalse(self.attrib.resolve(1000).resolved)

    def test_late_competitor_changes_existing_candidate_to_ambiguous(self):
        write_events(self.path, [(1000, A)])
        self.assertFalse(self.attrib.resolve(1010).ambiguous)
        write_events(self.path, [(1015, B)])
        self.assertTrue(self.attrib.resolve(1010).ambiguous)

    def test_late_event_resolves_on_retry(self) -> None:
        """本阶段的核心不变量：同一个 ts，事件落盘前后问，答案不同。

        B 的事件比 B 的流晚 65ms 落盘。当场问是 unresolved，重试才拿到 targetapp2。
        这个差值（65ms）远小于 2000ms 容差——**算法没错，是问得太早**。
        所以 addon 必须挂起重试，而不是当场定案。
        """
        write_events(self.path, [(EGRESS_A_TS, A)])
        self.assertEqual(self.attrib.resolve(FLOW_B_TS).package, None,
                         "B 的事件还没落盘，此时不该归因成功")

        write_events(self.path, [(EGRESS_B_TS, B)])
        found = self.attrib.resolve(FLOW_B_TS)
        self.assertEqual(found.package, B)
        self.assertEqual(found.delta_ms, EGRESS_B_TS - FLOW_B_TS)
        self.assertFalse(found.ambiguous)

    def test_two_apps_resolve_to_their_own_flows(self) -> None:
        """A 与 B 并发外发时，各自对上各自的事件——不串包。"""
        write_events(self.path, [(EGRESS_A_TS, A), (EGRESS_B_TS, B)])
        self.assertEqual(self.attrib.resolve(FLOW_A_TS).package, A)
        self.assertEqual(self.attrib.resolve(FLOW_B_TS).package, B)

    def test_prefix_packages_are_not_confused(self) -> None:
        """`com.vscanner.targetapp` 是 `com.vscanner.targetapp2` 的前缀。

        这正是我上一轮误报 `*** CROSSED ***` 的原因——comparison 用了子串包含。
        归因本身返回的是精确字符串，这里是钉死这一点。
        """
        write_events(self.path, [(EGRESS_B_TS, B)])
        got = self.attrib.resolve(FLOW_B_TS).package
        self.assertEqual(got, B)
        self.assertNotEqual(got, A)
        self.assertFalse(got.startswith(A) and got == A)

    def test_ambiguity_is_flagged_not_guessed(self) -> None:
        """两个不同包名的事件同样接近时，不许挑一个——标 ambiguous。"""
        write_events(self.path, [(FLOW_B_TS - 100, A), (FLOW_B_TS + 100, B)])
        found = self.attrib.resolve(FLOW_B_TS)
        self.assertTrue(found.ambiguous)
        self.assertIsNotNone(found.runner_up)
        self.assertEqual(found.label, "ambiguous")

    def test_same_package_twice_is_not_ambiguous(self) -> None:
        """同一个 App 连了两次，仍然确定是它，不是歧义。"""
        write_events(self.path, [(FLOW_B_TS - 100, A), (FLOW_B_TS + 100, A)])
        found = self.attrib.resolve(FLOW_B_TS)
        self.assertFalse(found.ambiguous)
        self.assertEqual(found.package, A)
        self.assertEqual(found.label, "app_process_hook")

    def test_beyond_tolerance_is_unresolved(self) -> None:
        """超出容差就是没对上，不能"就近挑一个"。"""
        write_events(self.path, [(FLOW_B_TS + MATCH_TOLERANCE_MS + 1, B)])
        found = self.attrib.resolve(FLOW_B_TS)
        self.assertFalse(found.resolved)
        self.assertEqual(found.label, "unresolved")
        self.assertIsNone(found.package)

    def test_tolerance_boundary_is_inclusive(self) -> None:
        write_events(self.path, [(FLOW_B_TS + MATCH_TOLERANCE_MS, B)])
        self.assertTrue(self.attrib.resolve(FLOW_B_TS).resolved)

    def test_ambiguity_boundary(self) -> None:
        """恰好等于 AMBIGUITY_MS 算歧义（<=），再远一点就不算。"""
        write_events(self.path, [(FLOW_B_TS - 10, A)])
        write_events(self.path, [(FLOW_B_TS + 10 + AMBIGUITY_MS, B)])
        self.assertTrue(self.attrib.resolve(FLOW_B_TS).ambiguous)

    def test_half_written_line_is_not_lost(self) -> None:
        """读到半截行时**不能推进偏移**，否则那条记录永久丢失。

        实测命中过：事件文件由 run.py 在另一个进程里边跑边追加，addon 与它并发读。
        `host_received_ts` 是在 json.dumps/open/write **之前**取的，所以完全可能
        "时间戳已定、字节还没落全"。旧写法（for 循环 + tell()）会越过那半截行，
        下轮从中间开始读，两半都解析失败——**文件里明明有，归因永远看不到**。
        """
        partial = json.dumps(
            {"ev": "EGRESS_CONNECT", "package": B, "host_received_ts": FLOW_B_TS - 10})
        # 先写完整的第一条
        write_events(self.path, [(FLOW_B_TS - 9000, A)])
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(partial[:len(partial) // 2])  # 只有半行，没有换行符

        self.assertIsNone(self.attrib.resolve(FLOW_B_TS).package,
                          "半截行不该被当成有效记录")

        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(partial[len(partial) // 2:] + "\n")  # 补完

        found = self.attrib.resolve(FLOW_B_TS)
        self.assertEqual(found.package, B,
                         "补完的整行必须能被读到——旧写法在这里会永久丢记录")
        self.assertEqual(found.delta_ms, 10)

    def test_missing_file_is_not_an_error(self) -> None:
        """事件文件还没建出来时不能崩——它是在 run.py 第一次落盘时才出现的。"""
        self.assertFalse(self.path.exists())
        self.assertFalse(self.attrib.resolve(FLOW_B_TS).resolved)


if __name__ == "__main__":
    unittest.main(verbosity=2)
