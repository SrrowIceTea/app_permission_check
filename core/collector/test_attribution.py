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
from attribution import AMBIGUITY_MS, MATCH_TOLERANCE_MS, TimeAttribution, target_match  # noqa: E402

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


def write_target_events(path: Path, events: list[tuple[int, str, str | None, str | None]]) -> None:
    """带目标地址的 egress 事件：(ts, package, target_host, target_ip)。"""
    with path.open("a", encoding="utf-8") as handle:
        for ts, package, host, ip in events:
            handle.write(json.dumps(
                {"ev": "EGRESS_CONNECT", "package": package, "host_received_ts": ts,
                 "target_host": host, "target_ip": ip}) + "\n")


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


class TargetMatchTest(unittest.TestCase):
    """目标地址校验：只有"目标匹配"的候选才能归属（见 core/collector/DECISIONS D413）。

    这是修掉移动端"别的 App 的流被静默认领给被审计包"的第二信号——时间归因的固有
    盲区（"真主迟到 600ms + 竞争者 65ms"与"真主就是 65ms 那个"证据同形）只能靠它补。
    """

    def test_four_way_identity(self) -> None:
        """host/IP/peername 三选一：任一非空字段对上就算匹配。"""
        self.assertTrue(target_match({"host": "api.example.com", "ip": "1.2.3.4"},
                                     {"host": "api.example.com", "ip": "5.6.7.8"}))  # host 同
        self.assertTrue(target_match({"host": "1.2.3.4", "ip": "1.2.3.4"},
                                     {"host": "api.example.com", "ip": "1.2.3.4"}))  # OkHttp 返回 IP
        self.assertTrue(target_match({"host": "API.Example.COM", "ip": None},
                                     {"host": "api.example.com", "ip": "1.2.3.4"}))  # 大小写
        self.assertFalse(target_match({"host": "api.example.com", "ip": "1.2.3.4"},
                                      {"host": "evil.net", "ip": "9.9.9.9"}))  # 都不匹配
        self.assertFalse(target_match(None, {"host": "h", "ip": "1.1.1.1"}))  # uid 事件无目标
        self.assertFalse(target_match({"host": None, "ip": None},
                                      {"host": "h", "ip": None}))  # 事件侧全空

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "egress_events.jsonl"

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_matching_target_resolves(self) -> None:
        write_target_events(self.path, [(1000, A, "api.example.com", "1.2.3.4")])
        found = TimeAttribution([self.path], target_check=True).resolve(
            1010, {"host": "api.example.com", "ip": "1.2.3.4"})
        self.assertEqual(found.package, A)

    def test_cdn_ip_divergence_still_matches_via_host(self) -> None:
        """两端解析域名拿到不同 CDN IP → 靠 host 兜住，不落到 unresolved。"""
        write_target_events(self.path, [(1000, A, "api.example.com", "1.2.3.4")])
        found = TimeAttribution([self.path], target_check=True).resolve(
            1010, {"host": "api.example.com", "ip": "5.6.7.8"})
        self.assertEqual(found.package, A)

    def test_mismatching_target_is_unresolved(self) -> None:
        """别的 App 的流（不同目标）不得认领给 A——宁缺勿错。"""
        write_target_events(self.path, [(1000, A, "api.example.com", "1.2.3.4")])
        found = TimeAttribution([self.path], target_check=True).resolve(
            1010, {"host": "evil.example.net", "ip": "9.9.9.9"})
        self.assertFalse(found.resolved)
        self.assertEqual(found.label, "unresolved")

    def test_check_off_keeps_time_only(self) -> None:
        """目标校验默认关：reverse 模式下仍按时间就近归因（D413 的显式开关）。"""
        write_target_events(self.path, [(1000, A, "api.example.com", "1.2.3.4")])
        found = TimeAttribution([self.path], target_check=False).resolve(
            1010, {"host": "evil.example.net", "ip": "9.9.9.9"})
        self.assertEqual(found.package, A)

    def test_no_target_event_excluded_when_check_on(self) -> None:
        """uid_sampler 风格事件（无目标）在目标校验开启时不得参与。"""
        write_events(self.path, [(1000, A)])
        found = TimeAttribution([self.path], target_check=True).resolve(
            1010, {"host": "api.example.com", "ip": "1.2.3.4"})
        self.assertFalse(found.resolved)

    def test_candidates_populated(self) -> None:
        """Top-K 候选扩成列表（D414），取证价值高于只存亚军。"""
        write_target_events(self.path, [(1000, A, "h", "1.1.1.1"),
                                        (1010, B, "h2", "2.2.2.2")])
        found = TimeAttribution([self.path]).resolve(1005)
        self.assertEqual(found.package, A)
        self.assertEqual(len(found.candidates), 2)
        self.assertEqual(found.candidates[0]["package"], A)
        self.assertEqual(found.candidates[1]["package"], B)


class ConservativeTest(unittest.TestCase):
    """保守弃权开关（D415）：存在竞争候选即弃权，宁可错杀不可静默串包。

    默认关（保留并发确定性）；`conservative=True` 时，容差窗口内只要有另一个包名的
    候选——无论离冠军多远——都标 ambiguous。代价是 D407 的双应用并发 MATCH 退化。
    """

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "egress_events.jsonl"

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_off_distant_runner_up_still_resolves(self) -> None:
        """默认：亚军离冠军超过 AMBIGUITY_MS 就不构成歧义，正常归因。"""
        write_events(self.path, [(1000, A), (1700, B)])  # 亚军离冠军 700ms > 500ms
        found = TimeAttribution([self.path]).resolve(1000)
        self.assertFalse(found.ambiguous)
        self.assertEqual(found.package, A)

    def test_on_distant_runner_up_abstains(self) -> None:
        """保守：亚军即使在 AMBIGUITY_MS 之外，也照样弃权。"""
        write_events(self.path, [(1000, A), (1700, B)])
        found = TimeAttribution([self.path], conservative=True).resolve(1000)
        self.assertTrue(found.ambiguous)
        self.assertEqual(found.label, "ambiguous")
        self.assertEqual(found.runner_up, B)

    def test_on_no_rival_not_ambiguous(self) -> None:
        write_events(self.path, [(1000, A)])
        found = TimeAttribution([self.path], conservative=True).resolve(1005)
        self.assertFalse(found.ambiguous)
        self.assertEqual(found.package, A)

    def test_on_same_package_twice_not_ambiguous(self) -> None:
        """同一包两次连接不算竞争候选——仍确定是它。"""
        write_events(self.path, [(1000, A), (1700, A)])
        found = TimeAttribution([self.path], conservative=True).resolve(1000)
        self.assertFalse(found.ambiguous)
        self.assertEqual(found.package, A)

    def test_on_runner_up_beyond_tolerance_is_ignored(self) -> None:
        """容差窗口外的候选不参与 resolve，故不构成竞争候选、不弃权。"""
        write_events(self.path, [(1000, A), (1000 + MATCH_TOLERANCE_MS + 1, B)])
        found = TimeAttribution([self.path], conservative=True).resolve(1000)
        self.assertFalse(found.ambiguous)
        self.assertEqual(found.package, A)


if __name__ == "__main__":
    unittest.main(verbosity=2)
