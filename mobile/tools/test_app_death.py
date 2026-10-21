#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""app 死亡取证的离线回归。

测试数据（逐字抄录的 crash 缓冲片段）见 `_app_death_fixtures.py`，本文件只留
断言逻辑。数据含义：
  - NATIVE_SIGABRT：Fossify Camera 的真实 SIGABRT tombstone（旧实现曾写成
    fatal_lines=[]、cause=null，而证据明明躺在设备上）；
  - SAME_MS_NEIGHBOUR：模拟器 UWB HAL 与 breezy 的日志**同毫秒**缝在一起的真实四行
    （曾导致把 UWB 的 abort message 写成 breezy 的死因）；
  - SIGSEGV_NO_TOMBSTONE / 尾 15 字符进程名：breezy 与 keepass 的真实 signal 行。

只测纯函数 parse_app_death——它不碰 adb，跑在离线回归里；真正的设备取证
（app_death_reason）靠这条解析链路保底。
"""
from __future__ import annotations

import unittest

from thirdparty_env import parse_app_death, orchestrator_notes, _representative_death
from _app_death_fixtures import (
    PKG, NATIVE_SIGABRT, OTHER_PROCESS_NOISE, JAVA_CRASH, SAME_MS_NEIGHBOUR,
    SIGSEGV_NO_TOMBSTONE, JIT_SEGV_20261019, NEIGHBOUR_HEADER_THEN_OUR_CMDLINE,
    TWO_RUNS_SAME_PACKAGE, JAVA_TWO_RUNS, PREFIX_COLLISION,
)


class ParseAppDeath(unittest.TestCase):
    def test_native_sigabrt_survives_timestamp_split(self):
        """libc 行与 tombstone 时间戳不同前缀——按块合并后两者都要保住。"""
        r = parse_app_death(NATIVE_SIGABRT, PKG)
        self.assertTrue(r["fatal_lines"], "Fatal signal 行必须被保留")
        self.assertIn("Fatal signal 6 (SIGABRT)", r["fatal_lines"][0])
        self.assertIsNotNone(r["cause"], "Abort message 必须被抽出来")
        self.assertIn("dalvik-main space", r["cause"])

    def test_other_process_crash_is_not_attributed(self):
        """别的进程崩在同窗口——不能扣到目标应用头上。"""
        r = parse_app_death(OTHER_PROCESS_NOISE, PKG)
        self.assertEqual(r["fatal_lines"], [])
        self.assertIsNone(r["cause"])

    def test_java_fatal_exception_yields_cause(self):
        r = parse_app_death(JAVA_CRASH, PKG)
        self.assertTrue(any("FATAL EXCEPTION" in l for l in r["fatal_lines"]))
        self.assertIsNotNone(r["cause"])
        self.assertIn("Exception", r["cause"])

    def test_mixed_log_picks_target_only(self):
        r = parse_app_death(OTHER_PROCESS_NOISE + NATIVE_SIGABRT, PKG)
        self.assertIn("dalvik-main space", r["cause"] or "")
        self.assertNotIn("uwb", (r["cause"] or "").lower())

    def test_no_crash_returns_empty(self):
        r = parse_app_death("10-13 15:00:00.000  123  123 I ActivityManager: Start proc org.fossify.camera\n", PKG)
        self.assertEqual(r["fatal_lines"], [])
        self.assertIsNone(r["cause"])

    def test_fatal_lines_capped_at_three(self):
        r = parse_app_death(NATIVE_SIGABRT + JAVA_CRASH, PKG)
        self.assertLessEqual(len(r["fatal_lines"]), 3)

    def test_same_millisecond_neighbour_is_not_stitched(self):
        """同一毫秒的邻居崩溃（UWB HAL）不得被缝进目标应用的死亡记录。

        这是 2026-10-13 真实踩过的坑：按"同时间前缀块"归属时，breezy 的死亡
        cause 被写成了 UWB 的 "failed to open the serial device"。
        """
        r = parse_app_death(SAME_MS_NEIGHBOUR, "org.breezyweather")
        self.assertEqual(r["fatal_lines"], [], "邻居的 Fatal signal 不能被算成我们的")
        self.assertIsNone(r["cause"], "邻居的 Abort message 不能被扣到我们头上")

    def test_signal_line_without_tombstone_is_kept(self):
        """tombstone 被崩溃循环挤出缓冲时，signal 行仍要如实保留（cause=null）。

        进程名在日志里是包名尾部 15 字符（g.breezyweather），必须认得出来。
        还要能从这条行推出死亡时刻——否则 coverage 只能记"不知道死了多久"。
        """
        r = parse_app_death(SIGSEGV_NO_TOMBSTONE, "org.breezyweather")
        self.assertEqual(len(r["fatal_lines"]), 1)
        self.assertIn("SIGSEGV", r["fatal_lines"][0])
        self.assertIn("g.breezyweather", r["fatal_lines"][0])
        self.assertIsNone(r["cause"])
        self.assertIsNotNone(r["death_ts_ms"], "只剩 signal 行时用日志时间戳兜底")
        self.assertEqual(r["death_ts_source"], "logcat_fatal_line")

    def test_fatal_line_older_than_segment_is_dropped(self):
        """since_ms 必须也管住 Fatal signal 行（旧轮崩溃不能算进本段）。"""
        r = parse_app_death(SIGSEGV_NO_TOMBSTONE, "org.breezyweather",
                            since_ms=1792400000000)
        self.assertEqual(r["fatal_lines"], [])
        self.assertIsNone(r["death_ts_ms"])

    def test_tail15_name_form_matches(self):
        """keepass 形态：com.kunzisoft.keepass.libre → t.keepass.libre（尾 15 字符）。"""
        frag = ("10-13 14:59:50.375 F/libc    (16323): Fatal signal 11 (SIGSEGV), code 1"
                " (SEGV_MAPERR), fault addr 0x0 in tid 16323 (t.keepass.libre),"
                " pid 16323 (t.keepass.libre)\n")
        r = parse_app_death(frag, "com.kunzisoft.keepass.libre")
        self.assertEqual(len(r["fatal_lines"]), 1)
        self.assertIn("SIGSEGV", r["fatal_lines"][0])

    # ---- 2026-10-19 夹具真实崩溃（JIT 线程 SIGSEGV）----
    def test_real_20261019_jit_segv_reads_uptime_and_signal(self):
        """真实形态：崩在 Jit thread pool，墓碑里没有 Abort message，但有 uptime。

        `Process uptime: 16s` 是"死在窗口第几秒"的权威来源（进程自报），报告要拿它
        限定阴性结论的观测范围；没有它就只能用墙钟，最多差一个轮询周期。
        """
        r = parse_app_death(JIT_SEGV_20261019, "com.vscanner.privacydemo")
        self.assertEqual(r["fatal_lines"][0].count("Fatal signal"), 1)
        self.assertIsNone(r["cause"], "SIGSEGV 墓碑通常没有 Abort message，不能瞎填")
        self.assertTrue(r["tombstone_seen"])
        self.assertEqual(r["uptime_s"], 16)
        self.assertEqual(r["signal"], "SIGSEGV")
        self.assertEqual(r["thread"], "Jit thread pool")
        self.assertEqual(r["fault_addr"], "0x71bcb9a08000")
        self.assertEqual(r["death_ts_ms"], 1792406330785)

    def test_truncated_tombstone_does_not_borrow_neighbour_abort(self):
        """我们的墓碑头被挤掉、紧挨着的是 UWB 的墓碑——不得借它的 Abort message。

        这是 2026-10-19 现场真实产物里的错误：夹具 SIGSEGV 的 `cause` 被写成
        "failed to open the serial device"（UWB HAL 的 panic）。旧的"锚 Cmdline
        →向前找最近的头→向后扫"写法在这里必错，因为最近的头是邻居的。
        """
        r = parse_app_death(NEIGHBOUR_HEADER_THEN_OUR_CMDLINE, "com.vscanner.privacydemo")
        self.assertEqual(len(r["fatal_lines"]), 1, "我们自己的 signal 行仍要保留")
        self.assertIsNone(r["cause"], "邻居的 Abort message 不得被扣到我们头上")
        self.assertTrue(r["tombstone_seen"], "我们的 Cmdline 残片还在")
        self.assertFalse(r["tombstone_complete"], "残片没有 `*** *** ***` 头 → 不完整，需走设备兜底")
        self.assertIsNone(r["uptime_s"])

    def test_pid_filter_rejects_previous_run_of_same_package(self):
        """同一个包名的**上一轮**崩溃不能算到本段头上（2026-10-19 冒烟实测）。

        段 0 被 force-stop 时，`logcat -d` 里还留着 5 分钟前另一次运行的 SIGSEGV +
        `Process uptime: 29s`，只按包名匹配就会把上一轮的死亡当成这一段的死因。
        """
        r = parse_app_death(TWO_RUNS_SAME_PACKAGE, "com.vscanner.privacydemo", pid="21131")
        self.assertTrue(all("pid 21131 " in ln for ln in r["fatal_lines"]),
                        "只保留本 pid 的 signal 行")
        self.assertEqual(r["uptime_s"], 27)
        self.assertEqual(r["signal"], "SIGABRT")

        r_old = parse_app_death(TWO_RUNS_SAME_PACKAGE, "com.vscanner.privacydemo", pid="13837")
        self.assertEqual(r_old["signal"], "SIGSEGV")
        self.assertEqual(r_old["uptime_s"], 29)

        r_none = parse_app_death(TWO_RUNS_SAME_PACKAGE, "com.vscanner.privacydemo", pid="99999")
        self.assertEqual(r_none["fatal_lines"], [], "别的 pid 的崩溃一条都不留")
        self.assertIsNone(r_none["uptime_s"])


class JavaPathFilters(unittest.TestCase):
    """Java `FATAL EXCEPTION` 路径的 pid / 包名 / 时间过滤（2026-10-19 复核补）。"""

    def test_java_crash_respects_pid(self):
        r = parse_app_death(JAVA_TWO_RUNS, "com.foo", pid=7301)
        self.assertEqual(len(r["fatal_lines"]), 1, "只留本 pid 那条")
        self.assertIn("NullPointerException", r["cause"])

        r_old = parse_app_death(JAVA_TWO_RUNS, "com.foo", pid=9000)
        self.assertIn("IllegalStateException", r_old["cause"])

        r_none = parse_app_death(JAVA_TWO_RUNS, "com.foo", pid=1234)
        self.assertEqual(r_none["fatal_lines"], [], "上一轮的 Java 崩溃不能算到本段")
        self.assertIsNone(r_none["cause"])

    def test_java_crash_respects_since(self):
        # 15:00 那次比 since 早一小时，必须被丢掉（日志行按 UTC 解释，与 offset_s=0 同口径）
        import calendar as _cal
        import time as _t
        epoch = _cal.timegm(_t.strptime("2026-10-13 16:00:00", "%Y-%m-%d %H:%M:%S"))
        r = parse_app_death(JAVA_TWO_RUNS, "com.foo", since_ms=int(epoch * 1000))
        self.assertEqual(len(r["fatal_lines"]), 1)
        self.assertIn("NullPointerException", r["cause"])

    def test_package_prefix_is_not_a_match(self):
        """`com.foobar` 不是 `com.foo`：Java 与 native 两条路径都要挡住。"""
        r = parse_app_death(PREFIX_COLLISION, "com.foo")
        self.assertEqual(r["fatal_lines"], [])
        self.assertIsNone(r["cause"])
        self.assertIsNone(r["signal"])

    def test_subprocess_is_not_main_process(self):
        """`com.foo:remote` 是子进程，不该算成主进程的死。"""
        raw = ("10-13 15:00:00.100  8888  8888 E AndroidRuntime: FATAL EXCEPTION: main\n"
               "10-13 15:00:00.100  8888  8888 E AndroidRuntime: "
               "Process: com.foo:remote, PID: 8888\n")
        r = parse_app_death(raw, "com.foo")
        self.assertEqual(r["fatal_lines"], [])


class RepresentativeDeath(unittest.TestCase):
    """多段采集：报告要引用第一次死亡的证据（a4-smoke5 的失真回归）。"""

    def test_first_death_segment_wins_over_empty_final(self):
        death = {"window_alive": False, "hooked_pid_alive": False,
                 "signal": None, "thread": None, "uptime_s": None, "cause": None}
        coverage = {"detail": [
            {"index": 0, "alive_at_end": False,
             "death": {"signal": "SIGSEGV", "thread": "Jit thread pool", "uptime_s": 33}},
            {"index": 1, "alive_at_end": True, "death": None},
        ]}
        d = _representative_death(death, coverage)
        self.assertEqual(d["signal"], "SIGSEGV")
        self.assertEqual(d["thread"], "Jit thread pool")
        notes = orchestrator_notes(death, "com.example", coverage)
        self.assertTrue(any("SIGSEGV" in n and "Jit thread pool" in n for n in notes),
                        f"注释应带真实死因，实际：{notes}")

    def test_final_death_kept_when_it_has_evidence(self):
        death = {"window_alive": False, "signal": "SIGABRT", "uptime_s": 12}
        coverage = {"detail": [{"index": 0, "alive_at_end": False,
                                "death": {"signal": "SIGSEGV", "uptime_s": 5}}]}
        self.assertEqual(_representative_death(death, coverage)["signal"], "SIGABRT")

    def test_no_coverage_is_harmless(self):
        death = {"window_alive": False, "signal": "SIGSEGV"}
        self.assertEqual(_representative_death(death, None)["signal"], "SIGSEGV")
        self.assertEqual(_representative_death(None, None), {})


if __name__ == "__main__":
    unittest.main()