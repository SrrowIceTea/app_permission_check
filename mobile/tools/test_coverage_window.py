"""coverage_window 的单测：段账目 → 有效观测时长/截断判定。

这些数字会直接进 verification.json / batch-summary.json，并且被报告用来限定
"窗口内未观察到 X" 这类阴性结论的范围——算错就是把"没看"说成"没有"。
"""
from __future__ import annotations

import unittest

import coverage_window as cov


class SegmentEntry(unittest.TestCase):
    def test_dead_segment_uses_tombstone_uptime_when_available(self):
        """死亡段的有效观测优先用墓碑自报的 uptime（精确），不吃墙钟的轮询误差。"""
        e = cov.segment_entry(0, 100.0, 140.0, False, {"uptime_s": 16}, events=2)
        self.assertEqual(e["observed_s"], 16.0)
        self.assertEqual(e["elapsed_s"], 40.0)

    def test_dead_segment_without_death_time_is_unknown_not_wallclock(self):
        """知道它死了、但不知道死在哪一刻 → 这一段没有可用的观测时长。

        2026-10-19 实测反例：`a1-args-2` 因为拿不到墓碑，旧实现把 156.5s 墙钟
        记成 `observed_s`（预算是 45s），等于把"死了一分半都不知道"写成"全程都看着"。
        """
        e = cov.segment_entry(0, 100.0, 256.5, False, {"uptime_s": None})
        self.assertIsNone(e["observed_s"])
        self.assertEqual(e["elapsed_s"], 156.5, "墙钟仍要留档，只是不能当观测时长")
        self.assertEqual(e["observed_basis"], "unknown_death")

    def test_dead_segment_uses_death_ts_when_uptime_missing(self):
        """墓碑没有 uptime 但有时间戳时，用时间戳换算死亡偏移（smoke5 的形态）。"""
        e = cov.segment_entry(0, 1000.0, 1060.0, False,
                              {"uptime_s": None, "death_ts_ms": 1_021_500})
        self.assertEqual(e["observed_s"], 21.5)
        self.assertEqual(e["observed_basis"], "death_ts")

    def test_stale_death_ts_before_segment_start_is_ignored(self):
        """墓碑比本段还早 → 这条证据不是本段的，不许拿它算偏移。"""
        e = cov.segment_entry(0, 1000.0, 1060.0, False,
                              {"uptime_s": None, "death_ts_ms": 705_700})
        self.assertIsNone(e["observed_s"])
        self.assertEqual(e["observed_basis"], "unknown_death")

    def test_alive_segment_counts_full_elapsed(self):
        e = cov.segment_entry(0, 100.0, 180.0, True)
        self.assertEqual(e["observed_s"], 80.0)

    def test_unknown_alive_is_not_counted_as_observed(self):
        e = cov.segment_entry(0, 100.0, 180.0, None)
        self.assertIsNone(e["observed_s"])


class Summarize(unittest.TestCase):
    def test_alive_only_window(self):
        segs = [cov.segment_entry(0, 0, 100, True, events=10)]
        s = cov.summarize(segs, 100)
        self.assertFalse(s["truncated"])
        self.assertEqual(s["observed_s"], 100.0)
        self.assertEqual(s["coverage_ratio"], 1.0)
        self.assertEqual(s["deaths"], 0)
        self.assertIn("窗口完整", s["caveat"])

    def test_death_then_restart_accumulates_both_segments(self):
        """死在第 16s、重启后又采了 85s → 观测 101s 超过 100s 预算，须截到预算并记 overrun。"""
        segs = [cov.segment_entry(0, 0, 30, False, {"uptime_s": 16}, events=2),
                cov.segment_entry(1, 35, 120, True, events=7)]
        s = cov.summarize(segs, 100)
        self.assertTrue(s["truncated"])
        self.assertEqual(s["deaths"], 1)
        self.assertEqual(s["observed_s"], 100.0)   # 16 + 85 = 101，截到预算
        self.assertEqual(s["overrun_s"], 1.0)      # 超出的 1s 记在 overrun，不冒充观测
        self.assertEqual(s["coverage_ratio"], 1.0)
        self.assertEqual(s["first_death_at_s"], 16.0)
        self.assertEqual(s["events_total"], 9)
        self.assertIn("窗口被截断", s["caveat"])

    def test_unknown_death_at_is_excluded_and_said_out_loud(self):
        segs = [cov.segment_entry(0, 0, 30, False, {"uptime_s": None}),
                cov.segment_entry(1, 40, 90, True)]
        s = cov.summarize(segs, 100)
        self.assertTrue(s["truncated"])
        self.assertEqual(s["unknown_death_at"], 1)
        self.assertEqual(s["observed_s"], 50.0, "只算第 2 段的 50s")
        self.assertIn("死亡时刻无法确认", s["caveat"])

    def test_first_death_is_reported_in_window_time_not_segment_time(self):
        """第 2 段死在段内第 10s，但窗口已经过了 40s → 首死应记 50s。"""
        segs = [cov.segment_entry(0, 0, 30, True),
                cov.segment_entry(1, 40, 70, False, {"uptime_s": 10})]
        s = cov.summarize(segs, 100, window_t0=0)
        self.assertEqual(s["first_death_at_s"], 50.0)

    def test_death_without_restart_exposes_lost_time(self):
        segs = [cov.segment_entry(0, 0, 30, False, {"uptime_s": 16})]
        s = cov.summarize(segs, 100)
        self.assertTrue(s["truncated"])
        self.assertEqual(s["observed_s"], 16.0)
        self.assertAlmostEqual(s["coverage_ratio"], 0.16)
        self.assertIn("未观测", s["caveat"])

    def test_unknown_alive_segments_do_not_fake_survival(self):
        segs = [cov.segment_entry(0, 0, 100, None)]
        s = cov.summarize(segs, 100)
        self.assertFalse(s["truncated"], "没测到 ≠ 崩了")
        self.assertIsNone(s["observed_s"], "没测到也不能贡献观测时长")
        self.assertEqual(s["unknown_alive"], 1)
        self.assertIn("无法判定", s["caveat"])

    def test_empty_segments_is_legacy_not_complete(self):
        s = cov.summarize([], 100)
        self.assertEqual(s["segments"], 0)
        self.assertIn("旧产物", s["caveat"])

    def test_uptime_longer_than_segment_is_clamped_and_said_so(self):
        """进程比钩子先起来时，uptime(38) > 本段长度(36.5)。

        有效观测只能是 36.5，且 `observed_basis` 不许写成 "uptime"——
        否则读报告的人会以为 36.5 是进程自报的（2026-10-19 实机 final-check-1 现场）。
        """
        e = cov.segment_entry(0, 1000.0, 1036.5, False, {"uptime_s": 38})
        self.assertEqual(e["observed_s"], 36.5)
        self.assertEqual(e["observed_basis"], "wall_clock_clamped")
        self.assertEqual(e["death_offset_s"], 38.0, "原始 uptime 留档备查")
        s = cov.summarize([e], 50)
        self.assertEqual(s["first_death_at_s"], 36.5, "「窗口第几秒」不能超过段长")
        self.assertEqual(s["observed_s"], 36.5)


if __name__ == "__main__":
    unittest.main()
