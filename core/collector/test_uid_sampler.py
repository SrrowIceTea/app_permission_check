#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""V-Scanner Phase 4 — uid_sampler 的离线用例（不需要设备、不需要 adb）。

仅用于授权测试（自有设备与自有 APK）/ For authorized testing on owned devices and APKs only.

    python -m unittest test_uid_sampler -v

**为什么这个测试值得存在**：`uid_sampler` 的失败模式全是静默的。早先 `adb()` 把
超时/`OSError`/退出码非 0 一律折成空串，于是"命令跑通了但没输出"与"adb 压根没起来"
长得一模一样——包名静默记成 `package: null`、时钟标定静默取 0 偏移（后者会污染
整个归因时间窗，而 0 看起来就像"已经标定好了"）。§8.6 铁律 3 要求任何调用方都能
区分"失败"与"空结果"，这里就把这条钉死。

全部用例都把 `adb` patch 掉，**不碰设备**——所以它进得了离线回归。
"""
from __future__ import annotations

import os
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

import uid_sampler  # noqa: E402


class DevicePathTest(unittest.TestCase):
    def test_paths_carry_the_pid_so_two_instances_do_not_clobber_each_other(self) -> None:
        """固定路径时两个并发采集实例会互相 `rm -f` 对方正在写的文件（§8.2 B-4）。"""
        log = uid_sampler.device_log_path()
        script = uid_sampler.device_script_path()
        self.assertIn(f".{os.getpid()}.", log)
        self.assertIn(f".{os.getpid()}.", script)
        self.assertNotEqual(log, script, "日志与被执行的脚本不能是同一个文件")


class AdbTest(unittest.TestCase):
    def test_nonzero_exit_is_a_failure_not_an_empty_result(self) -> None:
        """多设备时裸 `adb` 一律报错返回空串（M027）——正是这里要挡的形态。"""
        done = subprocess.CompletedProcess([], 1, stdout="")
        with mock.patch.object(uid_sampler.subprocess, "run", return_value=done):
            ok, _ = uid_sampler.adb("shell", "date")
        self.assertFalse(ok)

    def test_timeout_and_oserror_keep_the_reason(self) -> None:
        for exc in (subprocess.TimeoutExpired("adb", 30), OSError("adb not found")):
            with mock.patch.object(uid_sampler.subprocess, "run", side_effect=exc):
                ok, text = uid_sampler.adb("shell", "date")
            self.assertFalse(ok)
            self.assertTrue(text.strip(), "失败原因必须非空，否则下游只剩一句『空结果』")

    def test_success_returns_the_stdout(self) -> None:
        done = subprocess.CompletedProcess([], 0, stdout="ok\n")
        with mock.patch.object(uid_sampler.subprocess, "run", return_value=done):
            self.assertEqual((True, "ok\n"), uid_sampler.adb("shell", "date"))


class ClockOffsetTest(unittest.TestCase):
    def test_all_samples_failing_raises_instead_of_returning_zero(self) -> None:
        """回退到 0 会被下游当成"时钟已标定"，静默污染整个归因时间窗。"""
        with mock.patch.object(uid_sampler, "adb", return_value=(False, "boom")):
            with self.assertRaises(uid_sampler.AdbError):
                uid_sampler.measure_clock_offset_ms()

    def test_unparsable_device_time_is_also_a_failure(self) -> None:
        with mock.patch.object(uid_sampler, "adb", return_value=(True, "not-a-number")):
            with self.assertRaises(uid_sampler.AdbError):
                uid_sampler.measure_clock_offset_ms()

    def test_median_sample_wins_and_the_unit_is_ms(self) -> None:
        host = 1_000_000_000_000_000_000
        device = [host + 2_000_000_000] * 4 + [host + 900_000_000_000]   # 末次是离谱值
        with mock.patch.object(uid_sampler, "adb",
                               side_effect=[(True, str(v)) for v in device]), \
                mock.patch.object(uid_sampler.time, "time_ns", return_value=host):
            self.assertEqual(2000, uid_sampler.measure_clock_offset_ms())


class PackageMapTest(unittest.TestCase):
    def test_lookup_failure_raises_and_is_never_cached(self) -> None:
        """失败不入缓存：否则一次 adb 抖动会把那个 uid 永久钉成 null。"""
        packages = uid_sampler.PackageMap()
        with mock.patch.object(uid_sampler, "adb", return_value=(False, "device offline")):
            for _ in range(2):
                with self.assertRaises(uid_sampler.AdbError):
                    packages.package_for(1010212)
        self.assertEqual({}, packages._cache)

    def test_first_package_line_wins_and_success_is_cached(self) -> None:
        reply = (True, "package:com.example.a\npackage:com.example.b\n")
        with mock.patch.object(uid_sampler, "adb", return_value=reply) as fake:
            packages = uid_sampler.PackageMap()
            self.assertEqual("com.example.a", packages.package_for(1010212))
            self.assertEqual("com.example.a", packages.package_for(1010212))
            self.assertEqual(1, fake.call_count, "命中缓存时不该再走 adb")

    def test_no_package_line_is_a_null_result_not_a_failure(self) -> None:
        """没有包名（该 uid 真没装应用）是 None；没查到必须抛——两者不能长得一样。"""
        with mock.patch.object(uid_sampler, "adb", return_value=(True, "")):
            self.assertIsNone(uid_sampler.PackageMap().package_for(999))


class RowRegexTest(unittest.TestCase):
    def test_parses_a_proc_net_tcp_row_carrying_the_sampled_timestamp(self) -> None:
        line = ("1697000000123456789 0: 0A000010:36D4 0A000002:22B8 01 "
                "00000000:00000000 00:00000000 00000000 1010212 0 12345")
        match = uid_sampler.ROW.match(line)
        self.assertIsNotNone(match, "设备侧 sed 加的前缀时间戳必须仍能解析出 uid 与端口")
        ts, _lip, lport, _rip, rport, state, uid = match.groups()
        self.assertEqual("1697000000123456789", ts)
        self.assertEqual(0x36D4, int(lport, 16))
        self.assertEqual("22B8", rport.upper())
        self.assertEqual("01", state)
        self.assertEqual(1010212, int(uid))

    def test_a_non_tcp_line_is_ignored(self) -> None:
        self.assertIsNone(uid_sampler.ROW.match("cat: /proc/net/tcp: Permission denied"))


if __name__ == "__main__":
    unittest.main()
