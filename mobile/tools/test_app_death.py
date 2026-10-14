#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""app 死亡取证的离线回归。

测试数据不是编的，全部来自 2026-10-13 设备 crash 缓冲的**逐字抄录**：
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

from thirdparty_env import parse_app_death

PKG = "org.fossify.camera"

# 真实片段：libc 一行在 crash 缓冲、tombstone 在其后约 2 秒打出（不同时间戳前缀，
# 所以"按相邻行找原因"的旧写法必丢）。
NATIVE_SIGABRT = """\
10-13 14:35:12.426  7079  7079 F libc    : Fatal signal 6 (SIGABRT), code -1 (SI_QUEUE) in tid 7079 (.fossify.camera), pid 7079 (.fossify.camera)
10-13 14:35:14.730  8276  8276 F DEBUG   : Timestamp: 2026-10-13 14:35:12.852395700+0000
10-13 14:35:14.730  8276  8276 F DEBUG   : Cmdline: org.fossify.camera
10-13 14:35:14.730  8276  8276 F DEBUG   : pid: 7079, ppid: 459, tid: 7079, name: .fossify.camera  >>> org.fossify.camera <<<
10-13 14:35:14.730  8276  8276 F DEBUG   : uid: 10230
10-13 14:35:14.730  8276  8276 F DEBUG   : signal 6 (SIGABRT), code -1 (SI_QUEUE), fault addr --------
10-13 14:35:14.730  8276  8276 F DEBUG   : Abort message: '02000000-0e000000 rw-p 00000000 00:00 0                                  [anon:dalvik-main space]'
10-13 14:35:14.730  8276  8276 F DEBUG   : backtrace:
10-13 14:35:14.730  8276  8276 F DEBUG   :       #00 pc 000000000005b06d  /apex/com.android.runtime/lib64/bionic/libc.so (abort+189)
10-13 14:35:14.730  8276  8276 F DEBUG   :       #01 pc 0000000000000a2b  <anonymous:797ba79e8000>
"""

# 干扰项：同一时间窗里**别的进程**在反复崩（模拟器的 UWB HAL 崩溃循环），
# 取证不能把别人的 Abort message 扣到目标应用头上。
OTHER_PROCESS_NOISE = """\
10-13 14:35:15.485  8389  8389 F DEBUG   : Cmdline: /vendor/bin/hw/android.hardware.uwb-service
10-13 14:35:15.485  8389  8389 F DEBUG   : Abort message: 'failed to open the serial device: Os { code: 6 }'
10-13 14:35:15.485  8389  8389 F DEBUG   : backtrace:
10-13 14:35:15.485  8389  8389 F DEBUG   :       #00 pc 000000000005b06d  /apex/com.android.runtime/lib64/bionic/libc.so (abort+189)
"""

JAVA_CRASH = """\
10-13 15:00:00.100  9000  9000 E AndroidRuntime: FATAL EXCEPTION: main
10-13 15:00:00.100  9000  9000 E AndroidRuntime: Process: org.fossify.camera, PID: 9000
10-13 15:00:00.100  9000  9000 E AndroidRuntime: java.lang.NullPointerException: Attempt to invoke virtual method on a null object reference
10-13 15:00:00.100  9000  9000 E AndroidRuntime: \tat org.fossify.camera.MainActivity.onCreate(MainActivity.kt:42)
"""

# 真实案例 A（2026-10-13 org.breezyweather）：**同一毫秒**的四行来自两个不相干的进程。
# 按"同时间前缀圈块"的写法会把 UWB 的 Fatal signal 与 Abort message 全扣到 breezy 头上。
# 教训：归属只看「崩溃标记行自己有没有点名目标进程」，不看邻居说了什么。
SAME_MS_NEIGHBOUR = """\
10-13 15:10:52.349 W/PackageConfigPersister(  687): App-specific configuration not found for packageName: org.breezyweather and userId: 0
10-13 15:10:52.349 E/android.hardware.uwb(24381): uwb_default_hal: panicked at hardware/interfaces/uwb/aidl/default/src/uwb_chip.rs:56:14:
10-13 15:10:52.349 E/android.hardware.uwb(24381): failed to open the serial device: Os { code: 6, kind: Uncategorized, message: "No such device or address" }
10-13 15:10:52.349 F/libc    (24381): Fatal signal 6 (SIGABRT), code -1 (SI_QUEUE) in tid 24381 (android.hardwar), pid 24381 (android.hardwar)
10-13 15:11:43.232 F/DEBUG   (25783): Cmdline: /vendor/bin/hw/android.hardware.uwb-service /dev/uwb0
10-13 15:11:43.232 F/DEBUG   (25783): Abort message: 'failed to open the serial device: Os { code: 6 }'
10-13 15:11:43.232 F/DEBUG   (25783): backtrace:
"""

# 真实案例 B（2026-10-13 org.breezyweather）：SIGSEGV 行在 crash 缓冲里，但完整 tombstone
# 被 UWB 崩溃循环从环形缓冲里挤掉了——只有 signal 行也要如实记录，cause 就写 null。
SIGSEGV_NO_TOMBSTONE = """\
10-13 15:11:38.975 F/libc    (23924): Fatal signal 11 (SIGSEGV), code 1 (SEGV_MAPERR), fault addr 0x7978a6004000 in tid 23924 (g.breezyweather), pid 23924 (g.breezyweather)
10-13 15:11:42.504 F/libc    (25771): Fatal signal 6 (SIGABRT), code -1 (SI_QUEUE) in tid 25771 (android.hardwar), pid 25771 (android.hardwar)
"""


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
        """
        r = parse_app_death(SIGSEGV_NO_TOMBSTONE, "org.breezyweather")
        self.assertEqual(len(r["fatal_lines"]), 1)
        self.assertIn("SIGSEGV", r["fatal_lines"][0])
        self.assertIn("g.breezyweather", r["fatal_lines"][0])
        self.assertIsNone(r["cause"])

    def test_tail15_name_form_matches(self):
        """keepass 形态：com.kunzisoft.keepass.libre → t.keepass.libre（尾 15 字符）。"""
        frag = ("10-13 14:59:50.375 F/libc    (16323): Fatal signal 11 (SIGSEGV), code 1"
                " (SEGV_MAPERR), fault addr 0x0 in tid 16323 (t.keepass.libre),"
                " pid 16323 (t.keepass.libre)\n")
        r = parse_app_death(frag, "com.kunzisoft.keepass.libre")
        self.assertEqual(len(r["fatal_lines"]), 1)
        self.assertIn("SIGSEGV", r["fatal_lines"][0])


if __name__ == "__main__":
    unittest.main()
