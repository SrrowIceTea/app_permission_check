#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""app 死亡取证回归的测试数据（从 test_app_death.py 拆出，保持逐字抄录）。

非 test_ 前缀，不会被 unittest discover 当成测试模块。
数据不是编的，全部来自 2026-10-13 设备 crash 缓冲的逐字抄录（含义见
test_app_death.py 的模块 docstring 与各用例注释）。
"""

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

# 真实案例 C（2026-10-19 com.vscanner.privacydemo，夹具自检）：**JIT 线程** SIGSEGV。
# 崩在 Jit thread pool 上、SEGV_ACCERR、fault addr 页对齐——插桩（ArtMethod 入口替换）
# 与 JIT 编译线程竞态的原形态（A1 残留）。墓碑里没有 Abort message，但有 uptime。
JIT_SEGV_20261019 = """\
10-19 10:38:50.785 F/libc    ( 9364): Fatal signal 11 (SIGSEGV), code 2 (SEGV_ACCERR), fault addr 0x71bcb9a08000 in tid 9383 (Jit thread pool), pid 9364 (ner.privacydemo)
10-19 10:38:52.100 F/DEBUG   ( 9401): *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** ***
10-19 10:38:52.100 F/DEBUG   ( 9401): Build fingerprint: 'google/sdk_gphone16k_x86_64/emu64xa16k:17/CP41.260831.007/16416850:userdebug/dev-keys'
10-19 10:38:52.100 F/DEBUG   ( 9401): Timestamp: 2026-10-19 10:38:50.785000000+0000
10-19 10:38:52.100 F/DEBUG   ( 9401): Process uptime: 16s
10-19 10:38:52.100 F/DEBUG   ( 9401): Cmdline: com.vscanner.privacydemo
10-19 10:38:52.100 F/DEBUG   ( 9401): pid: 9364, ppid: 1, tid: 9383, name: Jit thread pool  >>> com.vscanner.privacydemo <<<
10-19 10:38:52.100 F/DEBUG   ( 9401): signal 11 (SIGSEGV), code 2 (SEGV_ACCERR), fault addr 0x71bcb9a08000
"""

# 真实案例 D（2026-10-19 现场产物里的错误归属）：我们的墓碑头已被 UWB 崩溃循环挤掉，
# 日志里紧挨着的上一个 `*** *** ***` 头属于 UWB。旧写法（锚 Cmdline → 向前找最近的头
# → 向后扫）会把 UWB 的 Abort message 写成夹具的死因。
NEIGHBOUR_HEADER_THEN_OUR_CMDLINE = """\
10-19 10:38:50.785 F/libc    ( 9364): Fatal signal 11 (SIGSEGV), code 2 (SEGV_ACCERR), fault addr 0x71bcb9a08000 in tid 9383 (Jit thread pool), pid 9364 (ner.privacydemo)
10-19 10:38:52.000 F/DEBUG   ( 9401): *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** ***
10-19 10:38:52.000 F/DEBUG   ( 9401): Cmdline: /vendor/bin/hw/android.hardware.uwb-service /dev/uwb0
10-19 10:38:52.000 F/DEBUG   ( 9401): Abort message: 'failed to open the serial device: Os { code: 6 }'
10-19 10:38:52.100 F/DEBUG   ( 9501): Cmdline: com.vscanner.privacydemo
10-19 10:38:52.100 F/DEBUG   ( 9501): pid: 9364, ppid: 1, tid: 9383, name: Jit thread pool  >>> com.vscanner.privacydemo <<<
"""

# 真实案例 E（2026-10-19 冒烟）：同一个包名在一个 crash 缓冲里躺着**两轮**崩溃。
# 不做 pid 过滤时，段 0（被 force-stop）会把上一轮的 SIGSEGV/uptime 29s 报成自己的死因。
TWO_RUNS_SAME_PACKAGE = """\
10-19 11:16:37.304 F/libc    (13837): Fatal signal 11 (SIGSEGV), code 2 (SEGV_ACCERR), fault addr 0x71bcb999c000 in tid 13845 (Jit thread pool), pid 13837 (ner.privacydemo)
10-19 11:16:37.878 F/DEBUG   (13870): *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** ***
10-19 11:16:37.878 F/DEBUG   (13870): Timestamp: 2026-10-19 11:16:37.878842600+0000
10-19 11:16:37.878 F/DEBUG   (13870): Process uptime: 29s
10-19 11:16:37.878 F/DEBUG   (13870): Cmdline: com.vscanner.privacydemo
10-19 11:16:37.878 F/DEBUG   (13870): pid: 13837, ppid: 473, tid: 13845, name: Jit thread pool  >>> com.vscanner.privacydemo <<<
10-19 11:22:30.299 F/libc    (21131): Fatal signal 6 (SIGABRT), code -1 (SI_QUEUE) in tid 21166 (RenderThread), pid 21131 (ner.privacydemo)
10-19 11:22:30.869 F/DEBUG   (21160): *** *** *** *** *** *** *** *** *** *** *** *** *** *** *** ***
10-19 11:22:30.869 F/DEBUG   (21160): Timestamp: 2026-10-19 11:22:30.869380200+0000
10-19 11:22:30.869 F/DEBUG   (21160): Process uptime: 27s
10-19 11:22:30.869 F/DEBUG   (21160): Cmdline: com.vscanner.privacydemo
10-19 11:22:30.869 F/DEBUG   (21160): pid: 21131, ppid: 473, tid: 21166, name: RenderThread  >>> com.vscanner.privacydemo <<<
10-19 11:22:30.869 F/DEBUG   (21160): Abort message: 'thread is making JNI calls without being attached'
"""

# 2026-10-19 审计构造的两个"串味"输入：Java 崩溃路径原先零过滤。
JAVA_TWO_RUNS = """\
10-13 15:00:00.100  9000  9000 E AndroidRuntime: FATAL EXCEPTION: main
10-13 15:00:00.100  9000  9000 E AndroidRuntime: Process: com.foo, PID: 9000
10-13 15:00:00.100  9000  9000 E AndroidRuntime: java.lang.IllegalStateException: 上一轮的死
10-13 16:00:00.100  7301  7301 E AndroidRuntime: FATAL EXCEPTION: main
10-13 16:00:00.100  7301  7301 E AndroidRuntime: Process: com.foo, PID: 7301
10-13 16:00:00.100  7301  7301 E AndroidRuntime: java.lang.NullPointerException: 这一轮的死
"""

# 包名前缀碰撞：目标包 com.foo，日志里是 com.foobar（Java 与 native 各一条）
PREFIX_COLLISION = """\
10-13 15:00:00.100  8888  8888 E AndroidRuntime: FATAL EXCEPTION: main
10-13 15:00:00.100  8888  8888 E AndroidRuntime: Process: com.foobar, PID: 8888
10-13 15:00:00.100  8888  8888 E AndroidRuntime: java.lang.RuntimeException: 别人的
10-13 15:00:01.100  8889  8889 F/libc    (8889): Fatal signal 11 (SIGSEGV), code 1 (SEGV_MAPERR), fault addr 0x10 in tid 8889 (com.foobar), pid 8889 (com.foobar)
"""