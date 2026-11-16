#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""第三方 APK 设备端链路的环境层：adb / frida-server / wifi / 代理 / mitm / 钩子进程。
仅用于授权测试（自有设备 / 已授权的公开第三方样本）。

这里是 `device_run_thirdparty.py` 的下半身；与夹具版 `mobile/tools/device_run.py`
的差异：包名 / APK / 入口 Activity 参数化、frida-server 自动推送、mitmproxy 走常规
代理模式（夹具版走 reverse）。其余已验证的坑位处理（root、端口 27043、wifi/路由、
代理残留、冷启动竞争）**照搬**。`device_run.py` 一行不改。

P2 拆分（2026-10-21，AGENTS.md 单文件 ≤300 行）：实现迁往五个子模块——
  thirdparty_env_adb.py      常量 / adb 封装 / wifi / 代理 / QUIC 压制
  thirdparty_env_process.py  进程树回收 / 端口占用 / 残留 mitmproxy 识别
  thirdparty_env_hook.py     mitmproxy 启动 / frida 解释器 / hook 子进程启停
  thirdparty_env_parse.py    日志/墓碑行解析工具与设备时钟偏移
  thirdparty_env_death.py    `parse_app_death`（纯函数死因解析）
  thirdparty_env_device.py   进程存活 / 墓碑兜底 / 死因取证 / Activity 解析
本文件仅 re-export，外部 `import thirdparty_env as ...` 引用面零改动。
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))   # 保证子模块可被同目录直导

from thirdparty_env_adb import (  # noqa: E402,F401
    ROOT, MOBILE, PY, ADB, FRIDA_PORT, MITM_PORT, GUEST_HOST,
    adb, device_guard, run, wait_boot, wait_for_app, ensure_frida_server,
    PROBE_TARGETS, ensure_wifi, get_proxy, set_proxy, QUIC_RULE, block_quic,
    unblock_quic, current_user_id, app_uid,
)
from thirdparty_env_process import (  # noqa: E402,F401
    kill_tree, kill_pid_tree, _representative_death, orchestrator_notes,
    tcp_open, port_owner, STALE_MITM_NAMES, STALE_MITM_CMDLINE, proc_cmdline,
    reclaim_port,
)
from thirdparty_env_hook import (  # noqa: E402,F401
    start_mitm, _FRIDA_PY_CACHE, frida_python, start_hook, stop_hook,
    start_conn_probe,
)
from thirdparty_env_parse import (  # noqa: E402,F401
    _process_name_variants, _tombstone_blocks, _block_cmdline, _block_has_header,
    _first_int, _logcat_epoch_ms, _CLOCK_OFFSET_S, _device_clock_offset_s,
    _tombstone_epoch_ms,
)
from thirdparty_env_death import parse_app_death  # noqa: E402,F401
from thirdparty_env_device import (  # noqa: E402,F401
    pid_alive, _device_tombstone, app_death_reason, parse_resolved_activity,
    device_main_activity,
)
