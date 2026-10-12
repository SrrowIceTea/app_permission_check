#!/usr/bin/env python3
"""移动版 mitmproxy 入口 —— 复用 core/collector/addon.py，只把敏感打标表换成移动版。

仅用于授权测试（已获授权的样本与设备）。只抓取、只标注、不改写任何报文。

为什么不复制一份 addon：core/collector/addon.py 是纯 HTTP 逻辑（反向代理、挂起重试式
归因、宽限期、失败流单独落盘、白名单门），与平台无关，且它的每个坑都有实测决策记录。
复制会立刻产生两份会漂移的实现。

打标表由 `core/collector/addon.py` 通过 `VSCAN_TAGGING` 环境变量按路径加载。
本文件只做两件事：把默认值指到移动版那张表（`mobile/traffic/tagging_mobile.py`），
再把 mitmproxy 需要的钩子原样转发出去。想抓车载流量就显式设
`VSCAN_TAGGING=vehicle/traffic/tagging.py` 并直接 `-s core/collector/addon.py`。

跑法（环境变量必须显式给全，缺一项的后果见 vehicle/traffic 文档：归因失败与"今天没流量"
长得一模一样）：
    VSCAN_FLOW_LOG=<会话目录>/flows.jsonl
    VSCAN_ATTRIB_SOURCES=<会话目录>/egress.jsonl
    VSCAN_PACKAGES=com.vscanner.privacydemo
    VSCAN_SESSION=<会话>
    mitmdump -s mobile/traffic/addon_mobile.py --mode reverse:http://127.0.0.1:8080 \
             --listen-host 0.0.0.0 --listen-port 8888
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

# 打标表默认指向移动版；已显式设过（比如想抓车载流量）就不覆盖。
os.environ.setdefault("VSCAN_TAGGING", str(ROOT / "mobile/traffic/tagging_mobile.py"))

from core.collector import addon  # noqa: E402

# mitmproxy 在脚本模块的命名空间里找钩子；显式再导出，避免"脚本加载了但一个钩子都没注册"。
load = addon.load
request = addon.request
response = addon.response
error = addon.error
done = addon.done
