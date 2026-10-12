#!/usr/bin/env python3
"""移动版 mitmproxy 入口 —— 复用 phase4/addon.py，只把敏感打标表换成移动版。

仅用于授权测试（已获授权的样本与设备）。只抓取、只标注、不改写任何报文。

为什么不复制一份 addon：phase4/addon.py 是纯 HTTP 逻辑（反向代理、挂起重试式归因、
宽限期、失败流单独落盘、白名单门），与车载无关，且它的每个坑都有实测决策记录。
复制会立刻产生两份会漂移的实现。这里只做**一处**替换：

    sys.modules["tagging"] = tagging_mobile      # 必须在 import addon 之前

addon.py 第 37 行是 `from tagging import scan_body, tag_sensitive`，
先占住 sys.modules 里的 "tagging" 键，这条 import 就解析到移动版。

跑法（环境变量必须显式给全，缺一项的后果见 phase4 文档：归因失败与"今天没流量"
长得一模一样）：
    VSCAN_FLOW_LOG=<会话目录>/flows.jsonl
    VSCAN_ATTRIB_SOURCES=<会话目录>/egress.jsonl
    VSCAN_PACKAGES=com.vscanner.privacydemo
    VSCAN_SESSION=<会话>
    mitmdump -s mobile/traffic/addon_mobile.py --mode reverse:http://127.0.0.1:8080 \
             --listen-host 0.0.0.0 --listen-port 8888
"""
from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
PHASE4 = ROOT / "phase4"

if not (PHASE4 / "addon.py").exists():
    raise SystemExit(f"[fatal] 找不到 {PHASE4 / 'addon.py'}；移动版流量层复用它，不能单独运行。")

sys.path.insert(0, str(HERE))
sys.path.insert(0, str(PHASE4))

import tagging_mobile  # noqa: E402

sys.modules["tagging"] = tagging_mobile

import addon  # noqa: E402

# mitmproxy 在脚本模块的命名空间里找钩子；显式再导出，避免"脚本加载了但一个钩子都没注册"。
load = addon.load
request = addon.request
response = addon.response
error = addon.error
done = addon.done
