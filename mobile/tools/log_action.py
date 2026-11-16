#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""登记一条业务动作（受控窗口用）。仅用于授权测试。

为什么单独一个入口：`device_run_thirdparty --max-rounds 0` 的窗口里动作是**外部注入**的
（adb / 人工点击），自动点击数为 0。旧判据 `ui_taps_made` 因此恒判失败，跑一次红一次
（2026-11-15 实测三连红）。现在用 `--action-log` 指向本工具写的 JSONL，判据变成
"窗口内登记了几条动作"。

用法（在业务动作**之后**立刻执行，时间戳才落得进窗口）：

    python mobile/tools/log_action.py --log <out>/actions.jsonl \
        --action open_url --detail "http://10.18.80.25:18900/pilot/pilot-b1"

`ts_ms` 用毫秒 epoch，与 `coverage.json` 的窗口边界同一时钟（都是宿主 wall clock）。
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import time
from pathlib import Path


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--log", required=True, help="动作登记 JSONL（不存在则创建）")
    ap.add_argument("--action", required=True, help="动作名，如 open_url / tap_login / send_msg")
    ap.add_argument("--detail", default="", help="动作细节：URL、控件、输入值摘要等")
    ap.add_argument("--source", default="manual", help="来源：manual / adb / script")
    args = ap.parse_args()

    path = Path(args.log)
    path.parent.mkdir(parents=True, exist_ok=True)
    now_ms = int(time.time() * 1000)
    row = {
        "ts_ms": now_ms,
        "ts_iso": dt.datetime.now().astimezone().isoformat(timespec="milliseconds"),
        "action": args.action,
        "detail": args.detail,
        "source": args.source,
    }
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(row, ensure_ascii=False) + "\n")
        fh.flush()
    print(json.dumps(row, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
