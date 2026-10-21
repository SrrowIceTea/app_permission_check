#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""i2 验证用：以独立 frida 会话加载纯触发 bundle（零替换零 attach，见 fixture_trigger.js）。

为什么独立成工具：validate_native_migration.py 的宿主解释器未必装了 frida（实测
`python` 裸解释器无 frida 模块），而 frida 注入必须用装了 frida 的解释器跑
（thirdparty_env.frida_python 负责探测）。本工具由验证器以该解释器子进程方式调用。

用法：
    python inject_triggers.py --pid PID --bundle path/fixture_trigger.bundle.js --log out.log
退出码：0=日志中出现 DONE；1=attach/加载失败或超时未见 DONE。
"""
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--pid", required=True, type=int)
    ap.add_argument("--bundle", required=True)
    ap.add_argument("--log", required=True)
    ap.add_argument("--host", default="127.0.0.1:27043")
    ap.add_argument("--wait", type=int, default=20)
    args = ap.parse_args()

    lines: list[str] = []
    bundle = Path(args.bundle)
    if not bundle.exists():
        lines.append("[inject] bundle 不存在: " + str(bundle))
        Path(args.log).write_text("\n".join(lines) + "\n", encoding="utf-8")
        return 1

    try:
        import frida  # 宿主 frida 与 server 同版（env.ensure_frida_server 已校验）
    except ImportError as e:
        lines.append(f"[inject] frida 不可用: {e}")
        Path(args.log).write_text("\n".join(lines) + "\n", encoding="utf-8")
        return 1

    text = bundle.read_text(encoding="utf-8")
    try:
        dev = frida.get_device_manager().add_remote_device(args.host)
        sess = dev.attach(args.pid)
    except Exception as e:
        lines.append(f"[inject] attach 失败: {e}")
        Path(args.log).write_text("\n".join(lines) + "\n", encoding="utf-8")
        return 1

    done = {"flag": False}

    def on_msg(m, _data):
        if m.get("type") == "log":
            lines.append("[inject] " + (m.get("payload") or ""))
        elif m.get("type") == "error":
            lines.append("[inject:error] " + str(m.get("description"))[:200])
        elif m.get("type") == "send":
            lines.append("[inject] " + str(m.get("payload"))[:200])

    try:
        script = sess.create_script(text)
        script.on("message", on_msg)
        script.load()
        deadline = time.monotonic() + args.wait
        while time.monotonic() < deadline and not done["flag"]:
            if any("DONE" in x for x in lines):
                done["flag"] = True
                break
            time.sleep(0.5)
        time.sleep(2)   # 让事件回传落盘
    except Exception as e:
        lines.append(f"[inject] load 失败: {e}")
    try:
        sess.detach()
    except Exception:
        pass
    Path(args.log).write_text("\n".join(lines) + "\n", encoding="utf-8")
    return 0 if done["flag"] else 1


if __name__ == "__main__":
    sys.exit(main())