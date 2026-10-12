#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""V-Scanner Phase 2 — 触发靶子 App 的单个行为按钮。

仅用于授权测试（自有设备与自有 APK）/ For authorized testing on owned devices and APKs only.

**为什么要有这个脚本**：Phase 3/4/5 的每一次端到端复现都要"让 App 做一件事"。
手工点击不可复现；而把坐标写死在 `input tap` 里，一旦分辨率或布局变了就会
**静默点空**——按钮没被触发，抓包和钩子里什么都没有，看起来像"钩子没抓到"，
排查方向会整个跑偏。所以这里每次都用 uiautomator dump 现读按钮的真实 bounds，
点击后**回读界面**确认，并把 App 自己的日志尾巴打出来。

    python trigger.py --package com.vscanner.targetapp --button btnEgressHttp
"""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
import time
import xml.etree.ElementTree as ET

REMOTE_XML = "/data/local/tmp/vscan_ui.xml"
BOUNDS = re.compile(r"\[(\d+),(\d+)]\[(\d+),(\d+)]")
TAG = "VSCTarget"

# 三个行为按钮，与审计规则一一对应。值是该按钮处理函数写的**第一行** logcat——
# 用它判定"按钮确实被按到了"，比比对界面文本可靠得多。
BUTTONS = {
    "btnOkHttp": "用户按下 OkHttp 按钮",
    "btnSubscribe": "用户按下订阅按钮",
    "btnPerm": "== 行为 1 开始：索权演示 ==",
    "btnRead": "用户按下按钮 2（读取 VHAL）",
    "btnEgressHttp": "用户按下外泄按钮，端点=",
    "btnEgressHttps": "用户按下外泄按钮，端点=",
    "btnCipher": "用户按下自绘加密外泄按钮",
}


def adb(*args: str, timeout: int = 60) -> tuple[str, str, int]:
    """所有调用都强制 UTF-8：uiautomator 的 XML 是 UTF-8，
    而 Windows 上 text=True 会按 GBK 解，中文界面文本会糊掉甚至抛 UnicodeDecodeError。"""
    proc = subprocess.run(["adb", *args], capture_output=True, encoding="utf-8",
                          errors="replace", timeout=timeout)
    return proc.stdout or "", proc.stderr or "", proc.returncode


def dump_ui(retries: int = 4) -> str:
    last = ""
    for _ in range(retries):
        out, err, _ = adb("shell", f"uiautomator dump {REMOTE_XML}")
        last = (out + err).strip()
        if "dumped to" in out:
            xml, _, _ = adb("shell", "cat", REMOTE_XML)
            if xml.lstrip().startswith("<?xml"):
                return xml
        # "Could not get idle state" 在界面刚起来时很常见，重试即可。
        time.sleep(1.0)
    raise SystemExit(f"uiautomator dump 连续 {retries} 次失败，最后一次输出：{last}")


def node_by_id(xml: str, resource_id: str):
    for node in ET.fromstring(xml).iter("node"):
        if node.get("resource-id") == resource_id:
            return node
    return None


def center_of(node) -> tuple[int, int]:
    match = BOUNDS.search(node.get("bounds") or "")
    if not match:
        raise SystemExit(f"节点 {node.get('resource-id')} 没有可解析的 bounds："
                         f"{node.get('bounds')!r}")
    x1, y1, x2, y2 = (int(v) for v in match.groups())
    return (x1 + x2) // 2, (y1 + y2) // 2


def logcat_since_clear() -> list[str]:
    """读 App 自己的 logcat。

    **判定按钮有没有被按到，要看 logcat 而不是界面文本**：界面上的 log 面板是个
    TextView，uiautomator 报出来的内容随可见区域变化，一次点击后"看起来没变"
    并不能说明按钮没触发——我最初就是这么误判的（实际 App 已经发出去了）。
    logcat 是 App 每一行都主动写的，权威且不受渲染影响。
    """
    out, _, _ = adb("logcat", "-d", "-s", TAG)
    return [ln for ln in out.splitlines() if TAG in ln]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--package", required=True)
    parser.add_argument("--button", required=True, choices=BUTTONS)
    parser.add_argument("--expect-endpoint", default="http://10.0.2.2:8888/collect",
                        help="外泄按钮的端点应当是什么；不符会告警（App 会发到别处）")
    parser.add_argument("--settle", type=float, default=1.5, help="启动后等待界面稳定的秒数")
    parser.add_argument("--after", type=float, default=2.0, help="点击后等待回读的秒数")
    args = parser.parse_args()

    out, _, _ = adb("shell", f"pidof {args.package}")
    if not out.strip():
        print(f"[trigger] {args.package} 不在运行，先启动")
    adb("shell", "am", "start", "--user", "10", "-W", "-n", f"{args.package}/.MainActivity")
    time.sleep(args.settle)

    xml = dump_ui()
    if args.button.startswith("btnEgress") or args.button == "btnOkHttp":
        field = node_by_id(xml, f"{args.package}:id/" + ("etHttpsEndpoint" if args.button in ("btnEgressHttps", "btnOkHttp") else "etHttpEndpoint"))
        endpoint = (field.get("text") or "") if field is not None else ""
        if endpoint and endpoint != args.expect_endpoint:
            # 这是会**静默改变结论**的情况：App 照常发，只是发去了别处，
            # 抓包侧一条流都看不到，却没有任何报错。
            print(f"[trigger] !! 端点不是预期值：界面={endpoint!r} 预期={args.expect_endpoint!r}\n"
                  f"[trigger] !! 靶子会把报文发到别处，抓包侧将一条流都看不到。",
                  file=sys.stderr)

    node = node_by_id(xml, f"{args.package}:id/{args.button}")
    scroll = node_by_id(xml, f"{args.package}:id/scrollContent")
    if node is None and scroll is not None:
        bounds = BOUNDS.search(scroll.get('bounds', ''))
        if bounds:
            x1, y1, x2, y2 = map(int, bounds.groups())
            x = (x1 + x2) // 2
            for _ in range(3):
                adb('shell', 'input', 'swipe', str(x), str(y1 + 30), str(x), str(y2 - 30), '250')
            xml = dump_ui()
            node = node_by_id(xml, f"{args.package}:id/{args.button}")
    # 横屏车机的内容高度有限；按真实滚动区域向下找，禁止硬编码按钮坐标。
    for _ in range(6):
        if node is not None:
            break
        scroll = node_by_id(xml, f"{args.package}:id/scrollContent")
        if scroll is None:
            break
        bounds = BOUNDS.search(scroll.get('bounds', ''))
        if not bounds:
            break
        x1, y1, x2, y2 = map(int, bounds.groups())
        x = (x1 + x2) // 2
        adb('shell', 'input', 'swipe', str(x), str(y2 - 30), str(x), str(y1 + 30), '350')
        xml = dump_ui()
        node = node_by_id(xml, f"{args.package}:id/{args.button}")
    if node is None:
        raise SystemExit(f"界面上找不到 {args.button}。当前可见的 id："
                         + ", ".join(sorted({n.get('resource-id', '')
                                             for n in ET.fromstring(xml).iter('node')
                                             if n.get('resource-id', '').startswith(args.package)})))
    x, y = center_of(node)

    adb("logcat", "-c")  # 清空，这样下面的日志必然出自本次点击
    adb("shell", "input", "tap", str(x), str(y))
    print(f"[trigger] tap {args.button} @ ({x},{y})  pkg={args.package}")
    time.sleep(args.after)

    lines = logcat_since_clear()
    marker = BUTTONS[args.button]
    for line in lines:
        # logcat 行形如 "09-23 14:15:55.149 30304 30304 I VSCTarget: <msg>"
        print("    " + line.split(f"{TAG}: ", 1)[-1])
    if not any(marker in ln for ln in lines):
        # 没有那行 = 处理函数压根没跑（点空了 / 点在别的窗口上 / 按钮被遮挡）。
        print(f"[trigger] !! 点击后未见 {marker!r} —— 按钮没有被触发。", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
