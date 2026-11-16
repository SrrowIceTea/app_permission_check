#!/usr/bin/env python3
"""按 JSON 脚本操作界面，把"应用内配置"变成可复现的一步。

为什么需要（2026-11-15 gpsdRelay 实测）：样本的业务前提是"在应用里加一条服务器、
把开关打开"，而这类操作原本只能写进报告——`input tap 1345 633` 换个分辨率就失效，
下一个人照着文字复现不了。

用法：
    ui_script.py --serial emulator-5554 --script cfg.json --log actions.jsonl

脚本是一串步骤，每个步骤一个动作：
    {"action": "wait_text", "text": "gpsdRelay", "timeout_s": 20}
    {"action": "tap_text",  "text": "SEE ALL SENSORS READING"}
    {"action": "tap_xy",    "x": 1345, "y": 633}
    {"action": "input_text", "text": "0.0.0.0", "clear": true}
    {"action": "key",       "keycode": "KEYCODE_BACK"}
    {"action": "sleep",     "seconds": 2}
    {"action": "assert_text", "text": "T:0.0.0.0:18960"}
    {"action": "screencap", "out": "step-3.png"}

设计取舍：
- **按文本定位优先**：`tap_text` 从 `uiautomator dump` 里找节点坐标，分辨率无关；
  只有在没有文本节点（Compose 图标按钮）时才退回 `tap_xy`，并把坐标写进脚本说明。
- **不猜**：找不到就失败退出（非零），不"点一个大概位置"。静默点错比报错更贵。
- **可审计**：每个动作写一行到 `--log`（与 `log_action.py` 同 schema），
  所以它产出的记录能直接喂给 `device_run_thirdparty.py --action-log`。
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from pathlib import Path

_ATTR = re.compile(r'(text|content-desc|bounds)="([^"]*)"')
_BOUNDS = re.compile(r"\[(\d+),(\d+)\]\[(\d+),(\d+)\]")


def _adb(serial: str, *args: str, timeout: int = 60) -> str:
    cmd = ["adb"] + (["-s", serial] if serial else []) + list(args)
    try:
        out = subprocess.run(cmd, capture_output=True, text=True,
                             encoding="utf-8", errors="replace", timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError(f"adb 失败：{type(exc).__name__}: {exc}") from exc
    return out.stdout or ""


def dump_nodes(serial: str) -> list[dict]:
    """取当前界面节点（text/content-desc/bounds）。坏 XML 直接返回空表，由调用方重试。"""
    remote = "/sdcard/.ui_script.xml"
    _adb(serial, "shell", f"uiautomator dump {remote} >/dev/null 2>&1")
    raw = _adb(serial, "shell", f"cat {remote}")
    if "<hierarchy" not in raw:
        return []
    try:
        root = ET.fromstring(raw[raw.index("<?xml"):] if "<?xml" in raw else raw)
    except ET.ParseError:
        return []
    nodes = []
    for el in root.iter("node"):
        bounds = _BOUNDS.match(el.get("bounds") or "")
        if not bounds:
            continue
        x1, y1, x2, y2 = (int(v) for v in bounds.groups())
        nodes.append({"text": el.get("text") or "", "desc": el.get("content-desc") or "",
                      "cls": el.get("class") or "", "bounds": (x1, y1, x2, y2),
                      "center": ((x1 + x2) // 2, (y1 + y2) // 2)})
    return nodes


def _find(nodes: list[dict], want: str, field: str = "text") -> dict | None:
    for node in nodes:
        if (node.get(field) or "").strip() == want.strip():
            return node
    for node in nodes:                      # 退一步做包含匹配：长标题常带省略号
        if want.strip() and want.strip() in (node.get(field) or ""):
            return node
    return None


def _log(path: Path | None, record: dict) -> None:
    if path is None:
        return
    record = {"ts_ms": int(time.time() * 1000),
              "ts_iso": time.strftime("%Y-%m-%dT%H:%M:%S%z"), **record}
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, ensure_ascii=False) + "\n")


def run_step(serial: str, step: dict, log: Path | None, outdir: Path,
             timeout_s: float = 20.0) -> str:
    action = step.get("action")
    if action == "sleep":
        time.sleep(float(step.get("seconds", 1)))
        return f"sleep {step.get('seconds', 1)}s"
    if action == "wait_text":
        want, deadline = step.get("text", ""), time.time() + float(step.get("timeout_s", timeout_s))
        while time.time() < deadline:
            node = _find(dump_nodes(serial), want)
            if node:
                return f"wait_text ok: {want!r}"
            time.sleep(1.0)
        raise RuntimeError(f"wait_text 超时：{want!r} 未出现")
    if action in ("tap_text", "tap_desc", "assert_text"):
        field = "desc" if action == "tap_desc" else "text"
        node = _find(dump_nodes(serial), step.get("text", ""), field)
        if action == "assert_text":
            if not node:
                raise RuntimeError(f"assert_text 失败：未找到 {step.get('text')!r}")
            return f"assert_text ok: {step.get('text')!r}"
        if not node:
            raise RuntimeError(f"{action} 失败：未找到 {step.get('text')!r}")
        x, y = node["center"]
        _adb(serial, "shell", f"input tap {x} {y}")
        return f"{action} {step.get('text')!r} @({x},{y})"
    if action == "tap_xy":
        x, y = int(step["x"]), int(step["y"])
        _adb(serial, "shell", f"input tap {x} {y}")
        return f"tap_xy ({x},{y})"
    if action == "input_text":
        if step.get("clear"):
            _adb(serial, "shell", "input keyevent KEYCODE_MOVE_END")
            for _ in range(int(step.get("clear_keys", 24))):
                _adb(serial, "shell", "input keyevent KEYCODE_DEL")
        _adb(serial, "shell", f"input text {json.dumps(str(step.get('text', '')))}")
        return f"input_text {step.get('text')!r}"
    if action == "key":
        _adb(serial, "shell", f"input keyevent {step.get('keycode', 'KEYCODE_BACK')}")
        return f"key {step.get('keycode', 'KEYCODE_BACK')}"
    if action == "screencap":
        name = step.get("out") or f"step-{int(time.time())}.png"
        dest = outdir / name
        _adb(serial, "shell", f"screencap -p /sdcard/.ui_script.png")
        _adb(serial, "pull", "/sdcard/.ui_script.png", str(dest))
        return f"screencap {dest}"
    raise RuntimeError(f"未知动作：{action!r}")


def main() -> int:
    ap = argparse.ArgumentParser(description="按 JSON 脚本操作界面（可复现的应用内配置）")
    ap.add_argument("--serial", default="")
    ap.add_argument("--script", required=True, help="步骤 JSON")
    ap.add_argument("--log", default=None, help="动作登记 JSONL（可直接给 --action-log）")
    ap.add_argument("--outdir", default=None, help="screencap 输出目录（默认脚本同级）")
    ap.add_argument("--timeout", type=float, default=20.0)
    args = ap.parse_args()

    script_path = Path(args.script).resolve()
    spec = json.loads(script_path.read_text(encoding="utf-8"))
    steps = spec.get("steps") or []
    outdir = Path(args.outdir) if args.outdir else script_path.parent
    outdir.mkdir(parents=True, exist_ok=True)
    log = Path(args.log) if args.log else None
    name = spec.get("name") or script_path.stem

    for index, step in enumerate(steps, 1):
        try:
            detail = run_step(args.serial, step, log, outdir, args.timeout)
        except RuntimeError as exc:
            _log(log, {"action": f"ui_script:{name}:fail@{index}",
                       "detail": f"{step.get('action')}: {exc}", "source": "ui_script"})
            print(f"[fail] 步骤 {index} {step.get('action')}: {exc}", file=sys.stderr)
            return 1
        _log(log, {"action": f"ui_script:{name}:{step.get('action')}",
                   "detail": detail, "source": "ui_script"})
        print(f"[{index}/{len(steps)}] {detail}", flush=True)
    print(f"[ok] {len(steps)} 步完成：{name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
