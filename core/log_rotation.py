#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""有上限的追加日志：超过阈值就分卷，**旧卷只读、绝不删除或覆盖**。

仅用于授权测试（自有设备与已授权的公开第三方样本）。

## 为什么需要它

`output/` 已 37.7 GB / 26 万文件（2026-11-11 盘点），其中跑批日志是纯增量：
`batch_dynamic.run` 的 `run.log`、`supervise_batch` 的 `supervise.log`/`batch.log`/
`emulator.log` 全部 `open("a")` 且无轮转，一个样本一轮、一轮一次重试，永远只涨。
`AGENTS.md`「待办」段又明确禁止按历史条目删 `output/` 里的现存内容，所以只能
**让新增的量有上限**，而不是回头清理。

## 分卷口径（可核查）

- 阈值 `DEFAULT_MAX_BYTES`（20 MB），达到就在**下次打开**时改名成
  `<name>.<YYYYmmdd-HHMMSS>`，然后从空文件继续追加，并在新文件首行写一句
  `# 续卷自 <卷名>`（否则看日志的人会以为这一轮是从头开始的）；
- 同一秒内多次分卷加 `-2`/`-3` 后缀。**卷名用 O_EXCL 先占位再改名**：先 `os.open`
  以 `O_CREAT|O_EXCL` 抢到文件名，再 `os.replace` 覆盖自己刚占的空文件。这样
  "检查存在 → 改名"之间没有竞态窗口，两个进程同时分卷也不会互相顶掉
  （对比过：直接 `os.replace` 在目标同名时是**替换**语义，会静默销毁一份 20 MB 现场）；
- 分卷失败（Windows 上文件被另一个进程持有）不抛异常：删掉自己占位的空文件，
  继续写原文件，并在 stdout 留一行可诊断的提示——日志绝不能因为轮转把跑批打断。

## 已知边界

子进程 stdout 直落的文件（`subprocess.call(stdout=fh)`）在子进程存活期间**无法**
中途改名——Windows 上换名会失败，所以分卷只发生在"下一次打开时"。跨批次、跨样本、
跨模拟器重启的无限追加被这条挡住；单轮内一次跑出 20 MB 以上的情况仍会超阈值，
那属于"这一轮本来就写了这么多"，不做截断（截断会丢现场）。

若守护进程自己的 stdout 被重定向到同一个 `batch.log`（`... > batch.log 2>&1`），那个句柄由
shell 持有且不带 `FILE_SHARE_DELETE`，分卷必然失败——退化为继续追加（不丢字节），但上限失效，
且两个句柄的写偏移会互相覆盖。无人值守启动时请让守护进程只写日志文件，不要把 stdout 指到它。

**`events.jsonl` 禁止接这一层**：`mobile/pipeline/stages.py:read_events` 的 offset 是
"已读行数"，分卷后新文件行数变小会让 SSE 永远返回空（`offset >= len(lines)`），
前端时间线会永久停住。事件流是契约文件，不是日志。
"""
from __future__ import annotations

import os
import time
from pathlib import Path

# 20 MB：实测一个样本的 device_run 输出在 1–4 MB 量级，20 MB 能容纳一次异常
# 重试的完整现场，又不至于让单个文件难以打开。
DEFAULT_MAX_BYTES = 20 * 1024 * 1024
# 同秒分卷的序号上限：只防"目录里堆了几百个同名卷"的病态情况，正常远到不了。
MAX_SERIAL = 1000


def volume_path(path: Path, stamp: str) -> Path:
    """卷名：`run.log` → `run.log.20261111-232900`。保持原名前缀，便于按名字归类。"""
    path = Path(path)
    return path.with_name(f"{path.name}.{stamp}")


def _reserve(target: Path) -> bool:
    """以 O_EXCL 抢注卷名：抢到返回 True。已被别人占用（同秒并发）返回 False。"""
    try:
        handle = os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    except FileExistsError:
        return False
    except OSError as exc:      # 目录只读 / 文件名非法：交给调用方按"分卷失败"处理
        print(f"[log] 无法占用卷名 {target.name}：{exc}", flush=True)
        return False
    os.close(handle)
    return True


def rotate_if_needed(path: Path, *, max_bytes: int = DEFAULT_MAX_BYTES,
                     stamp: str | None = None) -> Path | None:
    """达到阈值就把 `path` 改名成卷；返回卷路径，未分卷/失败返回 None。"""
    path = Path(path)
    try:
        size = path.stat().st_size
    except OSError:
        return None                      # 还没这个文件或 stat 被拒：不轮转，交给随后的 open 暴露
    if size < max(1, max_bytes):
        return None
    base = stamp or time.strftime("%Y%m%d-%H%M%S")
    serial = 1
    while True:
        target = volume_path(path, base if serial == 1 else f"{base}-{serial}")
        if _reserve(target):
            break
        serial += 1
        if serial > MAX_SERIAL:
            print(f"[log] 卷名用尽，继续写原文件：{path.name}", flush=True)
            return None
    try:
        os.replace(path, target)         # 覆盖的是本进程刚 O_EXCL 占下的空文件
    except OSError as exc:
        target.unlink(missing_ok=True)   # 撤销占位，不留空卷误导"已分卷"
        print(f"[log] 分卷失败，继续写原文件：{path.name} -> {target.name}：{exc}", flush=True)
        return None
    return target


def open_capped(path: Path, *, max_bytes: int = DEFAULT_MAX_BYTES,
                encoding: str = "utf-8"):
    """追加方式打开 `path`；打开前按阈值分卷。返回文件对象（配合 `with` 使用）。"""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    rotated = rotate_if_needed(path, max_bytes=max_bytes)
    handle = path.open("a", encoding=encoding)
    if rotated is not None:
        # 首行自描述：只翻到新卷的人能知道上一段在哪，不用去猜时间戳。
        handle.write(f"# 续卷自 {rotated.name}（达到 {max_bytes // (1024 * 1024)} MB 自动分卷）\n")
        handle.flush()
    return handle
