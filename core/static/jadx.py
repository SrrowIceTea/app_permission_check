#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Phase 7 — 驱动 jadx 做全量反编译，并把进度与**部分失败**如实带出来。

仅用于授权测试（自有设备与自有 APK）/ For authorized testing on owned devices and APKs only.

**为什么是全量而不是"点一下反编译一个类"**：实测 `--single-class` 单次 **14.1 秒**——
每次都要重新装载整个 APK 并建索引，所以逐类按需反编译在交互上不可用。
全量一次 3.6MB 夹具是 **28 秒**，之后浏览走磁盘上的现成文件，点开是毫秒级。

**部分失败必须被看见**：jadx 对夹具报 `finished with errors, count: 5`。这类失败很正常
（个别类解不出），但**不能让用户以为看全了**——所以计数写进结果、由前端显式展示。
"没反编译出来"与"这个类不存在"是两回事。
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

# 同目录下的构建工具链模块：仓库根入 sys.path，便于既被 `core.static.jadx`（服务端）
# 也被顶层 `import jadx`（离线回归）两种方式加载。
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from core.static import winpath  # noqa: E402

PROGRESS_RE = re.compile(r"progress: (?P<done>\d+) of (?P<total>\d+)")
ERRORS_RE = re.compile(r"finished with errors, count: (?P<count>\d+)")


def command(jar, java: str, apk: Path, out: Path, *, threads: int = 4,
            no_res: bool = True) -> list[str]:
    """拼 jadx 命令行。`--no-res` 只看代码；资源解析对静态分析没有增量，却明显更慢。"""
    args = [java, "-cp", str(jar), "jadx.cli.JadxCLI", "--threads-count", str(threads)]
    if no_res:
        args.append("--no-res")
    return args + ["-d", str(out), str(apk)]


def run(jar, java: str, apk: Path, out: Path, *, threads: int = 4,
        on_progress=None, is_cancelled=None, timeout_s: float = 1800) -> dict:
    """跑一次全量反编译，流式汇报进度。

    返回 `{"returncode", "errors", "classes_written", "cancelled", "log_tail"}`。
    **返回码非 0 不直接当失败**：jadx 在"部分类失败"时也可能给非 0，
    真正的判据是产物有没有生成 + `errors` 计数，两者都要报出来。
    """
    out.mkdir(parents=True, exist_ok=True)
    proc = subprocess.Popen(command(jar, java, apk, out, threads=threads),
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            encoding="utf-8", errors="replace")
    seen = 0
    errors = 0
    tail: list[str] = []
    cancelled = False
    try:
        for line in proc.stdout:
            line = line.rstrip("\r\n")
            if line.strip():
                tail = (tail + [line])[-40:]      # 只留尾巴：完整日志可能有几万行
            progress = PROGRESS_RE.search(line)
            if progress:
                seen = int(progress.group("done"))
                if on_progress:
                    on_progress(seen, int(progress.group("total")))
            found = ERRORS_RE.search(line)
            if found:
                errors = int(found.group("count"))
            if is_cancelled and is_cancelled():
                cancelled = True
                proc.terminate()
                break
    finally:
        proc.stdout.close()
        try:
            code = proc.wait(timeout=timeout_s)
        except subprocess.TimeoutExpired:
            proc.kill()
            code = -9
    sources = out / "sources"
    written = sum(1 for _ in sources.rglob("*.java")) if sources.is_dir() else 0
    return {"returncode": code, "errors": errors, "classes_written": written,
            "cancelled": cancelled, "log_tail": tail}


def source_tree(root: Path) -> list[dict]:
    """把 `sources/` 下的 .java 列成前端要的树（路径 + 大小）。

    只列路径与大小，**不读内容**——大 APK 有上万文件、几百 MB，
    一次读进内存会把浏览器和服务端一起拖死。
    """
    sources = root / "sources"
    if not sources.is_dir():
        return []
    entries = []
    for path in sorted(sources.rglob("*.java")):
        # stat 走 winpath：深包名的类文件绝对路径会超过 Windows 的 260，
        # 直接 stat 会抛 WinError 3（详见 winpath 模块头）。rglob 本身不受影响。
        entries.append({"path": path.relative_to(sources).as_posix(),
                        "size": winpath.size(path)})
    return entries


def index_json(root: Path) -> Path:
    return root / "phase7-tree.json"


def write_tree(root: Path) -> list[dict]:
    tree = source_tree(root)
    index_json(root).write_text(json.dumps(tree, ensure_ascii=False), encoding="utf-8")
    return tree


def read_source(root: Path, relative: str, max_bytes: int = 512 * 1024) -> dict:
    """读一个源文件。**路径必须限制在 sources/ 之内**——否则 `../` 能读到整个磁盘。"""
    sources = (root / "sources").resolve()
    target = (sources / relative).resolve()
    if not target.is_relative_to(sources):
        raise ValueError(f"路径越界：{relative}")
    # 越界判断用普通 Path（词法比较即可），真正的 IO 走 winpath 以扛住长路径。
    if not winpath.is_file(target):
        raise FileNotFoundError(relative)
    raw = winpath.read_bytes(target)
    truncated = len(raw) > max_bytes
    return {"path": relative, "size": len(raw), "truncated": truncated,
            "text": raw[:max_bytes].decode("utf-8", errors="replace")}
