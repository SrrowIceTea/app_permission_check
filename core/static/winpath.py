#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""Windows 长路径（MAX_PATH = 260）兼容层。

仅用于授权测试（自有设备与自有 APK）/ For authorized testing on owned devices and APKs only.

**为什么需要单独一层**：Windows 的 Win32 文件 API 默认把路径限制在 260 字符。jadx 反编译出的
源码树有多深，由**被测 APK 的包名与类名**决定——`android/view/accessibility/` 这种包前缀
加上 `AccessibilityManager$AccessibilityServicesStateChangeListener.java` 这种长类名，
**单是 `sources/` 之后就有 90+ 字符**；再叠上仓库路径与 `.cache/<sha256>/sources/`，
实测本项目里最长一条已经到 **262 字符**（2026-10-12，拆分把 `phase7/` 改名成
`vehicle/workbench/` 之后越过了这条线）。

超限后的症状**极具迷惑性**，值得单独记下来：

* `os.scandir` / `rglob` **仍然成功**——列目录用的是父目录，而父目录没超 260。
  于是"文件树看起来是好的、文件数也对"；
* 但一旦对那个文件 `stat()` / `open()` 就抛
  `FileNotFoundError: [WinError 3] 系统找不到指定的路径`。
  **WinError 3 是"路径找不到"（ERROR_PATH_NOT_FOUND），不是"文件找不到"
  （ERROR_FILE_NOT_FOUND）**——这正是路径被截断的特征，而不是文件真的不存在。

**解法**：在 Windows 上把路径转成扩展长度形式（`\\?\` 前缀；UNC 用 `\\?\UNC\`），
它绕过 260 限制。转换只发生在这层薄封装内，对外仍然传普通 `Path`，
避免 `\\?\` 渗进业务代码、日志与 JSON 输出。非 Windows 平台全部退化为透明转发。

**两个本机特有的坑**（都实测踩过，别再踩）：

1. MSYS2 的 mingw64 Python 是 `os.name == 'nt'` 却 `os.sep == '/'` 的怪胎，
   `os.path.abspath` 会返回 `C:/Users/...` 这种正斜杠路径。而 `\\?\` 扩展形式
   **只认反斜杠**，拿正斜杠拼出来的 `\\?\C:/...` 是非法路径，`os.stat` 会以
   WinError 2 失败——比原来的 WinError 3 还糟（短路径也挂）。所以分隔符必须自己归一。
2. 同样因为这个怪胎，**`shutil.rmtree` 不能用在扩展路径上**：它内部用
   `os.path.join` 拼子路径，拼出来是正斜杠，和前缀里的反斜杠混成 `\\?\D:\a\b/c`，
   Win32 报 WinError 123；更糟的是 `ignore_errors=True` 会把它**静默吞掉**，
   表现为"淘汰执行了、目录还在"。所以这里自己实现 `rmtree`，全程手工用反斜杠拼接。
"""
from __future__ import annotations

import fnmatch
import os
import stat
from pathlib import Path

_EXT_PREFIX = "\\\\?\\"
_UNC_PREFIX = "\\\\?\\UNC\\"

# 拼子路径用的分隔符。**不能用 `os.sep`**：MSYS2 的 mingw64 Python 是 `os.name == 'nt'`
# 却 `os.sep == '/'` 的怪胎，`os.sep` 拼出来是正斜杠，和 `\\?\` 前缀混成 `\\?\D:\a/b`
# → WinError 123（模块头第 2 条坑）。判据与 `extended()` 保持一致：只要 `os.name == 'nt'`，
# 我们给出的就是带前缀的扩展形式，必须用反斜杠。
_SEP = "\\" if os.name == "nt" else "/"


def extended(path) -> str:
    r"""把路径转成 Windows 扩展长度形式；非 Windows 或已是该形式则原样返回。

    分隔符**必须自己归一**，不能指望 `os.path.abspath`：MSYS2 的 mingw64 Python 是
    `os.name == 'nt'` 却 `os.sep == '/'`（实测 2026-10-12），`abspath` 会返回
    `C:/Users/...` 这种正斜杠路径；而 `\\?\` 扩展长度形式**只认反斜杠**。所以先 `abspath`
    （消掉 `.`/`..`、补全盘符），再把 `/` 一律换成 `\`。
    """
    raw = os.fspath(path)
    if isinstance(raw, bytes):
        raw = os.fsdecode(raw)
    if os.name != "nt":
        return raw
    absolute = os.path.abspath(raw).replace("/", "\\")
    if absolute.startswith(_EXT_PREFIX):
        return absolute
    if absolute.startswith("\\\\"):          # UNC：\\server\share → \\?\UNC\server\share
        return _UNC_PREFIX + absolute[2:]
    return _EXT_PREFIX + absolute


def size(path) -> int:
    return os.stat(extended(path)).st_size


def mtime(path) -> float:
    return os.stat(extended(path)).st_mtime


def is_file(path) -> bool:
    return os.path.isfile(extended(path))


def read_bytes(path) -> bytes:
    with open(extended(path), "rb") as handle:
        return handle.read()


def extended_rglob(root, pattern: str = "*") -> list[Path]:
    r"""递归列出 `root` 下匹配 `pattern` 的项，**每一级都走扩展长度路径**。

    **为什么不能直接用 `Path.rglob`**：它内部同样是 `os.scandir`，但遇到**目录自身**
    超过 260 的目录时 `scandir` 直接失败，而 `pathlib` 的递归通配会把 `OSError`
    **静默吞掉**——整棵子树从结果里消失，既不报错也不留痕（`source_tree` 少列、
    `Cache.usage()` 与 LRU 淘汰失准）。这与模块头记的"文件自身超限"是**两个症状**：
    文件超限时列目录用的还是父目录，`rglob` 照样能列到，只有 `stat`/`open` 会抛
    WinError 3；目录超限才会整块丢。

    语义对齐 `Path.rglob(pattern)` 的常用形态：

    * 不含分隔符的 `pattern` 按**文件名**匹配（`fnmatch`，Windows 上大小写不敏感）；
    * 目录**符号链接不递归**（与 Python 3.13 `rglob` 默认 `recurse_symlinks=False`
      一致），但它本身仍是一个可匹配的项；
    * **不含 `root` 自身**；返回顺序不保证（要稳定顺序请自行 `sorted()`）；
    * 返回值是普通 `pathlib.Path`，`\\?\` 不外泄（与 `extended()` 同一条纪律）。

    含分隔符的 `pattern`（如 `"a/*.java"`）**显式报错**：`pathlib` 那套多段通配
    （`**`、尾段锚定、隐式 `**/` 前缀）语义无法在这条手写遍历里精确复刻，
    与其悄悄给出偏差结果，不如让调用方换写法。

    路径不存在、以及遍历中途被删（`FileNotFoundError`）按"没有这一项"处理——
    与 `_is_dir_raw` 同一条口径；其余 `OSError`（权限、共享冲突…）**一律向上传播**，
    不复刻 `rglob` 静默吞树的老毛病（§8.6 第 3 条）。
    """
    # 两种分隔符都拦：写 `a/b.java` 的人以为在匹配相对路径，写 `a\b.java` 的人在
    # Windows 上更可能只是想匹配文件名——不管哪种，这里都给不出他们预期的语义。
    if any(sep in pattern for sep in ("/", "\\")):
        raise ValueError(
            f"extended_rglob 只支持按文件名匹配的单段模式，收到 {pattern!r}；"
            "多段通配（含 `**`）请改用 rglob，或自行按目录逐级调用。")
    base = Path(root)
    found: list[Path] = []
    stack: list[tuple[str, tuple[str, ...]]] = [(extended(base), ())]
    while stack:
        current, parts = stack.pop()
        try:
            with os.scandir(current) as entries:
                items = list(entries)
        except FileNotFoundError:
            continue
        for entry in items:
            child_parts = parts + (entry.name,)
            if fnmatch.fnmatch(entry.name, pattern):
                found.append(base.joinpath(*child_parts))
            if entry.is_dir(follow_symlinks=False):
                stack.append((current + _SEP + entry.name, child_parts))
    return found


def _is_dir_raw(path: str) -> bool:
    """按 lstat 判断（不跟随符号链接）：链向目录的符号链接会被当成待 unlink 的项。

    **只吞 `FileNotFoundError`**（路径不存在 ⇒ 不是目录，这是正常结果，遍历时也会被
    "文件在 scandir 之后被删掉"的竞态触发）。其余 `OSError`（权限、共享冲突…）一律
    向上传播：早先无条件吞掉，于是 `rmtree(ignore_errors=False)` 对无权限路径
    **静默成功**——"删完了"其实是"压根没查到"，违反失败可诊断铁律（§8.6 第 3 条）。
    """
    try:
        return stat.S_ISDIR(os.lstat(path).st_mode)
    except FileNotFoundError:
        return False


def rmtree(path, *, ignore_errors: bool = True) -> None:
    r"""递归删除目录，全程使用扩展长度路径。

    **不能用 `shutil.rmtree`**，原因见模块头第 2 条坑（`os.path.join` 拼出正斜杠 →
    WinError 123 → 被 `ignore_errors` 静默吞掉）。子路径在这里一律用反斜杠手工拼接，
    保证整条链始终是合法的扩展形式；先删文件、再自底向上删目录。
    """
    root = extended(path)
    files: list[str] = []
    dirs: list[str] = []
    stack = [root]
    while stack:
        current = stack.pop()
        # `_is_dir_raw` 现在会抛"路径不存在以外"的 OSError；ignore_errors=True 的语义
        # 仍是"忽略"，所以这里显式接住再决定。
        try:
            kind = _is_dir_raw(current)
        except OSError:
            if not ignore_errors:
                raise
            continue
        if not kind:
            continue
        dirs.append(current)
        try:
            with os.scandir(current) as entries:
                for entry in entries:
                    child = current + "\\" + entry.name
                    try:
                        if _is_dir_raw(child):
                            stack.append(child)
                        else:
                            files.append(child)
                    except OSError:
                        if not ignore_errors:
                            raise
        except OSError:
            if not ignore_errors:
                raise
    for name in files:
        try:
            os.unlink(name)
        except OSError:
            if not ignore_errors:
                raise
    for name in reversed(dirs):          # 自底向上：先清空子目录，再删自己
        try:
            os.rmdir(name)
        except OSError:
            if not ignore_errors:
                raise
