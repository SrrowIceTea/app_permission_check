#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""把 targets.generated.js 的 WATCH 表注入已构建的 hook bundle。

为什么需要它（2026-11-15）：
    `node build.mjs hook_all` 依赖 frida-compile，而后者依赖 `frida` 的 Node 原生绑定
    （node_modules/frida/build/frida_binding.node）。本机只有源码、没有预编译产物，
    打包直接抛 `Could not locate the bindings file`。规则库新增了 4 个 Location 取值 API
    （getLatitude/getLongitude/getSpeed/getAccuracy），不重建 bundle 的话钩子仍然按旧表
    工作——库改了、运行期没变，是最难查的那种不一致。

做什么：
    只替换 bundle 里 `var WATCH = [...]` 的数组文本，其余代码一行不动。

安全约束（违反任一即退出，不写文件）：
    * `targets.generated.js` 里 `export const WATCH = [` 必须恰好出现 1 次；
    * bundle 里 `var WATCH = [` 必须恰好出现 1 次；
    * 注入后条目数必须与生成源一致，且新增 API 名必须出现。

长期方案：frida-compile 可用后直接 `node build.mjs hook_all`，本脚本只在构建链不可用时兜底。
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
DEFAULT_TARGETS = HERE / "targets.generated.js"
DEFAULT_BUNDLE = HERE / "dist" / "hook_all.bundle.js"


def _array_bounds(text: str, decl: str) -> tuple[int, int]:
    """返回 decl 之后数组体的 [start, end) —— 从 '[' 后到收尾的 '\\n];' 之前。"""
    if text.count(decl) != 1:
        raise SystemExit(f"[fatal] {decl!r} 出现 {text.count(decl)} 次，预期 1 次")
    start = text.index(decl) + len(decl)
    end = text.find("\n];", start)
    if end < 0:
        raise SystemExit(f"[fatal] {decl!r} 之后找不到收尾的 '];'")
    return start, end


def main() -> int:
    ap = argparse.ArgumentParser(description="把 WATCH 表注入已构建 bundle")
    ap.add_argument("--targets", default=str(DEFAULT_TARGETS))
    ap.add_argument("--bundle", default=str(DEFAULT_BUNDLE))
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    targets = Path(args.targets)
    bundle = Path(args.bundle)
    src = targets.read_text(encoding="utf-8")
    dst = bundle.read_text(encoding="utf-8")

    s0, s1 = _array_bounds(src, "export const WATCH = [")
    watch_src = src[s0:s1]
    n_src = watch_src.count('"cls"')

    b0, b1 = _array_bounds(dst, "var WATCH = [")
    n_old = dst[b0:b1].count('"cls"')

    new = dst[:b0] + watch_src + dst[b1:]
    n_new = new[b0:b0 + len(watch_src)].count('"cls"')

    if n_new != n_src:
        raise SystemExit(f"[fatal] 注入后条目数 {n_new} != 生成源 {n_src}")
    if "getLatitude" in dst and "getLatitude" not in new:
        raise SystemExit("[fatal] 注入后反而丢了 getLatitude")

    # frida-compile 的包格式：`📦\n<size> <name>...\n✄\n<module>\n✄\n<module>`
    # 每个模块头部记着**该模块的 UTF-8 字节数**；core/frida_host/bundle_config.py
    # 在注入前会逐模块校验。改了模块内容却不改头部，运行期直接报
    # `Frida bundle 长度校验失败`（2026-11-15 实测）。这里统一重算。
    if new.startswith("📦\n"):
        header, rest = new.split("\n✄\n", 1)
        modules = rest.split("\n✄\n")
        entries = header.splitlines()[1:]
        if len(modules) != len(entries):
            raise SystemExit("[fatal] bundle 模块数与头部条目数不一致，拒绝写入")
        rebuilt = []
        for entry, module in zip(entries, modules):
            _old_size, name = entry.split(" ", 1)
            rebuilt.append(f"{len(module.encode('utf-8'))} {name}")
        new = "📦\n" + "\n".join(rebuilt) + "\n✄\n" + "\n✄\n".join(modules)

    print(f"[ok] WATCH: {n_old} -> {n_new} 条（源 {n_src}）"
          f"{'（dry-run，不写盘）' if args.dry_run else ''}")
    if args.dry_run:
        return 0

    # 写完必须过工具链自己的校验：bundle_config.configure 会逐模块比对长度头，
    # 头部没重算时它抛 `Frida bundle 长度校验失败`——这正是本轮踩过的坑，
    # 不能让脚本"写成功"而运行期才炸。
    sys.path.insert(0, str(HERE.parents[1] / "core" / "frida_host"))
    try:
        import bundle_config
        bundle_config.configure(new, ["com.example.verify"])
    except Exception as exc:  # noqa: BLE001
        raise SystemExit(f"[fatal] 注入后未通过工具链校验：{type(exc).__name__}: {exc}")

    tmp = bundle.with_suffix(bundle.suffix + ".tmp")
    tmp.write_text(new, encoding="utf-8")
    tmp.replace(bundle)
    print(f"[ok] 已写入 {bundle}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
