#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""单 agent 合并脚本的事件分流：reads.jsonl（含全部 src）→ 独立事件文件。

背景（2026-10-16，A1 修复）：hook 从"多 run.py 各挂一个脚本"改为"单 bundle
（hook_all）一次挂四个模块"——frida-java-bridge 不支持多脚本各自替换方法
（bridge 源码注释原文 "we don't support replacing methods from multiple
scripts"；实测双脚本 ~50% 触发 ART FATAL，单脚本 5/5 稳定）。代价：所有事件
落在同一个 --out 文件里，而下游（correlate_mobile / evidence_bundle /
build_delivery）按固定文件名读 consent/egress/tls。本工具把合并产物分流回
独立文件，**下游零改动**。

规则（src → 文件；src 集合来自各模块的 makeLogger 名）：
    consent → consent.jsonl
    egress  → egress.jsonl
    tls     → tls.jsonl
    native_crypto → native_crypto.jsonl（EVP/AES 明文）
    tls_meta      → tls_meta.jsonl（SNI / keylog）
    其余（privacy / native_ssl 等）留在 reads.jsonl（仅在"确有分流"时过滤重写主文件）

**幂等**：仅当主文件里确实存在可分流事件时才动手；独立脚本模式下主文件只有
privacy 事件 → 本步为 no-op。无法解析的坏行在重写主文件时**原样保留**（不静默丢）。

退出码：0=完成（含 no-op）；非 0=IO 失败（分流没做成要显性——影响结论完整性）。
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

SRC_TO_FILE = {
    "consent": "consent.jsonl",
    "egress": "egress.jsonl",
    "socket_meta": "socket-meta.jsonl",
    "tls": "tls.jsonl",
    # 内存 Hook 的明文/元数据体量大且与「隐私读取」语义无关，分流到独立文件，
    # 避免 reads.jsonl 被 EVP/SNI 事件淹没（2026-10-18）。下游目前不读这两个文件，
    # 留档供证据包/报告按需取用。
    "native_crypto": "native_crypto.jsonl",
    "tls_meta": "tls_meta.jsonl",
}
MAIN_FILE = "reads.jsonl"


def classify(entries: list[tuple[str, dict | None]]) -> tuple[list[tuple[str, dict | None]],
                                                             dict[str, list[str]]]:
    """把 (原始行, 解析结果) 分成"留在主文件"与"分流文件"。纯函数，可离线测试。

    解析失败（None）的行一律留在主文件——重写时不丢任何原始字节。
    返回 (主文件行, {目标文件: [原始行, ...]})。
    """
    main_rows: list[tuple[str, dict | None]] = []
    split: dict[str, list[str]] = {}
    for raw, parsed in entries:
        target = SRC_TO_FILE.get(parsed.get("src")) if parsed else None
        if target is None:
            main_rows.append((raw, parsed))
        else:
            split.setdefault(target, []).append(raw)
    return main_rows, split


def _atomic_write_text(path: Path, text: str) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(text, encoding="utf-8")
    tmp.replace(path)


def split(session: Path) -> dict:
    """执行分流。返回统计（供调用方/测试断言）。会话里没有主文件时 no-op。"""
    main_p = session / MAIN_FILE
    if not main_p.exists():
        return {"skipped": "no_main_file"}

    entries: list[tuple[str, dict | None]] = []
    for line in main_p.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        try:
            entries.append((line, json.loads(line)))
        except json.JSONDecodeError:
            entries.append((line, None))

    main_rows, split_rows = classify(entries)
    if not split_rows:
        return {"skipped": "nothing_to_split", "main_lines": len(main_rows)}

    # 先写分流文件（覆盖；幂等——再次运行主文件里已无这些 src）。
    for name, lines in split_rows.items():
        _atomic_write_text(session / name,
                           "\n".join(lines) + "\n" if lines else "")
    # 再重写主文件（只在确有分流时）。
    _atomic_write_text(main_p,
                       "\n".join(raw for raw, _ in main_rows) + "\n" if main_rows else "")
    return {"files": {k: len(v) for k, v in split_rows.items()},
            "main_lines": len(main_rows)}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--session", required=True, type=Path, help="采集会话目录")
    args = ap.parse_args()
    stats = split(args.session)
    print(f"[split] {json.dumps(stats, ensure_ascii=False)}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
