#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""批处理的**样本计划**：身份、产物目录、续跑与静态复用判定（串行、秒级、不碰设备）。

仅用于授权测试（自有设备 / 已授权的公开第三方样本）。

## 为什么拆出来（2026-10-19）

原先「解析身份 → 判续跑 → 跑静态」全挤在一个 for 循环里，只能一个一个来。
要并行静态，就必须**先**把整批的判定做完、拿到完整任务表，再一次性并发——
这些判定本身没有设备动作（aapt2 读 APK、读磁盘上的 verification.json），
串行做完是几十秒，拆开后主循环只剩「静态并行 → 动态串行」两步。

`collect()` 会**顺手建好目录并写 run.log 表头**：静态失败/被跳过的样本也要留下
可读的现场（本项目的老规矩——失败运行同样保留产物）。
"""
from __future__ import annotations

import json
import time
from pathlib import Path

from apk_meta import badging, short_slug

import batch_static as bs


def _finished(app_dir: Path) -> bool:
    """`--resume` 的完成判据：`verification.json` 通过 **且** 报告在。

    只看目录存在会把上次半途死掉的样本当成已完成——该目录里同样有 run.log 和
    static/，长得一模一样。
    """
    verification = app_dir / "verification.json"
    report = app_dir / "out" / "mobile-report.pdf"
    if not (verification.is_file() and report.is_file()):
        return False
    try:
        review = json.loads(verification.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    return isinstance(review, dict) and review.get("passed") is True


def _fill_findings(rec: dict, app_dir: Path) -> None:
    summary = app_dir / "out" / "summary.json"
    if not summary.is_file():
        return
    try:
        data = json.loads(summary.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return
    rec["findings_total"] = data.get("findings_total")
    rec["findings_by_type"] = data.get("findings_by_rule_type")


def completed_attempt(app_dir: Path) -> Path | None:
    attempts = (app_dir, *app_dir.glob("try-*"))
    return max((path for path in attempts if _finished(path)),
               key=lambda path: (path / "verification.json").stat().st_mtime_ns,
               default=None)


def _write_header(item: dict) -> None:
    """样本级 run.log 的表头：**追加**，不截断。

    为什么不是 `write_text`（2026-11-11 修正）：`--resume` 重跑同一批时，失败样本会再次
    进 collect；截断会把上一轮 attempt 的现场（device_run 的全部输出）抹掉，而
    `AGENTS.md` 要求"失败运行同样保留可读产物"。追加后每轮留一个带时间的分隔行，
    无限增长由 `core.log_rotation.open_capped` 的 20 MB 分卷兜住（同目录 `run.log.<ts>`）。
    """
    ident = item["ident"]
    log = item["app_dir"] / "run.log"
    header = (f"样本: {item['apk']}\n包名: {item['pkg']}\n"
              f"标签: {ident.get('app_label')}\n"
              f"版本: {ident.get('version_name')} ({ident.get('version_code')})\n"
              f"目录名是包名的短写（Windows 260 字符路径上限），"
              f"对应完整包名见本行上面的「包名」。\n")
    with log.open("a", encoding="utf-8") as handle:
        if log.stat().st_size:
            handle.write(f"\n===== {time.strftime('%Y-%m-%d %H:%M:%S')} 重新排入本样本"
                         f"（上一轮未完成，现场保留在上方）=====\n")
        handle.write(header)


def collect(apks: list[Path], batch: Path, *, build_tools: str,
            resume: bool = False, static_reuse: Path | None = None) -> list[dict]:
    """把 APK 列表变成计划表。**每项都带 rec**（最终写进 batch-summary.json 的那份）。"""
    plan: list[dict] = []
    for idx, apk in enumerate(apks, 1):
        rec: dict = {"apk": str(apk), "name": apk.name, "status": None, "steps": {}}
        ident = badging(apk, build_tools)
        rec["identity"] = ident
        item = {"idx": idx, "apk": apk, "rec": rec, "ident": ident,
                "pkg": ident.get("package"), "app_dir": None,
                "static_dir": None, "reuse": None}
        pkg = item["pkg"]
        if not pkg:
            rec["status"] = "unreadable_apk"
            rec["error"] = ident.get("error") or "aapt2 未解出包名"
            plan.append(item)
            continue
        if pkg != apk.stem:
            # 文件名与包名不一致不致命，但要说出来——报告里写错包名会让结论指向别的应用。
            rec["note"] = f"文件名 {apk.stem!r} 与包名 {pkg!r} 不一致（按包名建档）"

        app_dir = batch / f"{idx:02d}-{short_slug(pkg)}"
        item["app_dir"] = app_dir
        rec["dir"] = str(app_dir)

        finished = completed_attempt(app_dir) if resume else None
        if finished:
            rec["status"] = "resumed"
            rec["dir"] = str(finished)
            rec["report"] = str(finished / "out" / "mobile-report.pdf")
            _fill_findings(rec, finished)
            plan.append(item)
            continue

        app_dir.mkdir(parents=True, exist_ok=True)
        _write_header(item)
        # 静态复用两条来源：① 外部数据集（--static-reuse，按包名）；
        # ② **本批次自己的** `_static/`（仅 --resume）：跑批中途崩掉很常见
        #    （模拟器约 20 分钟一次），已经解完的 jadx 产物不该再花 1–2 分钟重解。
        item["reuse"] = (bs.reuse_hit(static_reuse, pkg)
                         or (bs.dir_for(batch, idx, pkg)
                             if resume and bs.manifest_done(bs.dir_for(batch, idx, pkg))
                             else None))
        # 任务对象在这里就建好：产物目录与日志路径只解析一次，避免下游各算一遍。
        if item["reuse"] is None:
            item["job"] = make_job(item, batch)
        plan.append(item)
    return plan


def needs_static(item: dict) -> bool:
    """要不要跑静态：有包名、没被判掉（resumed/unreadable）、且没有可复用的产物。"""
    return (item["pkg"] is not None and item["rec"]["status"] is None
            and item["reuse"] is None and "job" in item)


def make_job(item: dict, batch: Path) -> bs.Job:
    idx, pkg = item["idx"], item["pkg"]
    return bs.Job(key=bs.key_for(idx, pkg), apk=item["apk"], package=pkg,
                  out=bs.dir_for(batch, idx, pkg),
                  log=bs.log_for(batch, idx, pkg))


def apply_static(item: dict, rcs: dict[str, int]) -> None:
    """把静态结果写回计划项。失败只标该样本，不影响其余。"""
    rec = item["rec"]
    if item["pkg"] is None or rec["status"] is not None:
        return
    if item["reuse"] is not None:
        item["static_dir"] = item["reuse"]
        rec["steps"]["static"] = 0
        rec["static_reused_from"] = str(item["reuse"])
        return
    job = item["job"]
    rc = rcs.get(job.key, 1)
    rec["steps"]["static"] = rc
    rec["static_log"] = str(job.log)
    if rc != 0:
        rec["status"] = "static_failed"
        return
    item["static_dir"] = job.out
