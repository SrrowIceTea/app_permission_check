#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Phase 7 — 静态命中与运行时观测的四象限对照。

仅用于授权测试（自有设备与自有 APK）/ For authorized testing on owned devices and APKs only.

这是本工作台相对 jadx-gui 的**唯一实质增量**：光看源码人人都能做，能把
"代码里引用了什么"和"运行时真的发生了什么"对起来，才是这个平台的独有材料。

四象限（每条规则落且只落一格）：

    静态\\运行时     观测到            未观测到
    命中             both             static_only
    未命中           dynamic_only     none

**`dynamic_only` 是最有价值的一格**：代码里找不到、运行时却观测到了——通常意味着
规则库覆盖不全，或者被测应用用了反射 / 动态加载 / 加壳。这一格出现时应当去查原因，
而不是当成噪声。

**前提是两边是同一个 APK。** 动态证据来自某一次采集会话，它可能对应另一个构建。
用会话清单里的 `installed_apk_sha256` 与拖入的 APK 比对，不一致就**明确拒绝出象限表**，
只报告"两者不是同一个 APK"——拿两个不同版本的 APK 做对照，得出的每一格都是错的。
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

QUADRANTS = ("both", "static_only", "dynamic_only", "none")


def sha256_of(path: Path, chunk: int = 1 << 20) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while block := handle.read(chunk):
            digest.update(block)
    return digest.hexdigest()


def resolve_findings(session_dir: Path | None, findings: Path | None) -> tuple[Path | None, str]:
    """确定动态侧读哪个文件，并**说清是怎么找到的**。

    这里有个会给出**自信的错答案**的坑：`findings.jsonl` 在**交付目录**里，
    不在设备会话目录里（会话目录只有 reads/egress/flows/verification）。
    指着会话目录时如果直接读、读不到就当空，象限表会算成"22 条 static_only"——
    而真相是"动态侧压根没载入"。两者在界面上长得一模一样。
    """
    if findings:
        return findings, f"来自 --findings：{findings}"
    if session_dir is None:
        return None, "没有提供会话目录或 findings.jsonl"
    candidate = Path(session_dir) / "findings.jsonl"
    if candidate.exists():
        return candidate, f"{candidate}（会话目录下直接找到）"
    return None, (f"在 {session_dir} 下没找到 findings.jsonl。"
                  "注意**交付目录**里才有 findings.jsonl（设备会话目录只有 "
                  "reads/egress/flows/verification 这几样）——"
                  "请指向 output 下的 delivery-* 目录，或用 --findings 显式指定。")


def load_dynamic(findings_path: Path | None) -> dict:
    """读 vehicle/analyze 的 `findings.jsonl`，按 rule_id 归纳。

    一条规则可能有多条结论（不同属性/不同包），这里保留最高等级那条，
    因为象限只看"这条规则在运行时到底有没有落地"。
    """
    if not findings_path or not findings_path.exists():
        return {}
    from static_rules import LEVEL_ORDER
    best: dict[str, dict] = {}
    for line in findings_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        record = json.loads(line)
        rule_id = record.get("rule_id")
        if not rule_id:
            continue
        level = record.get("conclusion_level", "candidate")
        rank = LEVEL_ORDER.index(level) if level in LEVEL_ORDER else 0
        if rule_id not in best or rank > best[rule_id]["_rank"]:
            best[rule_id] = {"rule_id": rule_id, "conclusion_level": level,
                             "evidence_kind": record.get("evidence_kind"), "_rank": rank}
    for record in best.values():
        record.pop("_rank", None)
    return best


def identity(apk_sha256: str, manifest: dict | None) -> dict:
    """判断"拖入的 APK"与"动态证据对应的 APK"是不是同一个。

    `manifest` 是采集会话的 `session-manifest.json`（Phase 7 之前加入的）。
    没有清单**不等于**一致——那是"无法证明一致"，要如实说，不能默认放行。
    """
    if manifest is None:
        return {"same_apk": None, "reason": "没有会话清单，无法证明静态与动态针对同一个 APK",
                "apk_sha256": apk_sha256, "session_apk_sha256": None}
    session_sha = manifest.get("installed_apk_sha256")
    if not session_sha:
        return {"same_apk": None, "apk_sha256": apk_sha256, "session_apk_sha256": None,
                "reason": f"会话清单里没有 APK 哈希（采集时没算成："
                          f"{manifest.get('installed_apk_hash_error')}）"}
    same = session_sha == apk_sha256
    return {"same_apk": same, "apk_sha256": apk_sha256, "session_apk_sha256": session_sha,
            "reason": "同一个 APK" if same else "不是同一个 APK：静态与动态不能互相印证"}


def compare(static_result: dict, dynamic: dict, identity_report: dict,
            dynamic_source: str = "") -> dict:
    """产出四象限。**动态侧没载入或 APK 不同时不出象限表**，只返回拒绝理由。"""
    static_hits = {f["rule_id"]: f for f in static_result.get("findings", [])}
    all_ids = sorted(set(static_hits) | set(dynamic))

    if not dynamic:
        # 空动态**不能**当成"运行时什么都没发生"：多半是路径指错了。
        # 这种情况下算出来的象限表（全 static_only）是自信的错答案。
        return {"comparable": False, "identity": identity_report,
                "reason": f"动态侧一条结论都没读到（{dynamic_source}）。"
                          "空结果与「运行时确实没有任何命中」无法区分，"
                          "因此不出象限表——请确认 findings.jsonl 的路径。"}
    if identity_report.get("same_apk") is False:
        return {"comparable": False, "identity": identity_report,
                "static_hits": sorted(static_hits), "dynamic_hits": sorted(dynamic),
                "reason": "静态与动态针对的不是同一个 APK，逐条对照无意义；"
                          "请用与本次拖入 APK 同一个构建的采集会话。"}

    grid: dict[str, list] = {name: [] for name in QUADRANTS}
    rows = []
    for rule_id in all_ids:
        stat, dyn = static_hits.get(rule_id), dynamic.get(rule_id)
        quadrant = ("both" if stat and dyn else
                    "static_only" if stat else
                    "dynamic_only" if dyn else "none")
        grid[quadrant].append(rule_id)
        rows.append({
            "rule_id": rule_id, "quadrant": quadrant,
            "static_strength": (stat or {}).get("static_strength"),
            "static_signals": (stat or {}).get("signals"),
            "dynamic_level": (dyn or {}).get("conclusion_level"),
            "static_conclusion_level": (stat or {}).get("conclusion_level"),
        })

    return {
        "comparable": True,
        "identity": identity_report,
        "dynamic_source": dynamic_source,
        "rules_compared": len(all_ids),
        "grid": grid,
        "counts": {name: len(grid[name]) for name in QUADRANTS},
        "rows": rows,
        "static_context": static_result.get("static_context"),
        "attention": ("dynamic_only 表示运行时观测到了、代码里却找不到——"
                      "多半是规则库覆盖不全，或被反射/动态加载绕开了。"
                      if grid["dynamic_only"] else
                      "本轮没有 dynamic_only。"),
        "caveat": "静态侧只到 candidate（引用不等于行为）；动态侧是采集当时的观测。"
                  "两者一致**不构成违规结论**，违规仍需人工判定。",
    }


def load_manifest(session_dir: Path | None) -> dict | None:
    if not session_dir:
        return None
    path = Path(session_dir) / "session-manifest.json"
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else None
