#!/usr/bin/env python3
"""隐私政策的**确定性**检查 —— 只有不需要语义理解的那部分。

仅用于授权测试（已获授权的样本与设备）。

三种检查分开，绝不混为一谈：
    text_present  正则/长度/中文占比 —— 确定性，但**只是代理指标**（见下）
    ai            需要读懂语义（"目的写清了没有""保存期限有没有说"）
    manual        需要人（"弹窗是否在首次运行出现""点击深度是否超过 4 次"）

代理指标的边界（必须保留）：正则没命中 **不等于** 政策没写。
政策完全可以用别的措辞表达同一件事。所以 text_present 的结果统一带
`basis: "regex_proxy"`，报告里它是线索，不是"未明示"的结论。
真正的"未明示"结论由 AI 研判给出，且必须引用政策原文。

disclosure_scan 是 policy_mismatch 谓词的输入：逐数据类别扫关键词，
命中则给出**所在片段**（供 AI 与人工复核），未命中只说明"没找到该说法"。
"""
from __future__ import annotations

import json
import re
from pathlib import Path

HERE = Path(__file__).resolve().parent
KEYWORDS_PATH = HERE.parent / "rules" / "seed" / "disclosure_keywords.json"


def load_keywords(path: Path | None = None) -> dict[str, list[str]]:
    data = json.loads((path or KEYWORDS_PATH).read_text(encoding="utf-8"))
    return data["keywords"]


def _snippet(text: str, start: int, end: int, radius: int = 40) -> str:
    a = max(0, start - radius)
    b = min(len(text), end + radius)
    return ("…" if a > 0 else "") + text[a:b].replace("\n", " ") + ("…" if b < len(text) else "")


def disclosure_scan(text: str, keywords: dict[str, list[str]]) -> dict[str, dict]:
    """逐数据类别扫关键词。→ {data_type: {found, hits:[{keyword, snippet}], note}}"""
    out: dict[str, dict] = {}
    for dt, words in sorted(keywords.items()):
        hits = []
        for w in words:
            idx = text.find(w)
            if idx >= 0:
                hits.append({"keyword": w, "snippet": _snippet(text, idx, idx + len(w))})
                if len(hits) >= 5:      # 每个类别最多留 5 条片段，够复核即可
                    break
        out[dt] = {"found": bool(hits), "hits": hits,
                   "note": None if hits else "未找到该说法的关键词；不等于政策未提及。"}
    return out


def check_requirement(req: dict, text: str, cjk_ratio: float) -> dict:
    """对一条 policy_requirements 行做确定性检查（或如实标为需 AI/人工）。"""
    kind = req["check_kind"]
    result: dict = {"req_id": req["req_id"], "title": req["title"], "check_kind": kind,
                    "severity": req["severity"], "requirement": req["requirement"]}

    if kind in ("ai", "manual"):
        result["result"] = "deferred" if kind == "ai" else "manual_required"
        result["basis"] = "semantic" if kind == "ai" else "human"
        result["note"] = ("需语义研判：交由 AI 阶段逐条判断，且必须引用政策原文。"
                          if kind == "ai" else "需人工核验（UI 行为，本工具不自动判定）。")
        return result

    spec = req.get("check_spec") or {}
    checks = []
    if "min_chars" in spec:
        ok = len(text) >= spec["min_chars"]
        checks.append({"check": "min_chars", "expected": spec["min_chars"],
                       "actual": len(text), "met": ok})
    if "min_cjk_ratio" in spec:
        ok = cjk_ratio >= spec["min_cjk_ratio"]
        checks.append({"check": "min_cjk_ratio", "expected": spec["min_cjk_ratio"],
                       "actual": cjk_ratio, "met": ok})
    if "regex" in spec:
        m = re.search(spec["regex"], text)
        checks.append({"check": "regex", "pattern": spec["regex"], "met": bool(m),
                       "match": m.group(0) if m else None})
    if not checks:
        result["result"] = "not_evaluable"
        result["basis"] = "config"
        result["note"] = "该条款没有可执行的 check_spec；按未实现处理，不得当成通过。"
        return result

    met = all(c["met"] for c in checks)
    result["checks"] = checks
    result["result"] = "proxy_met" if met else "proxy_not_met"
    # **代理指标**：未命中不等于政策没写，只是没匹配上这个模式。
    result["basis"] = "regex_proxy"
    result["note"] = ("代理指标命中；不等于该条款已合规。" if met else
                      "代理指标未命中；**不等于**政策未写该内容——换措辞就会不命中，"
                      "需人工或 AI 复核。")
    return result


def lint(text: str, requirements: list[dict], cjk_ratio: float = 0.0) -> dict:
    checks = [check_requirement(r, text, cjk_ratio) for r in requirements]
    by_result: dict[str, int] = {}
    for c in checks:
        by_result[c["result"]] = by_result.get(c["result"], 0) + 1
    return {
        "checks": checks,
        "by_result": dict(sorted(by_result.items())),
        "note": "text_present 类结果是正则代理指标，不是合规结论；ai 类需语义研判；manual 类需人工。",
    }


def load_requirements(db_path: Path, version: str) -> list[dict]:
    """从 rules_mobile.db 读启用的条款（只读）。"""
    import sqlite3
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT req_id, title, requirement, check_kind, check_spec_json, severity"
        " FROM policy_requirements WHERE android_version=? AND enabled=1"
        " ORDER BY req_id", (version,)).fetchall()
    conn.close()
    out = []
    for r in rows:
        out.append({"req_id": r["req_id"], "title": r["title"], "requirement": r["requirement"],
                    "check_kind": r["check_kind"],
                    "check_spec": json.loads(r["check_spec_json"]) if r["check_spec_json"] else {},
                    "severity": r["severity"]})
    return out
