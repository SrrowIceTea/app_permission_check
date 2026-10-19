#!/usr/bin/env python3
"""移动隐私关联引擎 —— 读取事件 × 同意时序 × 网络流 × 政策 → 结论（findings.jsonl）。

仅用于授权测试（已获授权的样本与设备）。

与 vehicle/analyze/correlate.py 的关系：
  * 输出**沿用同一套 findings/summary 字段契约**，因此 vehicle/dashboard 看板可以不改代码直接读；
  * 代码行号链**直接复用 core/evidence/codeloc.py**（它按 evidence_kind 分派，与车载共用一套）；
  * 求值器换成移动的八种谓词（见 evaluation_mobile.py）。

三条不能省的记录：
  * 缺哪一路输入就写进 summary.gaps —— 否则"没采集到"会被读成"没发生"；
  * 结论等级只由规则决定，引擎绝不抬高；
  * 时间窗来自规则；用 --window-override-ms 覆盖时如实标 window_overridden。
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT))
from core.evidence import codeloc  # noqa: E402  复用（车载/移动共用一套行号提取）
from core.io_utils import load_jsonl_counting  # noqa: E402  JSONL 唯一实现（§8.2 B-2）
import evaluation_mobile as ev  # noqa: E402
from read_semantics import read_state, read_gaps

def read_jsonl(path: Path | None, gaps: list[str] | None = None) -> list[dict]:
    """统一走 core/io_utils（§8.2 B-2）。

    坏行**不再静默 `continue`**：给了 `gaps` 就写进 gaps，否则打到 stderr。
    "少了几条证据"必须看得见，否则会被读成"没发生"。
    """
    rows, skipped = load_jsonl_counting(path)
    if skipped:
        note = f"{Path(path).name if path else '?'} 有 {skipped} 行无法解析的 JSONL，已跳过（证据不完整）"
        if gaps is not None:
            gaps.append("[jsonl] " + note)
        else:
            print(f"[warn] {note}", file=sys.stderr)
    return rows


def sha16(path: Path | None) -> str | None:
    if not path or not path.exists():
        return None
    return hashlib.sha256(path.read_bytes()).hexdigest()[:16]


def load_rules(db: Path, version: str) -> list[dict]:
    conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT * FROM risk_rules WHERE android_version=? ORDER BY rule_id",
                        (version,)).fetchall()
    if not rows:
        sys.exit(f"[fatal] 规则库里没有 android_version={version} 的规则")
    out = []
    for r in rows:
        out.append({
            "rule_id": r["rule_id"], "rule_revision": r["rule_revision"],
            "title": r["title"], "rule_type": r["rule_type"], "severity": r["severity"],
            "enabled": r["enabled"], "condition": json.loads(r["condition_json"] or "{}"),
            "window_ms": r["window_ms"], "conclusion_level": r["conclusion_level"],
            "permission_name": r["permission_name"], "data_type_key": r["data_type_key"],
            "basis_refs": json.loads(r["basis_refs_json"]),
            "source_refs": json.loads(r["source_refs_json"]),
            "android_version": r["android_version"],
        })
    conn.close()
    return out


def load_data_types(db: Path, version: str) -> tuple[dict, dict, dict]:
    """→ (data_type→中文名, data_type→[权限短名], category_key→category)"""
    conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    zh, hints = {}, {}
    for r in conn.execute("SELECT data_type_key, name_zh, permission_hint FROM"
                          " sensitive_data_types WHERE android_version=?", (version,)):
        zh[r["data_type_key"]] = r["name_zh"]
        hint = r["permission_hint"] or ""
        tokens = [t.strip() for t in hint.replace("（", " ").replace("）", " ")
                  .replace("(", " ").replace(")", " ").replace("，", ",").split(",")]
        hints[r["data_type_key"]] = [t for t in tokens
                                     if t and t.isascii() and "_" in t]
    conn.close()
    return zh, hints, {}


def load_category(db: Path, version: str, key: str | None) -> dict:
    if not key:
        return {"key": None, "known": False,
                "note": "未声明 App 类目：over_collection 判定不可用"}
    conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT name_zh, basic_function, necessary_data_json,"
                       " no_personal_info_required FROM app_categories WHERE category_key=?"
                       " AND android_version=?", (key, version)).fetchone()
    conn.close()
    if row is None:
        return {"key": key, "known": False,
                "note": f"类目 {key!r} 不在 39 类清单里：over_collection 判定不可用"}
    return {"key": key, "known": True, "name_zh": row["name_zh"],
            "basic_function": row["basic_function"],
            "necessary_data": json.loads(row["necessary_data_json"]),
            "no_personal_info_required": bool(row["no_personal_info_required"])}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--rules", default=str(ROOT / "mobile" / "rules" / "rules_mobile.db"))
    ap.add_argument("--version", default="36")
    ap.add_argument("--session", required=True, help="会话目录（reads/consent/flows.jsonl）")
    ap.add_argument("--reads", default=None)
    ap.add_argument("--consent", default=None)
    ap.add_argument("--flows", default=None)
    ap.add_argument("--egress", default=None)
    ap.add_argument("--permissions", default=None, help="清单权限列表（每行一个）")
    ap.add_argument("--policy-store", default=None)
    ap.add_argument("--version-code", default=None, help="APK versionCode, for local policy association")
    ap.add_argument("--apk-sha256", default=None, help="Full APK SHA-256, for exact local policy association")
    ap.add_argument("--package", required=True)
    ap.add_argument("--app-category", default=None)
    ap.add_argument("--window-override-ms", type=int, default=None)
    ap.add_argument("--out", required=True)
    ap.add_argument("--summary", required=True)
    args = ap.parse_args()

    session = Path(args.session)
    reads_p = Path(args.reads) if args.reads else session / "reads.jsonl"
    consent_p = Path(args.consent) if args.consent else session / "consent.jsonl"
    flows_p = Path(args.flows) if args.flows else session / "flows.jsonl"
    egress_p = Path(args.egress) if args.egress else session / "egress.jsonl"
    out, summary_p = Path(args.out), Path(args.summary)
    for p in (out, summary_p):
        if p.exists():
            sys.exit(f"[refuse] {p} 已存在。既有结论可能是证据，换路径或先移走。")

    rules = load_rules(Path(args.rules), args.version)
    dt_zh, dt_hints, _ = load_data_types(Path(args.rules), args.version)
    gaps: list[str] = []
    reads, flows, egress = (read_jsonl(reads_p, gaps), read_jsonl(flows_p, gaps),
                            read_jsonl(egress_p, gaps))
    consent_raw = read_jsonl(consent_p, gaps)
    gaps.extend(read_gaps(reads))
    gaps.append("政策接受缺少直接信号：policy_consent_state=unknown；POLICY_VIEW/PERM_RESULT 不证明接受政策。")
    if not reads:
        gaps.append("reads.jsonl 缺失或为空：无读取证据（不等于没有读取，可能钩子未挂上）")
    if not consent_raw:
        gaps.append("consent.jsonl 缺失或为空：**no_consent_read 类结论全部不可判定**")
        consent = None
    else:
        consent = [e for e in consent_raw if e.get("ev") in ev.CONSENT_SIGNALS]
        if not consent:
            gaps.append("同意链里没有任何 PERM_RESULT/POLICY_VIEW：时序里没有「同意时刻」")
    if not flows:
        gaps.append("flows.jsonl 缺失或为空：无网络流证据（不等于没有外发）")

    permissions = []
    if args.permissions and Path(args.permissions).exists():
        permissions = [ln.strip() for ln in
                       Path(args.permissions).read_text(encoding="utf-8").splitlines()
                       if ln.strip() and not ln.startswith("#")]
    else:
        gaps.append("未提供清单权限列表：over_permission 类结论不可判定")

    sys.path.insert(0, str(ROOT / "mobile" / "policy"))
    import policy_lint
    from policy_library import load_policy
    policy = load_policy(Path(args.policy_store) if args.policy_store else None,
        package=args.package, version_code=args.version_code, apk_sha256=args.apk_sha256,
        allow_legacy=bool(args.policy_store and args.package == "com.vscanner.privacydemo"))
    gaps.extend(policy.get("gaps", []))
    if policy["available"]:
        policy["disclosure_scan"] = policy_lint.disclosure_scan(policy["text"], policy_lint.load_keywords())
    else:
        gaps.append("未取得匹配且校验通过的本地应用政策：policy_mismatch 类结论不可判定")

    ctx = {"package": args.package, "reads": reads, "consent": consent, "flows": flows,
           "permissions": permissions, "category": load_category(Path(args.rules),
                                                                 args.version, args.app_category),
           "policy": policy, "dt_zh": dt_zh, "dt_hints": dt_hints,
           "window_override_ms": args.window_override_ms}

    findings = []
    for rule in rules:
        try:
            f = ev.evaluate(rule, ctx)
        except Exception as e:  # noqa: BLE001
            # 求值器抛异常必须留痕：否则某条规则静默失效，看起来像"没有命中"。
            gaps.append(f"规则 {rule['rule_id']} 求值异常: {e.__class__.__name__}: {e}")
            continue
        if f:
            findings.append(f)

    findings = codeloc.attach(findings, reads, flows, egress, args.package)
    findings.sort(key=lambda f: (f["rule_id"]))

    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as fh:
        for f in findings:
            fh.write(json.dumps(f, ensure_ascii=False, sort_keys=True) + "\n")

    by_level, by_type, by_predicate = {}, {}, {}
    rules_with_finding = set()
    observed_data_types = set()
    for f in findings:
        by_level[f["conclusion_level"]] = by_level.get(f["conclusion_level"], 0) + 1
        by_type[f["rule_type"]] = by_type.get(f["rule_type"], 0) + 1
        by_predicate[f["predicate"]] = by_predicate.get(f["predicate"], 0) + 1
        rules_with_finding.add(f["rule_id"])
        dt = (f.get("data_type") or "")
        if dt:
            observed_data_types.add(dt)
    for r in reads:
        if r.get("ev") == "PRIVACY_READ" and read_state(r) == "obtained":
            for dt in (r.get("data_types") or []):
                observed_data_types.add(dt)

    all_predicates = {
        "manifest_permission_requires_necessity_review", "successful_sensitive_api_read",
        "read_before_consent_or_permission_grant", "read_before_egress_within_window",
        "data_type_not_in_necessary_scope", "sensitive_data_in_plaintext_flow",
        "sensitive_data_to_third_party_domain", "data_type_absent_from_policy_disclosure",
    }
    rules_by_type = {}
    for r in rules:
        rt = r["rule_type"]
        rules_by_type[rt] = rules_by_type.get(rt, 0) + 1

    coverage = {
        "data_types_observed": sorted(observed_data_types),
        "data_types_total": len(dt_zh),
        "data_types_coverage_pct": round(len(observed_data_types) / max(len(dt_zh), 1) * 100, 1),
        "rules_with_finding": len(rules_with_finding),
        "rules_total": len(rules),
        "rules_firing_pct": round(len(rules_with_finding) / max(len(rules), 1) * 100, 1),
        "predicates_fired": sorted(by_predicate.keys()),
        "predicates_silent": sorted(all_predicates - set(by_predicate.keys())),
        "predicates_count": dict(sorted(by_predicate.items())),
        "inputs_present": {
            "reads": len(reads) > 0, "consent": consent is not None,
            "flows": len(flows) > 0, "permissions": len(permissions) > 0,
            "policy": policy.get("available", False),
        },
        "rules_by_type_total": dict(sorted(rules_by_type.items())),
        "rules_by_type_firing": dict(sorted(
            {rt: sum(1 for rid in rules_with_finding
                     if next((r["rule_type"] for r in rules if r["rule_id"] == rid), None) == rt)
             for rt in rules_by_type}.items())),
    }

    summary = {
        "status": "correlated",
        "android_version": args.version, "package": args.package,
        "inputs": {"reads": len(reads), "flows": len(flows),
                   "egress_connections": sum(1 for e in egress
                                             if e.get("ev") == "EGRESS_CONNECT"),
                   "consent_events": len(consent_raw), "requested_permissions": len(permissions),
                   "rules_evaluated": len(rules),
                   "reads_path_sha256": sha16(reads_p), "flows_path_sha256": sha16(flows_p)},
        "findings_total": len(findings),
        "findings_by_conclusion_level": dict(sorted(by_level.items())),
        "findings_by_rule_type": dict(sorted(by_type.items())),
        "coverage": coverage,
        "code_locs": codeloc.summarize(findings),
        "app_category": ctx["category"].get("key"),
        "policy": {k: v for k, v in policy.items() if k not in ("text", "disclosure_scan")},
        "window_override_ms": args.window_override_ms,
        "gaps": gaps, "policy_consent_state": "unknown",
        "rules_sha256": hashlib.sha256(Path(args.rules).read_bytes()).hexdigest(),
        "caveat": "本工具不产出 policy_violation：是否违规是政策判定，需人工/AI 复核。"
                  "结论等级由规则自身封顶，引擎不抬高。",
    }
    summary_p.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n",
                         encoding="utf-8")
    dt_observed = len(coverage["data_types_observed"])
    dt_total = coverage["data_types_total"]
    print(json.dumps({"status": "correlated", "findings": len(findings),
                      "by_conclusion_level": summary["findings_by_conclusion_level"],
                      "by_rule_type": summary["findings_by_rule_type"],
                      "coverage": {"data_types": f"{dt_observed}/{dt_total}",
                                   "rules_firing": f"{coverage['rules_with_finding']}"
                                                    f"/{coverage['rules_total']}",
                                   "predicates_silent": coverage["predicates_silent"],
                                   "inputs_present": coverage["inputs_present"]},
                      "gaps": gaps}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
