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
from core.collector.attribution import CONNECT_AGE_MS  # noqa: E402  连接→请求的实测年龄上限
from core.evidence import codeloc  # noqa: E402  复用（车载/移动共用一套行号提取）
from core.evidence.app_classes import load_app_classes  # noqa: E402  R8 混淆类的权威判据
from core.io_utils import load_jsonl_counting  # noqa: E402  JSONL 唯一实现（§8.2 B-2）
from core.rules_contract import load_rule_rows  # noqa: E402  规则行唯一读库入口
import evaluation_mobile as ev  # noqa: E402
from read_semantics import read_gaps
# 同意链四态观测判定拆自本文件（correlate_mobile 曾超 300 行硬线）。
import correlate_consent  # noqa: E402
# 归因分布段同样拆出（2026-11-15，P1-04）：兜底归因也有 package，
import flow_attribution  # noqa: E402
import summary_sections  # noqa: E402
from line_egress_evidence import NAME as LINE_EGRESS, admitted_flows

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
    """转发 core 契约层（原自写 SQL 的 URI 未 quote）；本线只留 14 字段投影与空规则退出。"""
    rows = load_rule_rows(db, version)
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
    ap.add_argument("--version", default="36",
                    help="规则库的 android_version（不是设备 API）。设备版本用 --device-api 单独传")
    ap.add_argument("--device-api", default=None,
                    help="设备实际 API（如 35）。summary.device_api 据此单列——"
                         "2026-11-15 试点发现把规则库版本当成设备版本会被误读（P2-02）")
    ap.add_argument("--session", required=True, help="会话目录（reads/consent/flows.jsonl）")
    ap.add_argument("--reads", default=None)
    ap.add_argument("--consent", default=None)
    ap.add_argument("--flows", default=None)
    ap.add_argument("--egress", default=None)
    ap.add_argument("--permissions", default=None, help="清单权限列表（每行一个）")
    ap.add_argument("--static-dir", default=None,
                    help="静态产物目录（含 dexfacts.json）。给了就用 APK 类表认 R8 混淆后的"
                         "应用类名；不给则退回包名前缀，混淆样本的代码行号会对不上。")
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
    reads, flows, egress = (read_jsonl(reads_p, gaps), read_jsonl(flows_p, gaps), read_jsonl(egress_p, gaps))
    consent_raw = read_jsonl(consent_p, gaps)
    eg = summary_sections.egress_channels(out, flows, egress)
    gaps.extend(read_gaps(reads) + eg.pop("gaps"))
    gaps.append("政策接受缺少直接信号：policy_consent_state=unknown；POLICY_VIEW/PERM_RESULT 不证明接受政策。")
    if not reads:
        gaps.append("reads.jsonl 缺失或为空：无读取证据（不等于没有读取，可能钩子未挂上）")
    consent, consent_observation = correlate_consent.observe_consent(
        consent_raw, ev.CONSENT_SIGNALS, gaps)
    if not flows:
        gaps.append("flows.jsonl 缺失或为空：无网络流证据（不等于没有外发）")
    else:
        fallback_n = sum(1 for f in flows
                         if f.get("attribution") == "single_package_fallback")
        if fallback_n:
            # 排除法归因没有时间对齐，比"时间距离大"更松。必须写进结论，
            # 否则报告里会和精确时间归因长得一样（2026-10-19 审计发现）。
            # 2026-11-15 修正：原来只在**全部**流都是兜底时才写；混合场景
            # （1 条实测 + 3 条兜底）一条缺口都不记，看报告的人无从分辨（P1-04）。
            if fallback_n == len(flows):
                head = f"本轮 {len(flows)} 条网络流全部为单包排除法归因"
            else:
                head = f"本轮 {len(flows)} 条网络流中有 {fallback_n} 条为单包排除法归因"
            gaps.append(head + "（single_package_fallback）：仅有白名单候选，实际发送包无法确认；"
                        "相关结论封顶 candidate")
    rules_api_match = (args.device_api == args.version) if (args.device_api or "").isdigit() else None
    if rules_api_match is False:
        gaps.append(f"设备 API {args.device_api} 使用规则库版本 {args.version}；跨版本适用性未经验证。")

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
           "pcap_line_flows": admitted_flows(read_jsonl(session / LINE_EGRESS), session=session.name, package=args.package),
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

    app_classes = load_app_classes(args.static_dir)
    if args.static_dir and app_classes is None:
        gaps.append(f"[codeloc] {Path(args.static_dir) / 'dexfacts.json'} 不可用或没有 classes 字段："
                    "本样本按包名前缀判定应用帧，R8 混淆后的类名会认不出来")
    findings = codeloc.attach(findings, reads, flows, egress, args.package, app_classes,
                              connect_window_ms=CONNECT_AGE_MS)
    findings.sort(key=lambda f: (f["rule_id"]))

    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as fh:
        for f in findings:
            fh.write(json.dumps(f, ensure_ascii=False, sort_keys=True) + "\n")

    by_level, by_type, by_predicate, rules_with_finding = \
        summary_sections.conclusion_counts(findings)
    observed_data_types = summary_sections.collect_observed_data_types(findings, reads)
    coverage = summary_sections.coverage_section(
        observed_data_types=observed_data_types, dt_total=len(dt_zh), rules=rules,
        rules_with_finding=rules_with_finding, by_predicate=by_predicate,
        reads=reads, consent=consent, permissions=permissions, policy=policy, flows=flows)

    by_attr, identity_verified = flow_attribution.attribution_breakdown(flows)

    summary = {
        "status": "correlated",
        "android_version": args.version, "package": args.package,
        "device_api": args.device_api,
        "apk_sha256": args.apk_sha256, "version_code": args.version_code,
        "rules_device_api_match": rules_api_match,
        "android_version_source": "rules_db",
        "flows_by_attribution": dict(sorted(by_attr.items())),
        "flows_identity_verified": identity_verified,
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
        # 代码行号能不能认 R8 混淆类，取决于这张表有没有加载成功——排查时先看这里。
        "app_classes": {"loaded": app_classes is not None,
                        "count": len(app_classes or ())},
        "app_category": ctx["category"].get("key"),
        "policy": {k: v for k, v in policy.items() if k not in ("text", "disclosure_scan")},
        "window_override_ms": args.window_override_ms,
        "gaps": gaps, "egress_channels": eg, "policy_consent_state": "unknown",
        "consent_observation": consent_observation,
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
