#!/usr/bin/env python3
"""证据打包 —— 把一次检测的全部事实汇成一个**可引用、已脱敏**的 JSON。

仅用于授权测试（已获授权的样本与设备）。

这份 JSON 是 AI 研判唯一的输入。三条设计约束：

  1) **每条事实都有 evidence_id**。提示词强制模型在每条结论里引用它们；
     校验阶段会逐条核对引用是否存在——引用不存在就是编造，会被挡下来。

  2) **默认脱敏后再外发**。动态读取事件本来就只带值哈希与前 6 字符预览；
     网络流默认**不带** request_preview（那 400 字符里可能有个人信息原文），
     只带元数据、标签、以及**令牌哈希**。模型判断"有没有传"不需要原文。
     要带原文得显式 --include-previews，且报告里会写明这一轮带了。

  3) **缺什么就写什么**。任何一路输入缺失都进 gaps 列表，
     绝不静默省略——否则模型会把"没采集到"当成"没发生"。
     这是本项目最贵的教训（未命中与未扫到长得一样）。

输出：evidence-bundle.json（+ 同目录的 bundle.sha256，供报告回溯）。
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(HERE.parent / "policy"))
import policy_lint  # noqa: E402

BUNDLE_VERSION = "1"


def read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    out = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


def sha256_file(path: Path) -> str | None:
    if not path.exists():
        return None
    return hashlib.sha256(path.read_bytes()).hexdigest()


def top_app_frame(stack: str | None) -> str | None:
    """栈里第一条应用帧的文本。整栈可达数百行，打包时只留第一帧做定位线索。"""
    if not stack:
        return None
    for line in stack.splitlines():
        s = line.strip()
        if s.startswith("at ") and "com.android" not in s and "android." not in s[:40]:
            return s[:200]
    return None


def load_rules_meta(db: Path, version: str) -> dict:
    conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    by_type = {r["rule_type"]: r["n"] for r in conn.execute(
        "SELECT rule_type, COUNT(*) n FROM risk_rules WHERE android_version=? AND enabled=1"
        " GROUP BY rule_type", (version,))}
    regs = []
    for r in conn.execute("SELECT DISTINCT basis_refs_json FROM risk_rules WHERE"
                          " android_version=? AND enabled=1", (version,)):
        for ref in json.loads(r[0]):
            if ref.get("kind") == "regulation":
                key = (ref["doc"], ref["clause"])
                if key not in [(x["doc"], x["clause"]) for x in regs]:
                    regs.append({"doc": ref["doc"], "clause": ref["clause"],
                                 "title": ref.get("title")})
    conn.close()
    return {"version": version, "enabled_by_type": dict(sorted(by_type.items())),
            "enabled_total": sum(by_type.values()),
            "regulations": sorted(regs, key=lambda x: (x["doc"], x["clause"])),
            "db_sha256": sha256_file(db)}


def load_category(db: Path, version: str, key: str | None) -> dict:
    """取该类目的「必要个人信息」范围。key 为空或不认识时如实返回 unknown——
    over_collection 判定依赖它，缺了就判不了，不能默认成"无必要范围"。"""
    if not key:
        return {"key": None, "known": False,
                "note": "未声明 App 类目：over_collection 判定不可用"}
    conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    row = conn.execute(
        "SELECT name_zh, basic_function, necessary_data_json, no_personal_info_required,"
        " ordinal, source_refs_json FROM app_categories WHERE category_key=?"
        " AND android_version=?", (key, version)).fetchone()
    conn.close()
    if row is None:
        return {"key": key, "known": False,
                "note": f"类目 {key!r} 不在 39 类清单里：over_collection 判定不可用"}
    return {"key": key, "known": True, "name_zh": row["name_zh"],
            "basic_function": row["basic_function"],
            "necessary_data": json.loads(row["necessary_data_json"]),
            "no_personal_info_required": bool(row["no_personal_info_required"]),
            "ordinal": row["ordinal"], "source_refs": json.loads(row["source_refs_json"])}


def build_reads(session: Path, gaps: list[str]) -> list[dict]:
    events = read_jsonl(session / "reads.jsonl")
    if not events:
        gaps.append("reads.jsonl 缺失或为空：无动态读取证据（不等于没有读取，"
                    "可能只是钩子没挂上或应用没运行）")
    out = []
    n = 0
    for e in events:
        if e.get("ev") != "PRIVACY_READ":
            continue
        n += 1
        out.append({
            "evidence_id": f"R{n}",
            "data_type": (e.get("data_types") or [None])[0],
            "data_types": e.get("data_types"),
            "data_type_zh": (e.get("data_types_zh") or [None])[0],
            "sensitivity": e.get("max_sensitivity"),
            "api": e.get("api"),
            "outcome": e.get("outcome"),
            "arg_disc": e.get("arg_disc"),
            "value_kind": e.get("value_kind"),
            "value_hash": e.get("value_hash"),
            "value_preview": e.get("value_preview"),
            "value_count": e.get("value_count"),
            "column_count": e.get("column_count"),
            "ts": e.get("ts"),
            "host_received_ts": e.get("host_received_ts"),
            "app_frame": top_app_frame(e.get("stack")),
        })
    return out


def build_consent(session: Path, gaps: list[str]) -> list[dict]:
    events = read_jsonl(session / "consent.jsonl")
    if not events:
        gaps.append("consent.jsonl 缺失或为空：**无法判定「同意前收集」**——"
                    "没有同意时序就没有「之前」这个基准")
        return []
    out = []
    n = 0
    for e in events:
        if e.get("ev") not in ("PERM_REQ", "PERM_RESULT", "PERM_CHECK", "POLICY_VIEW"):
            continue
        n += 1
        item = {"evidence_id": f"C{n}", "signal": e.get("ev"), "ts": e.get("ts"),
                "host_received_ts": e.get("host_received_ts")}
        for k in ("permissions", "granted", "denied", "permission",
                  "check_granted", "url", "request_code"):
            if e.get(k) is not None:
                item[k] = e[k]
        out.append(item)
    return out


def build_flows(session: Path, gaps: list[str], *, include_previews: bool) -> tuple[list, list]:
    flows = read_jsonl(session / "flows.jsonl")
    if not flows:
        gaps.append("flows.jsonl 缺失或为空：无网络流证据（不等于没有外发）")
    out, plaintext = [], []
    for i, f in enumerate(flows, 1):
        eid = f"F{i}"
        rec = {
            "evidence_id": eid,
            "host": f.get("host"), "path": f.get("path"), "method": f.get("method"),
            "scheme": f.get("scheme"), "intercepted_tls": f.get("intercepted_tls"),
            "status_code": f.get("status_code"),
            "attribution": f.get("attribution"),
            "attribution_ambiguous": f.get("attribution_ambiguous"),
            "request_tags": f.get("request_tags") or [],
            "request_tokens": f.get("request_tokens") or [],
            "response_tags": f.get("response_tags") or [],
            "request_bytes": f.get("request_bytes"),
            "ts": f.get("ts"),
        }
        if (rec["request_tags"] or rec["response_tags"]):
            rec["sensitive_payload"] = True
        if rec["scheme"] == "http" or rec["intercepted_tls"] is False:
            plaintext.append(eid)
        if include_previews:
            rec["request_preview"] = f.get("request_preview")
        out.append(rec)
    return out, plaintext


def build(session: Path, rules_db: Path, *, version: str, policy_store: Path | None,
          findings_path: Path | None, app: dict, include_previews: bool,
          notes: list[str] | None = None) -> dict:
    gaps: list[str] = []
    # 编排层显式提供的缺口说明。它们**不替代**下面自动发现的缺口，只做补充：
    # 有些限制是样本/环境特有的（例如"该样本的 HTTP 客户端不读系统代理，抓包结构性为空"），
    # 工具无法从数据里推出来，只能由知道现场的人写下来。带 [orch] 前缀以便区分来源。
    for note in (notes or []):
        if note and note.strip():
            gaps.append("[orch] " + note.strip())
    reads = build_reads(session, gaps)
    consent = build_consent(session, gaps)
    flows, plaintext = build_flows(session, gaps, include_previews=include_previews)

    findings = read_jsonl(findings_path) if findings_path else []
    if not findings:
        gaps.append("findings.jsonl 缺失或为空：无规则结论（correlate 阶段未跑或没有命中）")

    health = {}
    for src, fname in (("privacy", "reads.jsonl"), ("consent", "consent.jsonl"),
                       ("egress", "egress.jsonl")):
        events = read_jsonl(session / fname)
        armed = next((e for e in events if e.get("ev") == "ARMED"), None)
        start = next((e for e in events if e.get("ev") == "START"), None)
        if start:
            health[src] = {"armed": armed.get("hooks") if armed else None,
                           "failed": armed.get("failed") if armed else None,
                           "whitelisted": start.get("pkg"),
                           "not_target": any(e.get("ev") == "NOT_TARGET" for e in events)}
        else:
            health[src] = {"armed": None, "failed": None, "note": "无 START 事件：脚本可能没跑起来"}
    if any(v.get("not_target") for v in health.values()):
        gaps.append("有钩子报了 NOT_TARGET：该进程不在白名单，事件为空是预期的，不是故障")

    policy = {"available": False}
    if policy_store and policy_store.exists():
        metas = sorted(policy_store.glob("policy-*.meta.json"))
        if metas:
            meta = json.loads(metas[-1].read_text(encoding="utf-8"))
            text_file = policy_store / meta["text_file"]
            text = text_file.read_text(encoding="utf-8") if text_file.exists() else ""
            reqs = policy_lint.load_requirements(rules_db, version)
            text_lint = policy_lint.lint(text, reqs, meta.get("cjk_ratio") or 0.0)
            policy = {"available": True, "source": meta.get("source"),
                      "source_kind": meta.get("source_kind"),
                      "raw_sha256": meta.get("raw_sha256"),
                      "text_sha256": meta.get("text_sha256"),
                      "extract_status": meta.get("extract_status"),
                      "chars": meta.get("text_chars"), "title": meta.get("title"),
                      "text": text,
                      "lint": text_lint,
                      "disclosure_scan": policy_lint.disclosure_scan(
                          text, policy_lint.load_keywords())}
        else:
            gaps.append("policy store 里没有 policy-*.meta.json：未取得隐私政策文本")
    else:
        gaps.append("未提供 policy store：**隐私政策相关判定全部不可用**")

    return {
        "bundle_version": BUNDLE_VERSION,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "app": app,
        "rules": load_rules_meta(rules_db, version),
        "dynamic": {"reads": reads, "consent_timeline": consent, "hook_health": health},
        "traffic": {"flows": flows, "plaintext_flow_ids": plaintext},
        "findings": [{"rule_id": f.get("rule_id"), "rule_type": f.get("rule_type"),
                      "severity": f.get("severity"), "conclusion_level": f.get("conclusion_level"),
                      "data_type": (f.get("condition") or {}).get("data_type")
                      if isinstance(f.get("condition"), dict) else f.get("data_type"),
                      "evidence_kind": f.get("evidence_kind"),
                      "event_ids": f.get("event_ids"),
                      "basis_refs": f.get("basis_refs"),
                      "note": f.get("note")} for f in findings],
        "policy": policy,
        "masking": {"applied": not include_previews,
                    "policy_text": "值哈希 + 前 6 字符预览；标识符原文不进入本文件"
                                   if not include_previews else
                                   "**本轮带入了报文预览原文**（--include-previews）",
                    "request_previews_included": include_previews},
        "gaps": gaps,
        "counts": {"reads": len(reads), "consent_events": len(consent),
                   "flows": len(flows), "findings": len(findings)},
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--session", required=True, help="采集会话目录（含 reads/consent/flows.jsonl）")
    ap.add_argument("--rules", default=str(ROOT / "mobile" / "rules" / "rules_mobile.db"))
    ap.add_argument("--version", default="36")
    ap.add_argument("--policy-store", default=None)
    ap.add_argument("--findings", default=None)
    ap.add_argument("--package", required=True)
    ap.add_argument("--app-category", default=None, help="39 类中的 category_key（未声明则留空）")
    ap.add_argument("--apk-sha256", default=None)
    ap.add_argument("--device", default=None)
    ap.add_argument("--include-previews", action="store_true",
                    help="把报文预览原文一并写入（默认关闭：预览可能含个人信息原文）")
    ap.add_argument("--note", action="append",
                    help="编排层提供的缺口说明（可重复）；写入 gaps，前缀 [orch] 标明来源")
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    session = Path(args.session)
    if not session.is_dir():
        sys.exit(f"[fatal] 会话目录不存在: {session}")

    app = {"package": args.package, "apk_sha256": args.apk_sha256, "device": args.device,
           "app_category": load_category(Path(args.rules), args.version, args.app_category)}
    bundle = build(session, Path(args.rules), version=args.version,
                   policy_store=Path(args.policy_store) if args.policy_store else None,
                   findings_path=Path(args.findings) if args.findings else None,
                   app=app, include_previews=args.include_previews, notes=args.note)

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(bundle, ensure_ascii=False, indent=2, sort_keys=True)
    out.write_text(text + "\n", encoding="utf-8")
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    (out.parent / (out.name + ".sha256")).write_text(digest + "\n", encoding="utf-8")
    print(json.dumps({"status": "ok", "out": str(out), "sha256": digest,
                      "counts": bundle["counts"], "gaps": len(bundle["gaps"]),
                      "policy_available": bundle["policy"]["available"]},
                     ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
