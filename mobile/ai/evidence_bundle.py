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
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "policy"))
sys.path.insert(0, str(HERE.parent / "tools"))
sys.path.insert(0, str(ROOT))
from bundle_observations import read_jsonl, top_app_frame, build_reads, build_consent, build_flows
import policy_lint  # noqa: E402
from local_knowledge import bind_regulations, load_bound_policy
from mobile.ai.storage_observations import build_storage_crypto
from mobile.ai.supplemental_observations import build_static, build_network
from mobile.analyze.bundle_risk import assess_bundle
import apk_packer_probe  # noqa: E402  加固特征探测：命中即把「结论受限」写进 gaps

BUNDLE_VERSION = "1"


def sha256_file(path: Path) -> str | None:
    if not path.exists():
        return None
    return hashlib.sha256(path.read_bytes()).hexdigest()


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
    regs, scope = bind_regulations(regs)
    return {"version": version, "knowledge_scope": scope, "enabled_by_type": dict(sorted(by_type.items())),
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


def build(session: Path, rules_db: Path, *, version: str, policy_store: Path | None,
          findings_path: Path | None, app: dict, include_previews: bool,
          notes: list[str] | None = None, apk_path: Path | None = None,
          allow_legacy_policy: bool = False, static_evidence: Path | None = None) -> dict:
    gaps: list[str] = []
    # 编排层显式提供的缺口说明。它们**不替代**下面自动发现的缺口，只做补充：
    # 有些限制是样本/环境特有的（例如"该样本的 HTTP 客户端不读系统代理，抓包结构性为空"），
    # 工具无法从数据里推出来，只能由知道现场的人写下来。带 [orch] 前缀以便区分来源。
    for note in (notes or []):
        if note and note.strip():
            gaps.append("[orch] " + note.strip())

    # 加固壳检测：命中即如实标注"结论受限"。不提供 APK 时跳过（不制造噪音），
    # 但那就意味着报告无法提示"样本可能是壳"——所以能传就传。
    packer = None
    if apk_path and apk_path.is_file():
        try:
            packer = apk_packer_probe.probe(apk_path)
            packer_note = apk_packer_probe.gap_note(packer)
            if packer_note:
                gaps.append(packer_note)
        except Exception as e:  # noqa: BLE001 —— 探测失败不得拖垮证据包，但必须留痕
            gaps.append(f"[probe] APK 加固特征探测失败（{e.__class__.__name__}: {e}）："
                        "本轮无法判断样本是否加壳，结论按未加壳呈现时需留意。")
    elif apk_path:
        gaps.append(f"[probe] 指定的 APK 不存在: {apk_path}；未做加固特征探测。")

    reads = build_reads(session, gaps)
    consent = build_consent(session, gaps)
    flows, plaintext = build_flows(session, gaps, include_previews=include_previews)
    storage_crypto = build_storage_crypto(session, app.get("package"), gaps)
    static = build_static(static_evidence, app, gaps)
    network = build_network(session, app, gaps)

    findings = read_jsonl(findings_path, gaps) if findings_path else []
    if not findings:
        gaps.append("findings.jsonl 缺失或为空：无规则结论（correlate 阶段未跑或没有命中）")

    health = {}
    for src, fname in (("privacy", "reads.jsonl"), ("consent", "consent.jsonl"),
                       ("egress", "egress.jsonl")):
        events = read_jsonl(session / fname, gaps)
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

    policy = load_bound_policy(policy_store, app, rules_db, version,
                               allow_legacy=allow_legacy_policy)
    gaps.extend(policy.get("gaps") or [])
    if not policy.get("available"):
        gaps.append("本地隐私政策不可用或未匹配APK：隐私政策相关判定不可用")

    bundle = {
        "bundle_version": BUNDLE_VERSION,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "app": app,
        "rules": load_rules_meta(rules_db, version),
        "dynamic": {"reads": reads, "consent_timeline": consent, "hook_health": health,
                    "policy_consent_state": "unknown", "storage_crypto": storage_crypto},
        "traffic": {"flows": flows, "plaintext_flow_ids": plaintext, "network_observations": network},
        "static": static,
        "findings": [{"rule_id": f.get("rule_id"), "rule_type": f.get("rule_type"),
                      "severity": f.get("severity"), "conclusion_level": f.get("conclusion_level"),
                      "title": f.get("title"), "policy_consent_state": f.get("policy_consent_state"),
                      "permission_state": f.get("permission_state"), "consent_basis": f.get("consent_basis"),
                      "conclusion_capped_by": f.get("conclusion_capped_by"),
                      "declared_conclusion_level": f.get("declared_conclusion_level"),
                      "pairs": f.get("pairs"),
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
        "packer_probe": packer if packer is not None else {"probed": False,
                                                           "note": "未提供 APK，未做加固特征探测"},
        "gaps": gaps,
        "counts": {"reads": len(reads), "consent_events": len(consent),
                   "flows": len(flows), "findings": len(findings),
                   "storage_crypto_observations": len(storage_crypto["observations"]),
                   "storage_crypto_findings": len(storage_crypto["findings"])},
    }
    bundle["risk_assessment"] = assess_bundle(bundle)
    return bundle


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--session", required=True, help="采集会话目录（含 reads/consent/flows.jsonl）")
    ap.add_argument("--rules", default=str(ROOT / "mobile" / "rules" / "rules_mobile.db"))
    ap.add_argument("--version", default="36")
    ap.add_argument("--policy-store", default=None)
    ap.add_argument("--allow-legacy-policy", action="store_true",
                    help="仅兼容显式指定的旧夹具政策目录；真实应用应使用有版本绑定的政策库")
    ap.add_argument("--version-code", default=None)
    ap.add_argument("--static-evidence", type=Path, default=None, help="Same-original-APK workbench-static.json")
    ap.add_argument("--findings", default=None)
    ap.add_argument("--package", required=True)
    ap.add_argument("--app-category", default=None, help="39 类中的 category_key（未声明则留空）")
    ap.add_argument("--apk-sha256", default=None)
    ap.add_argument("--apk", default=None,
                    help="样本 APK 路径；提供则做加固特征探测，命中时写入 gaps（结论受限）")
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

    app = {"package": args.package, "version_code": args.version_code,
           "apk_sha256": args.apk_sha256, "device": args.device,
           "app_category": load_category(Path(args.rules), args.version, args.app_category)}
    bundle = build(session, Path(args.rules), version=args.version,
                   policy_store=Path(args.policy_store) if args.policy_store else None,
                   findings_path=Path(args.findings) if args.findings else None,
                   app=app, include_previews=args.include_previews, notes=args.note,
                   apk_path=Path(args.apk) if args.apk else None,
                   allow_legacy_policy=args.allow_legacy_policy, static_evidence=args.static_evidence)

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
