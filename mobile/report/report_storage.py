"""仅用于授权测试：正式报告的存储/加密事实、技术评分与原始事件索引。"""
from reportlab.lib.units import mm
from report_common import Paragraph, esc, grid_table, kv_table


def section_storage(bundle, st, font):
    storage = (bundle.get("dynamic") or {}).get("storage_crypto") or {}
    out = [Paragraph("3.5 存储与加密观察（API 边界，不等于磁盘或泄露证明）", st["h2"])]
    if storage.get("available") is not True:
        out.append(Paragraph("本轮未提供存储/加密采集证据；不得据此认定没有写入、没有加密或安全。", st["warn"]))
        return out
    health, risk = storage.get("health") or {}, storage.get("risk_assessment") or {}
    observations, findings = storage.get("observations") or [], storage.get("findings") or []
    score = risk.get("signal_score")
    out.append(kv_table([
        ("存储/加密钩子", "健康检查通过" if health.get("healthy") else "健康未确认/失败，证据受限"),
        ("采集规模", f"脱敏 API 观察 {len(observations)}；技术观察 {len(findings)}"),
        ("原始证据绑定", esc((storage.get("source_artifact") or {}).get("name")) + "；SHA-256 " +
         esc((storage.get("source_artifact") or {}).get("sha256"))),
        ("技术复核优先级", (str(score) if score is not None else "未知/无可评分技术观察") +
         "；VSCAN-STORAGE-1：4×可能性×影响，各 0–5，取最高；不是法律、CVSS 或整体安全评分"),
        ("数据内容保护", esc(storage.get("masking"))),
    ], st, font))
    for finding in findings:
        out.append(Paragraph(esc(finding["evidence_id"]) + " · " + esc(finding["kind"]), st["h2"]))
        out.append(Paragraph(esc(finding["detail"]), st["body"]))
        out.append(Paragraph("证据：" + esc(", ".join(finding.get("evidence_refs") or [])) +
                             "；技术分值 " + str(finding.get("signal_score")) +
                             "；持久化和个人信息泄露均未证明；不作法规适用定性。", st["small"]))
    if observations:
        out.append(Paragraph("原始事件索引（前 20 条；完整逐条索引见证据包 dynamic.storage_crypto.observations）", st["small"]))
        rows = []
        for row in observations[:20]:
            source = row["source"]
            rows.append([esc(row["evidence_id"]), esc(row["event"]),
                         esc(f"audit.jsonl:{source['line']} evt_id={source.get('evt_id')}"),
                         esc(f"{source['session_id']} / pid {source['pid']}"),
                         esc(row.get("algorithm") or row["observation_scope"])])
        out.append(grid_table(["ID", "事件", "来源行/原ID", "会话/进程", "算法/边界"], rows, st, font,
                              widths=[13 * mm, 32 * mm, 43 * mm, 40 * mm, 42 * mm]))
    for gap in storage.get("coverage_gaps") or []:
        out.append(Paragraph("- " + esc(gap), st["small"]))
    return out
