"""Only actual ST/N sources, with technical scope and explicit display bounds."""
from report_common import Paragraph, esc, grid_table


def section_supplemental(bundle, st, font):
    static = bundle.get("static") or {}
    network = (bundle.get("traffic") or {}).get("network_observations") or {}
    if not static and not network:
        return []
    out = [Paragraph("3.6 原始 APK 静态候选与网络元数据", st["h2"])]
    out.append(Paragraph("ST 为原 APK 清单/DEX 引用候选，不是运行时调用栈或执行证明；N 为限定会话网络元数据，不是个人数据外发、明文或解密证明。", st["small"]))
    findings = static.get("findings") or []
    out.append(Paragraph(f"静态候选：{len(findings)} 组；原始记录 {static.get('source_finding_count', 0)}。原 APK SHA-256：" + esc(static.get("apk_sha256")), st["body"]))
    if findings:
        out.append(grid_table(["证据", "规则/类型", "候选及来源"], [
            [esc(r["evidence_id"]), esc(str(r.get("rule_id")) + " / " + str(r.get("evidence_kind"))),
             esc(str(r.get("title")) + "; candidate; count=" + str(r["count"]) +
                 "; source indices=" + str(r["source_indices"]))] for r in findings], st, font))
    rows = network.get("observations") or []
    out.append(Paragraph(f"网络观察：{len(rows)} 组；以下最多显示 20 组，完整来源文件摘要、行号/包序号及全部分组见证据包 traffic.network_observations。", st["body"]))
    if rows:
        out.append(grid_table(["证据/数量", "技术元数据", "来源/归因"], [
            [esc(r["evidence_id"] + " / " + str(r["count"])),
             esc(str(r.get("endpoint") or {k: r.get(k) for k in ("protocol", "src_ip", "src_port", "dst_ip", "dst_port")}) +
                 "; payload=" + str(r.get("payload_visibility"))),
             esc(r["source_artifact"] + ":" + str(r["source_indices"][:8]) +
                 (" …完整索引见证据包" if len(r["source_indices"]) > 8 else "") + "; " + r["attribution"])]
            for r in rows[:20]], st, font))
    for gap in [*(static.get("gaps") or []), *(network.get("gaps") or [])]:
        out.append(Paragraph("- " + esc(str(gap)), st["small"]))
    return out
