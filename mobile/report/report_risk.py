"""Compact deterministic per-APK score section; model opinion cannot alter this score."""
from report_common import Paragraph, esc, grid_table, kv_table


def section_risk(bundle, st, font):
    risk = bundle.get('risk_assessment')
    out = [Paragraph('1.5 应用量化风险信号（固定算法，与 AI 总评分开）', st['h2'])]
    if not risk:
        out.append(Paragraph('此证据包未计算版本化应用风险分；不将缺失评分显示为 0 或安全。', st['warn']))
        return out
    score = risk.get('score')
    out.append(kv_table([
        ('风险信号分', '未知' if score is None else f'{score}/100 · {risk.get("level")}'),
        ('方法版本', esc(risk.get('method_version')) + ' / ' + esc(risk.get('adapter_version'))),
        ('证据范围', esc(risk.get('summary'))),
        ('评分规则', '单项=4×可能性×影响；取最高项，不按权限数量累加；25–59 中、60–100 高。AI 不修改分值。'),
    ], st, font))
    rows = [[esc(d['label']), '未知' if d['score'] is None else str(d['score']),
             esc(d['status']), str(d['findings_count'])] for d in risk.get('dimensions', [])]
    out.append(grid_table(['维度', '风险信号分', '证据状态', '信号项数'], rows, st, font))
    for signal in sorted(risk.get('findings', []), key=lambda s: -s['score'])[:8]:
        out.append(Paragraph(esc(signal['id']) + '：' + str(signal['score']) + ' 分；' +
            esc(signal['evidence_strength']) + '；证据 ' + esc(', '.join(signal['evidence_refs'])) +
            '。' + esc(signal['rationale']), st['small']))
    out.append(Paragraph('完整逐项权重与证据见 risk_assessment.findings。存储 API 写入不等于磁盘持久化；'
        '缺政策/无目标流量的维度仍未知。分值是本项目复核优先级，不是法律结论、官方 OWASP/CVSS 分或安全认证。', st['small']))
    return out
