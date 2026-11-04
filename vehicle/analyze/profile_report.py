"""Vehicle scenario/profile appendix. Authorized tests only."""
from xml.sax.saxutils import escape
from reportlab.platypus import PageBreak, Paragraph, Spacer


def profile_story(summary, body, heading):
    profile = summary.get('vehicle_profile')
    if not profile:
        return []
    story = [PageBreak(), Paragraph('七、车载场景与证据覆盖', heading)]
    general = summary.get('general_privacy')
    if general:
        story.append(Paragraph(escape('通用隐私来源返回值状态：' + str(general['states'])), body))
        for dtype, states in general['by_data_type'].items():
            story.append(Paragraph(escape(dtype + '：' + str(states)), body))
        for gap in general['caveats']:
            story.append(Paragraph(escape(gap), body))
    for gap in summary.get('capture_validation', {}).get('gaps', []):
        story.append(Paragraph(escape('采集范围：' + gap), body))
    chain = summary.get('coverage_chain', {})
    if chain:
        story.append(Paragraph(escape('尚未接入的类别：' + '、'.join(chain['unconnected_types']) +
                                     '；完整覆盖链见 coverage/coverage.json。'), body))
    static = summary.get('static_analysis', {})
    story.append(Paragraph(escape('静态核对：' + static.get('status', 'not_requested') + '；' +
        (str(static.get('findings')) + ' 条候选，候选不证明实际采集。' if static.get('status') == 'completed'
         else static.get('reason', '未提供装机版本对应 APK。'))), body))
    story.append(Paragraph(escape('已观测用户 ID：' + ', '.join(map(str, profile['users']))), body))
    for scenario in profile['scenarios']:
        text = (f"场景 {scenario.get('id')}：成功读取事件 {scenario['successful_read_events']} 条，"
                f"捕获流 {scenario['captured_flows']} 条。")
        story.append(Paragraph(escape(text), body))
        story.append(Paragraph(escape(str(scenario.get('context', {}))), body))
        for hint in scenario['review_hints']:
            story.append(Paragraph(escape(hint['rule_id'] + '：' + hint['note']), body))
    story.append(Spacer(1, 8))
    story.append(Paragraph('采集频率按属性及 API 分组；主机收包频率不等于传感器采样率。', body))
    for row in profile['sampling']:
        text = (f"{row['property']} / {row['api']}：{row['samples']} 条成功时间样本，"
                f"观测跨度 {row['host_span_ms']} ms；结果 {row['outcomes']}。")
        story.append(Paragraph(escape(text), body))
    story.append(Spacer(1, 8))
    story.append(Paragraph('复核排序（实验性工程权重；非风险概率，未用专家标注校准）', body))
    for row in summary.get('review_order', []):
        story.append(Paragraph(escape(f"{row['finding_id']} / {row['rule_id']}："
            f"关注分 {row['attention_score']}；证据 {row['evidence_confidence']}；"
            f"UID 核验 {row['identity_verified']}。"), body))
    ai = summary.get('ai_review', {})
    policy = summary.get('policy_assessment', {})
    if policy:
        story.append(Paragraph(escape('政策复核状态：' + policy['status']), body))
        for row in policy.get('reviews', []):
            story.append(Paragraph(escape(f"{row['finding_id']}：{row['disclosure_signal']}；"
                '必要性需人工复核。'), body))
            for reference in row['policy_refs'][:2]:
                story.append(Paragraph(escape(f"policy/policy.txt 字符 {reference['start']}–"
                    f"{reference['end']}：{reference['text']}"), body))
        for gap in policy.get('gaps', []):
            story.append(Paragraph(escape(gap), body))
    story.append(Spacer(1, 8))
    story.append(Paragraph('AI 研判状态：' + escape(ai.get('status', 'not_requested')), body))
    if ai.get('reason'):
        story.append(Paragraph(escape(ai['reason']), body))
    for review in ai.get('reviews', []):
        story.append(Paragraph(escape(f"{review['finding_id']} / {review['review_priority']}：{review['hint']}"), body))
    for caveat in profile['caveats']:
        story.append(Paragraph(escape(caveat), body))
    return story
