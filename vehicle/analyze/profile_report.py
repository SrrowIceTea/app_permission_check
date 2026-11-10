"""Vehicle scenario/profile appendix. Authorized tests only."""
from datetime import datetime
from xml.sax.saxutils import escape
from reportlab.platypus import PageBreak, Paragraph, Spacer


def _stamp(value):
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        return '时间缺失'
    if value > 1e11:            # 事件库里的 host_received_ts 是毫秒
        value = value / 1000.0
    return datetime.fromtimestamp(value).strftime('%Y-%m-%d %H:%M:%S')


def _evidence_rows(findings):
    index = {}
    for row in findings or []:
        for event in row.get('read_evidence') or []:
            if isinstance(event, dict):
                index.setdefault(row.get('data_type'), []).append((row.get('rule_id'), event))
    return index


def observation_story(summary, findings, body):
    """与工作台共用同一套四态口径（vehicle.webapp.observation），不在报告里另立判据。"""
    from vehicle.webapp.observation import observation
    result = observation(summary, findings or [])
    story = [Paragraph(escape('通用隐私来源观测口径（设备侧，仅本轮）：' + result['note']), body)]
    if result['status'] != 'available':
        story.append(Paragraph(escape(result['reason_text']), body))
        return story
    evidence = _evidence_rows(findings)
    for item in result['data_types']:
        text = '%s：%s（%s）—— %s' % (item['data_type_name'], item['state_label'],
                                     item['reason_code'], item['reason_text'])
        story.append(Paragraph(escape(text), body))
        for rule_id, event in evidence.get(item['data_type'], [])[:5]:
            story.append(Paragraph(escape(
                '    证据 %s ｜ evt %s ｜ collection_state=%s ｜ 值哈希 %s ｜ %s' % (
                    rule_id, event.get('evt_id'), event.get('collection_state'),
                    str(event.get('value_hash') or '无')[:12], _stamp(event.get('host_received_ts')))), body))
    gaps = result['observation_gaps']
    if gaps:
        story.append(Paragraph(escape('Hook 缺口（本轮 %d 条，缺口涉及的 API 未观测到不等于未采集）：' % len(gaps)), body))
        for gap in gaps[:6]:
            story.append(Paragraph(escape('    evt %s ｜ %s ｜ %s' % (
                gap.get('evt_id'), gap.get('where'), str(gap.get('message'))[:180])), body))
        if len(gaps) > 6:
            story.append(Paragraph(escape('    其余 %d 条见 audit/summary.json 的 general_privacy.hook_gaps。'
                                          % (len(gaps) - 6)), body))
    general = summary.get('general_privacy') if isinstance(summary, dict) else None
    for caveat in (general or {}).get('caveats', []):
        if str(caveat).startswith('通用钩子缺口：'):
            continue      # 上面已逐条列出缺口事件，不再重复一句笼统的占位
        story.append(Paragraph(escape('采集范围：' + caveat), body))
    return story


def profile_story(summary, body, heading, findings=None):
    profile = summary.get('vehicle_profile')
    general = summary.get('general_privacy')
    if not profile and not general:
        return []
    story = [PageBreak(), Paragraph('七、车载场景与证据覆盖', heading)]
    story.extend(observation_story(summary, findings, body))
    if not profile:
        story.append(Paragraph(escape(
            '本轮没有 vehicle_profile 产物，本节的场景/采样/复核排序不适用；'
            '这不等于未采集，也不能当作安全。'), body))
        return story
    for gap in summary.get('capture_validation', {}).get('gaps', []):
        if str(gap).startswith('通用钩子缺口：'):
            continue
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
