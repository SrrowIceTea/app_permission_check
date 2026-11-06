"""归属信息、规则覆盖与载荷证据截图。仅用于授权测试。"""
import hashlib
import json
import os
from pathlib import Path
from xml.sax.saxutils import escape

from PIL import Image as Raster, ImageDraw, ImageFont
from reportlab.platypus import Image, PageBreak, Paragraph, Spacer
from core.io_utils import load_jsonl
from vehicle.pipeline.evidence_manifest import ref_path, verify_document

# 中文字体候选表（**全项目车载侧唯一一份**，report.py 从这里 import）。
# 早先 report.py 只有 SimHei/DengXian、这里只有 雅黑/SimHei，两处各写一份且不一致——
# 换机时改一处漏一处（§8.2 B-2）。合并后顺序即优先级：SimHei → DengXian → 雅黑。
# 换机不想改代码时用 VSCAN_CJK_FONT=<ttf/ttc 路径> 覆盖，它排在最前。
FONT_CANDIDATES = [
    ("SimHei", r"C:\Windows\Fonts\simhei.ttf"),
    ("DengXian", r"C:\Windows\Fonts\Deng.ttf"),
    ("MicrosoftYaHei", r"C:\Windows\Fonts\msyh.ttc"),
]
if os.environ.get("VSCAN_CJK_FONT"):
    FONT_CANDIDATES.insert(0, ("CustomCJK", os.environ["VSCAN_CJK_FONT"]))

_RASTER_FONTS: dict = {}


def load_report_evidence(args):
    summary = json.loads(Path(args.summary).read_text(encoding='utf-8'))
    base = Path(args.summary).resolve().parent
    verify_document(summary, rules=args.rules, findings=args.findings, flows=args.flows, base=base)
    flow_path = args.flows
    sealed = summary.get('evidence_artifacts')
    if flow_path is None and sealed:
        flow_path = ref_path(summary['input_completeness']['inputs']['flows'], base)
    flows = load_jsonl(flow_path)
    if sealed:
        flows = [flow for flow in flows if flow.get('package') == summary['package']
                 and flow.get('session_id') == summary['session_id']]
    return load_jsonl(args.findings), summary, flows


def fingerprint_rows(summary):
    if not summary.get('evidence_artifacts'):
        return []
    inputs = summary['input_completeness']
    return [
        ['证据契约', summary['schema_version']],
        ['覆盖矩阵 SHA-256', summary['coverage_sha']],
        ['证据输入', '齐备' if inputs['complete'] else '；'.join(row['reason'] for row in inputs['missing'])],
        *[[f'{name} SHA-256', row['sha256'] or '缺失'] for name, row in inputs['inputs'].items()],
    ]


def raster_font(size: int):
    """模块级字体缓存：原来每个 flow × 方向都重新 `ImageFont.truetype`（§8.2 B-3），
    一轮几十条流 × 2 个方向就是上百次字体解析。"""
    if size not in _RASTER_FONTS:
        path = next((p for _, p in FONT_CANDIDATES if Path(p).exists()), None)
        _RASTER_FONTS[size] = (ImageFont.truetype(str(path), size) if path
                               else ImageFont.load_default(size=size))
    return _RASTER_FONTS[size]


def footer(canvas, doc):
    canvas.saveState()
    canvas.setFont('Helvetica', 8)
    canvas.setFillColorRGB(.35, .4, .47)
    canvas.drawString(doc.leftMargin, 24, 'V-Scanner | Authorized test evidence')
    canvas.drawRightString(doc.pagesize[0] - doc.rightMargin, 24, 'Page ' + str(doc.page))
    canvas.restoreState()


def payload_images(flow, direction, folder):
    payload = flow.get(direction + '_payload')
    if payload is None:
        text = flow.get(direction + '_preview', '')
        label = 'LEGACY PREVIEW ONLY - full payload unavailable'
        digest = hashlib.sha256(text.encode()).hexdigest()
    else:
        text = payload['text']
        label = 'CAPTURED PAYLOAD (UTF-8 display)'
        if payload.get('retention') == 'redacted':
            label += ' - CREDENTIALS REDACTED'
        if payload.get('text_truncated') or payload.get('raw_truncated'):
            label += ' - TRUNCATED AT CAPTURE LIMIT'
        digest = payload['raw_sha256']
    if not text:
        return []
    try:
        text = json.dumps(json.loads(text), ensure_ascii=False, indent=2)
    except ValueError:
        pass
    # 控制字符不交给字体引擎；可打印内容不做删改。
    text = ''.join(c if c in '\n\t' or ord(c) >= 32 else f'\\x{ord(c):02x}' for c in text)
    font = raster_font(19)
    small = raster_font(15)
    lines = []
    for line in text.expandtabs(4).splitlines():
        current = ''
        for char in line:
            if current and font.getlength(current + char) > 1140:
                lines.append(current)
                current = ''
            current += char
        lines.append(current)
    # Report only the first 160 lines of the persisted display copy.
    omitted = max(0, len(lines) - 160)
    lines = lines[:160]
    if omitted:
        lines.append(f'... {omitted} additional display lines omitted; see source JSONL')
    folder.mkdir(parents=True, exist_ok=True)
    paths = []
    for page, start in enumerate(range(0, len(lines), 40), 1):
        chunk = lines[start:start + 40]
        picture = Raster.new('RGB', (1200, 150 + len(chunk) * 27), '#f5f7fa')
        draw = ImageDraw.Draw(picture)
        draw.text((25, 16), f"FLOW {flow.get('evt_id')} | {direction.upper()} | PART {page}",
                  font=font, fill='#142d4e')
        draw.text((25, 48), label, font=small, fill='#4e5b6b')
        draw.text((25, 76), 'SHA-256: ' + digest, font=small, fill='#4e5b6b')
        for row, line in enumerate(chunk):
            draw.text((25, 116 + row * 27), line, font=font, fill='#182536')
        path = folder / f"flow-{flow.get('evt_id')}-{direction}-{digest[:12]}-{page}.png"
        picture.save(path)
        paths.append(path)
    return paths


def extra_story(summary, flows, ownership, folder, body, heading, findings):
    story = [PageBreak(), Paragraph('五、覆盖范围与接收端归属', heading)]
    parsing = summary.get('inputs', {}).get('parsing', {})
    for side, title in (('request', '请求'), ('response', '响应')):
        if side in parsing:
            stats = parsing[side]
            legacy = stats['by_status'].get('legacy_unrecorded', 0)
            unknown = stats['by_status'].get('invalid_parse_status', 0)
            file_gaps = stats['coverage_gaps'].get('multipart_file_bodies_uninspected', 0)
            story.append(Paragraph(
                f"{title}解析覆盖　已解析 {stats['parsed']} 条，未解析 {stats['unparsed']} 条，"
                f"旧记录缺状态 {legacy} 条，状态无效 {unknown} 条，"
                f"multipart 文件正文未检查 {file_gaps} 条。", body))
    cover = summary.get('coverage', {})
    story.append(Paragraph(escape('规则覆盖：' + json.dumps(cover, ensure_ascii=False)), body))
    story.append(Paragraph('RDAP 提供注册信息，不证明接收服务器的物理位置或实际运营者。', body))
    for item in ownership:
        text = (f"{item['host']} | {item['status']} | 注册组织："
                f"{item.get('registered_organization') or '未知/隐私隐藏'} | 注册国家："
                f"{item.get('registration_country') or '未知'} | 服务器位置："
                f"{item.get('server_location') or '未知'}")
        story.append(Paragraph(escape(text), body))
        source = f"来源：{item.get('source_url', '-')}；查询时间：{item.get('retrieved_at', '-')}"
        story.append(Paragraph(escape(source), body))
        if item.get('geolocation'):
            geo = item['geolocation']
            story.append(Paragraph(escape('IP 地理估计来源：' + json.dumps(geo, ensure_ascii=False)), body))
        if item.get('error'):
            story.append(Paragraph(escape(item['error']), body))
    story.extend([PageBreak(), Paragraph('六、敏感载荷明文证据截图', heading)])
    if summary.get('owntracks_location'):
        story.append(Paragraph('OwnTracks 定位证据仅展示事件引用与关联结果，报告不附坐标正文截图。', body))
        return story
    referenced = {(p.get('flow_src', 'proxy'), p['flow_event_id'])
                  for f in findings for p in f.get('pairs', [])}
    selected = [f for f in flows if (f.get('src', 'proxy'), f.get('evt_id')) in referenced
                or f.get('request_tags')]
    if not selected:
        story.append(Paragraph('本次没有可展示的流；不使用示意载荷代替实测证据。', body))
    for flow in selected:
        story.append(Paragraph(escape(f"流 #{flow.get('evt_id')} · {flow.get('package')} · "
                                      f"{flow.get('method')} {flow.get('host')}{flow.get('path')}"), body))
        for direction in ('request', 'response'):
            for path in payload_images(flow, direction, folder):
                with Raster.open(path) as picture:
                    width, height = picture.size
                target_width = 480
                story.append(Image(str(path), width=target_width,
                                   height=height * target_width / width))
                story.append(Spacer(1, 8))
    # A trailing Spacer can spill onto a blank page before the next appendix's
    # PageBreak. It carries no evidence and should not create an empty page.
    if story and isinstance(story[-1], Spacer):
        story.pop()
    return story
def evidence_summary(summary):
    counts = summary.get('evidence_counts', {})
    names = (('manifest_permission_candidates', '清单权限候选'), ('runtime_read_findings', '运行时读取'),
             ('runtime_content_correlations', '运行时内容关联'), ('static_candidates', '静态候选'))
    lines = [f"{label} {counts[key] if counts[key] is not None else '未评估'}"
             for key, label in names if key in counts]
    if abs_send := summary.get('abs_native_send'):
        lines.append(f"YAABSA 隔离回环请求 {abs_send['verified_requests']} 条已验证发送身份，"
                     f"{abs_send['unresolved_requests_discarded']} 条归因未解决")
    if owntracks := summary.get('owntracks_location'):
        lines.append(f"OwnTracks 侧载对照 {owntracks['callback_events']} 条定位回调，"
                     f"{owntracks['matched_requests']} 条 HTTP 请求满足同值候选条件。")
    return '<br/>'.join([f"发现记录共 {summary['findings_total']} 条。", *lines]) + '<br/>'
