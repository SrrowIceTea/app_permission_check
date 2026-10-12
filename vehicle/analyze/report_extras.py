"""归属信息、规则覆盖与载荷证据截图。仅用于授权测试。"""
import hashlib
import json
from pathlib import Path
from xml.sax.saxutils import escape

from PIL import Image as Raster, ImageDraw, ImageFont
from reportlab.platypus import Image, PageBreak, Paragraph, Spacer


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
        label = 'CAPTURED PAYLOAD (UTF-8 display; raw bytes retained in JSONL)'
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
    font_path = next((p for p in [Path('C:/Windows/Fonts/msyh.ttc'),
                                 Path('C:/Windows/Fonts/simhei.ttf')] if p.exists()), None)
    font = ImageFont.truetype(str(font_path), 19) if font_path else ImageFont.load_default(size=19)
    small = ImageFont.truetype(str(font_path), 15) if font_path else ImageFont.load_default(size=15)
    lines = []
    for line in text.expandtabs(4).splitlines():
        current = ''
        for char in line:
            if current and font.getlength(current + char) > 1140:
                lines.append(current)
                current = ''
            current += char
        lines.append(current)
    # 报告最多展示前160行；原始JSONL仍保留全部捕获内容。
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
    referenced = {p['flow_event_id'] for f in findings for p in f.get('pairs', [])}
    selected = [f for f in flows if f.get('evt_id') in referenced or f.get('request_tags')]
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
    return story
