"""Tag safe payload projections and retain parse diagnostics. 仅用于授权测试。

打标来源必须与**真正被持久化的正文**说得上话。`payloads.capture` 在
text/html、xml、multipart、octet-stream/protobuf 以及超过体积上限时会把
`text` 置空；继续拿 `payload['text']` 打标就会得到"有敏感内容、却零标签"，
而 `scan_basis` 还写 `safe_text`——报告读起来像"扫过没发现"，实际是"没扫"。

因此：持久化正文可用时按旧行为打标（标签可复核）；不可用时对**内存里的原文**
打标保证不漏发现，但 `scan_basis` 记 `unavailable`，绝不写 `safe_text`。
"""
from core.collector.body import MAX_BODY_SCAN, scan_body
from core.collector.parse import parse_body, parse_summary
from core.collector.payloads import capture
from core.collector.redaction import redact_text, sensitive_key

# 正文打标覆盖不到的格式，才额外用结构化字段补标签；JSON 仍走纯文本，
# 保证既有 JSON 流量的 tags/tokens 逐字不变。
FIELD_STATUSES = frozenset({
    'parsed_form', 'parsed_multipart', 'parsed_websocket_text', 'parsed_protobuf_heuristic',
})


def _tag_text(payload, raw_text):
    """(用于打标的文本, scan_basis)。

    `unchanged` / `redacted` / `decoded_text_only` 的 `payload['text']` 是已脱敏
    或原样的持久化正文，与旧行为逐字一致；其余 retention（omitted_*、unavailable）
    说明落盘正文不可用，退回内存原文。
    """
    retention = payload['retention']
    if retention in ('unchanged', 'redacted', 'decoded_text_only'):
        basis = 'raw_text' if retention == 'unchanged' else 'safe_text'
        return payload['text'][:MAX_BODY_SCAN], basis
    return raw_text[:MAX_BODY_SCAN], 'unavailable'


def inspect_body(message, tag_sensitive, tag_fields=None, direction=None, frame_type=None):
    raw_text, scan = scan_body(message)
    payload = capture(message)
    parsed = parse_body(message, content_type=payload['content_type'],
                        content_encoding=payload['content_encoding'],
                        frame_type=frame_type)
    summary = parse_summary(parsed)
    # 方向必须留在摘要里：请求体与响应体走同一套解析层，不能靠调用方记忆区分。
    if direction:
        summary['direction'] = direction
    # Tagging a credential before redaction could duplicate it into a token;
    # 可用时一律用脱敏后的正文，见 _tag_text。
    text, basis = _tag_text(payload, raw_text)
    labels, tokens = tag_sensitive(text)
    summary['scan_basis'] = basis
    if tag_fields and parsed['parse_status'] in FIELD_STATUSES:
        fields = [field for field in parsed['fields'] if isinstance(field['value'], str)
                  and not sensitive_key(field['path']) and redact_text(field['path']) == field['path']
                  and redact_text(field['value']) == field['value']]
        field_labels, field_tokens = tag_fields(fields)
        labels = sorted(set(labels) | set(field_labels))
        tokens = sorted(set(tokens) | set(field_tokens))
        summary['scan_basis'] = 'fields+' + basis
    return scan, summary, labels, tokens
