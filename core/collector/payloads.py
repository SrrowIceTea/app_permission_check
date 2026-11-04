"""Build a bounded persistence copy of HTTP evidence. 仅用于授权测试。"""
import base64
import hashlib
import re

from core.collector.media import (FORM_MEDIA, PLAIN_MEDIA, is_json_media,
                                  is_json_text, media_type)
from core.collector.redaction import redact_json, redact_text

LIMIT = 1024 * 1024
FORM_PREFIX = re.compile(r'^[\w%.-]+=')


def _declared(headers, name):
    """原样记录声明头（含参数），供离线重放复用；没有就记 None。"""
    try:
        value = headers.get(name) if headers is not None else None
    except Exception:  # noqa: BLE001
        return None
    return str(value) if value is not None else None


def capture(message):
    raw = getattr(message, 'raw_content', None)
    headers = getattr(message, 'headers', None)
    result = {'raw_base64': '', 'raw_sha256': hashlib.sha256(raw).hexdigest() if raw is not None else None,
              'raw_bytes': len(raw or b''), 'raw_truncated': len(raw or b'') > LIMIT,
              'text': '', 'text_truncated': False, 'decode_error': None,
              # 报文格式声明是解析判据的一部分：只存正文、不存 Content-Type，离线重放
              # 就只能嗅探，表单正文会被记成 unparsed_unknown_content_type。
              'content_type': _declared(headers, 'content-type'),
              # mitmproxy 的 `content` 已解压；声明编码说明 raw_base64 是压缩态。
              'content_encoding': _declared(headers, 'content-encoding')}

    def omitted(reason):
        return {**result, 'retention': reason}

    if raw is None:
        return omitted('unavailable')
    if result['raw_truncated']:
        return omitted('omitted_size_limit')
    try:
        decoded = message.content or b''
    except Exception:
        result['decode_error'] = 'content_decode_failed'
        return omitted('omitted_decode_error')
    if len(decoded) > LIMIT:
        result['text_truncated'] = True
        return omitted('omitted_size_limit')
    headers = getattr(message, 'headers', None)
    media = media_type(headers.get('content-type', '') if headers is not None else '')
    is_json = is_json_media(media)
    is_form = media == FORM_MEDIA
    if decoded and not (is_json or is_form or media in ('', PLAIN_MEDIA)):
        return omitted('omitted_content_type')
    try:
        text = decoded.decode('utf-8')
    except UnicodeError:
        result['decode_error'] = 'invalid_utf8'
        return omitted('omitted_decode_error')
    if not is_json and not is_form and any(ord(char) < 32 and char not in '\r\n\t' for char in text):
        return omitted('omitted_binary')
    try:
        if text and is_json_text(media, text):
            clean = redact_json(text)
        else:
            clean = redact_text(text, form=is_form or bool(FORM_PREFIX.match(text) and '\n' not in text))
    except (ValueError, RecursionError):
        return omitted('omitted_invalid_json')
    result['text'] = clean
    if clean != text:
        return omitted('redacted')
    if raw != decoded:
        return omitted('decoded_text_only')
    result['raw_base64'] = base64.b64encode(raw).decode('ascii')
    return omitted('unchanged')
