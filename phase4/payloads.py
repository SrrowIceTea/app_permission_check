"""保留请求/响应原始字节及摘要；仅用于授权测试。"""
import base64
import hashlib

LIMIT = 1024 * 1024


def capture(message):
    raw = message.raw_content or b'' if message is not None else b''
    # raw_content 保留原始传输编码；content 是 mitmproxy 解码后的内容。
    try:
        decoded = message.content or b'' if message is not None else b''
        error = None
    except Exception as exc:
        decoded, error = raw, str(exc)
    return {'raw_base64': base64.b64encode(raw[:LIMIT]).decode(),
            'raw_sha256': hashlib.sha256(raw).hexdigest(), 'raw_bytes': len(raw),
            'raw_truncated': len(raw) > LIMIT,
            'text': decoded[:LIMIT].decode('utf-8', errors='replace'),
            'text_truncated': len(decoded) > LIMIT, 'decode_error': error}
