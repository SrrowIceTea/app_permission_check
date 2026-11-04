"""Remove known credential fields before writing evidence. 仅用于授权测试。"""
import hashlib
import json
import re
from urllib.parse import unquote, unquote_plus

REDACTED = '[REDACTED]'
_KEYS = {
    'token', 'access_token', 'refresh_token', 'password', 'authorization',
    'proxy_authorization', 'auth', 'secret', 'api_key', 'apikey', 'passwd',
    'webhook_secret', 'cookie', 'set_cookie', 'client_secret', 'id_token',
    'x_api_key', 'x_auth_token', 'x_access_token', 'session_token', 'session_id',
}
_NORMALIZED_KEYS = {key.replace('_', '') for key in _KEYS}

_WEBHOOK = re.compile(r"""((?:/|%2f)api(?:/|%2f)webhook(?:/|%2f))([^/?#\s"'<>\\]+)""", re.I)
_FINGERPRINT = re.compile(r'sha256:[a-f0-9]{16}')
_USERINFO = re.compile(r"""((?:https?|wss?)://)[^/?#\s<>"']+@""", re.I)
_QUERY = re.compile(r"""([?&;])([^=&#\s;?]+)=([^&#\s;"'<>]*)""")
_FORM = re.compile(r'(?m)^([\w%.-]+)=([^&#;\r\n]*)')
_STRING = r'"(?:\\.|[^"\\])*"'
_JSON_STRING_PAIR = re.compile(r'(' + _STRING + r')(\s*:\s*)(' + _STRING + r')')
_HEADER = re.compile(r'(?im)^([ \t]*)([\w-]+)[ \t]*:[ \t]*([^\r\n]*)')


def sensitive_key(key):
    return unquote_plus(key).casefold().replace('-', '').replace('_', '') in _NORMALIZED_KEYS


def redact_path(path):
    """Preserve public route markers and a stable fingerprint for a HA webhook."""
    if not isinstance(path, str):
        return path

    def webhook(match):
        value = unquote(match[2])
        fingerprint = 'sha256:' + hashlib.sha256(value.encode('utf-8')).hexdigest()[:16]
        return match[1] + (value if _FINGERPRINT.fullmatch(value) else fingerprint)

    def query(match):
        return match[1] + match[2] + '=' + REDACTED if sensitive_key(match[2]) else match[0]

    path = _USERINFO.sub(lambda m: m[1] + REDACTED + '@', path)
    return _QUERY.sub(query, _WEBHOOK.sub(webhook, path))


def redact_text(text, *, form=False):
    """Scrub URL, header and credential key/value syntax in text or logs."""
    if not isinstance(text, str):
        return text

    def form_pair(pair):
        key, sep, value = pair.partition('=')
        if not sep:
            return redact_path(pair)
        if sensitive_key(key):
            return key + sep + REDACTED
        decoded = unquote_plus(value)
        return key + sep + (value if redact_text(decoded) == decoded else REDACTED)

    if form:
        return '&'.join(map(form_pair, text.split('&')))

    def json_pair(match):
        try:
            key = json.loads(match[1])
        except ValueError:
            return match[0]
        return match[1] + match[2] + json.dumps(REDACTED) if sensitive_key(key) else match[0]

    text = _JSON_STRING_PAIR.sub(json_pair, text)
    text = redact_path(text)
    text = _FORM.sub(lambda m: m[1] + '=' + REDACTED if sensitive_key(m[1]) else m[0], text)
    return _HEADER.sub(lambda m: m[1] + m[2] + ': ' + REDACTED if sensitive_key(m[2]) else m[0], text)


def redact_json(text):
    """Parse complete JSON so escaped names, nested and non-string values are scrubbed."""
    changed = False

    def scrub(value):
        nonlocal changed
        if isinstance(value, str):
            clean = redact_text(value)
            changed |= clean != value
            return clean
        if isinstance(value, list):
            return [scrub(item) for item in value]
        return value

    def object_pairs(pairs):
        nonlocal changed
        clean = {}
        for key, value in pairs:
            if sensitive_key(key):
                # An earlier duplicate in the source may still contain a credential.
                changed = True
                clean[key] = REDACTED
            else:
                clean[scrub(key)] = scrub(value)
        return clean

    clean = scrub(json.loads(text, object_pairs_hook=object_pairs))
    return json.dumps(clean, ensure_ascii=True) if changed else text
