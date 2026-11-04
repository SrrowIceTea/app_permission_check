"""报文媒体判据：采集侧（payloads）与解析侧（parse）共用一份。仅用于授权测试。

两边曾各写一份 JSON 判定：`payloads.capture` 认 `+json`，`parse` 的 `JSON_MEDIA`
不认，于是 `application/vnd.api+json`、`text/plain` 返回 JSON 的报文在采集侧能脱敏，
在解析侧却落成 `unparsed_unknown_content_type`，`batch_pairing` 也用不上。
契约写死在这里：

- `application/json` / `text/json` / `application/x-json` / 任意 `... +json` 都是 JSON；
- 没有 Content-Type 或 `text/plain` 时，正文以 `{` / `[` 开头按 JSON 处理（许多
  服务端把 JSON 回成 text/plain；不嗅探就会把可解析正文记成未知类型）；
- `text/plain` 的非 JSON 正文仍按文本脱敏，不结构化解析。
"""
from __future__ import annotations

JSON_BASE = frozenset({"application/json", "text/json", "application/x-json"})
FORM_MEDIA = "application/x-www-form-urlencoded"
PLAIN_MEDIA = "text/plain"


def media_type(content_type) -> str:
    return (content_type or "").split(";", 1)[0].strip().lower()


def is_json_media(content_type) -> bool:
    media = media_type(content_type)
    return media in JSON_BASE or media.endswith("+json")


def is_json_text(content_type, text: str) -> bool:
    """正文是否应按 JSON 解析；`text` 必须是完整正文。"""
    media = media_type(content_type)
    if is_json_media(media):
        return True
    if not media or media == PLAIN_MEDIA:
        return (text or "").lstrip()[:1] in ("{", "[")
    return False
