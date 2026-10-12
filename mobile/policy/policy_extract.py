#!/usr/bin/env python3
"""隐私政策正文抽取：HTML/文本 → 纯文本 + 抽取状态。

仅用于授权测试（已获授权的样本与设备）。

为什么要单独一个模块并带「状态」：
    "抽出来的正文里没有提到位置信息" 与 "正文压根没抽出来" 在报告里长得一样，
    但前者是判定依据，后者是失败。所以每次抽取都返回 status，
    并如实记录用了哪条路径、丢掉了什么。

边界（必须保留）：这是**保守的正则清洗**，不是 HTML 解析器。
它能处理常见政策页（正文在 body 里、script/style 占大头），
遇到正文由 JS 动态渲染的页面会抽到近乎空的内容——那时 status 会报
`text_too_short`，而不是悄悄给出一个空正文让人误判。
"""
from __future__ import annotations

import re
import unicodedata

# 整块丢弃：脚本、样式、注释、模板。政策正文不会在这些里面。
_DROP_BLOCKS = [
    re.compile(r"<script\b[^>]*>.*?</script>", re.IGNORECASE | re.DOTALL),
    re.compile(r"<style\b[^>]*>.*?</style>", re.IGNORECASE | re.DOTALL),
    re.compile(r"<noscript\b[^>]*>.*?</noscript>", re.IGNORECASE | re.DOTALL),
    re.compile(r"<template\b[^>]*>.*?</template>", re.IGNORECASE | re.DOTALL),
    re.compile(r"<!--.*?-->", re.DOTALL),
]

# 块级标签 → 换行，避免相邻段落黏成一行。
_BLOCK_TAGS = re.compile(
    r"</?(?:p|div|br|li|tr|h[1-6]|section|article|header|footer|table|ul|ol|blockquote)\b[^>]*>",
    re.IGNORECASE)

_TAG = re.compile(r"<[^>]+>")
_TITLE = re.compile(r"<title\b[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_ENTITY = re.compile(r"&(#x?[0-9a-fA-F]+|[a-zA-Z]+);")

_NAMED = {"nbsp": " ", "amp": "&", "lt": "<", "gt": ">", "quot": '"', "apos": "'",
          "ldquo": "“", "rdquo": "”", "lsquo": "‘", "rsquo": "’", "mdash": "—",
          "ndash": "–", "hellip": "…", "middot": "·"}

MIN_USEFUL_CHARS = 200


def _unescape(text: str) -> str:
    def sub(m: re.Match[str]) -> str:
        body = m.group(1)
        if body.startswith("#"):
            try:
                code = int(body[2:], 16) if body[1] in "xX" else int(body[1:])
                return chr(code)
            except (ValueError, OverflowError):
                return m.group(0)
        return _NAMED.get(body.lower(), m.group(0))
    return _ENTITY.sub(sub, text)


def _normalize(text: str) -> str:
    text = unicodedata.normalize("NFKC", text)
    text = text.replace("　", " ")          # 全角空格
    text = re.sub(r"[ \t\f\v]+", " ", text)
    text = re.sub(r"\n\s*\n\s*(\n\s*)+", "\n\n", text)
    return "\n".join(line.strip() for line in text.splitlines()).strip()


def html_to_text(html: str) -> tuple[str, str | None]:
    """→ (正文, title 或 None)。"""
    title = None
    m = _TITLE.search(html or "")
    if m:
        title = _normalize(_unescape(_TAG.sub("", m.group(1)))) or None
    text = html or ""
    for pat in _DROP_BLOCKS:
        text = pat.sub("\n", text)
    text = _BLOCK_TAGS.sub("\n", text)
    text = _TAG.sub("", text)
    text = _unescape(text)
    return _normalize(text), title


def cjk_ratio(text: str) -> float:
    """CJK 字符占比。用于「是否提供简体中文版」这条线索（不是结论）。"""
    if not text:
        return 0.0
    cjk = sum(1 for ch in text if "一" <= ch <= "鿿")
    return cjk / len(text)


def extract(raw: bytes, *, content_type: str = "", source: str = "") -> dict:
    """字节 → {text, title, status, ...}。status 说明这次抽取到底发生了什么。"""
    text_raw = None
    decode_error = None
    for enc in ("utf-8", "utf-8-sig", "gb18030", "big5", "latin-1"):
        try:
            text_raw = raw.decode(enc)
            break
        except UnicodeDecodeError as e:
            decode_error = str(e)
    if text_raw is None:
        return {"text": "", "title": None, "status": "decode_failed",
                "decode_error": decode_error, "source": source,
                "chars": 0, "cjk_ratio": 0.0}

    is_html = ("html" in (content_type or "").lower()
               or re.search(r"<\s*(?:html|body|div|p)\b", text_raw[:4000], re.IGNORECASE) is not None)
    if is_html:
        text, title = html_to_text(text_raw)
        path = "html"
    else:
        text, title = _normalize(text_raw), None
        path = "plain"

    status = "ok"
    if len(text) < MIN_USEFUL_CHARS:
        # 动态渲染页面的典型症状。必须显式报出来，不能让空正文冒充"政策里没写"。
        status = "text_too_short"
    return {"text": text, "title": title, "status": status, "path": path,
            "chars": len(text), "cjk_ratio": round(cjk_ratio(text), 4),
            "raw_bytes": len(raw), "source": source,
            "note": ("正文过短：可能是 JS 动态渲染页面、或抓到的不是政策正文；"
                     "不得据此判定'政策未提及'。" if status != "ok" else None)}
