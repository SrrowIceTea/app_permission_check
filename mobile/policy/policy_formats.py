"""Decode reviewed public document formats without executing downloaded JavaScript."""
from __future__ import annotations

import html
import json
import re

QQ_DOCUMENT = "application/vnd.vscan.qq-document+json"
BILI_MANIFEST = "application/vnd.vscan.bilibili-manifest+javascript"


def document_html(raw: bytes, content_type: str) -> tuple[str, str] | None:
    """Return HTML only for explicitly selected, validated official document schemas."""
    if content_type == QQ_DOCUMENT:
        payload = json.loads(raw.decode("utf-8"))
        data = payload.get("data")
        if payload.get("code") != 0 or not isinstance(data, dict):
            raise ValueError("Official QQ document API returned no successful document")
        sections = data.get("sections")
        if not isinstance(sections, list) or not sections:
            raise ValueError("Official QQ document has no sections")
        parts = ["<h1>" + html.escape(data["name"]) + "</h1>"]
        for key, label in (("updateTime", "更新日期"), ("effectTime", "生效日期")):
            parts.append("<p>" + label + ":" + html.escape(data.get(key, "")) + "</p>")
        for section in sections:
            if not isinstance(section.get("content"), str):
                raise ValueError("Official QQ document section has no HTML content")
            parts.extend(["<h2>" + html.escape(section.get("title", "")) + "</h2>",
                          section["content"]])
        return "\n".join(parts), "qq_document_sections"
    if content_type == BILI_MANIFEST:
        text = raw.decode("utf-8")
        match = re.match(r"\s*\(function\s*\(\)\s*\{\s*window\."
                         r"__BILIACT_MANIFEST_PLACEHOLDER__(\d+)\s*=\s*", text)
        if not match:
            raise ValueError("Unrecognized official Bilibili manifest wrapper")
        payload, end = json.JSONDecoder().raw_decode(text[match.end():])
        if not re.fullmatch(r"\s*;?\s*\}\)\(\);?\s*", text[match.end() + end:]):
            raise ValueError("Unexpected executable text after official manifest")
        if payload.get("pageid") != int(match[1]):
            raise ValueError("Official Bilibili manifest ID mismatch")
        structure, modules = payload["structure"], payload["modules"]
        parts, seen = [], set()

        def visit(key: str) -> None:
            if key in seen:
                raise ValueError("Cyclic official document structure")
            seen.add(key)
            module = modules[key]
            if module["tag"] == "h5-rich-text2":
                value = module["config"]["htmlObj"]["dangerHtml"]
                if not isinstance(value, str):
                    raise ValueError("Official document HTML is not a string")
                parts.append(value)
            for child in structure[key].get("children", []):
                visit(child)

        visit("root")
        if not parts:
            raise ValueError("Official Bilibili manifest contains no policy HTML")
        return "\n".join(parts), "bilibili_manifest_sections"
    return None
