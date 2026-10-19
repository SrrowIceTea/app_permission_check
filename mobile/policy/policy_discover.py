#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""从 APK 里找隐私政策的**素材发现**（只找，不抓、不存）。

仅用于授权测试（已获授权的样本）。

## 为什么单独成文件

`policy_fetch.py` 已经 270 行，而"发现"和"抓取/落盘"改动的理由完全不同：

* 发现：遍历 zip 条目、挖资源表里的 URL —— 纯离线，可单测；
* 抓取：走网络，受可达性影响，要落盘并记来源。

## 两种来源（2026-10-19 补齐）

1. **内嵌正文**：`assets/**`、`res/raw/**` 里的 HTML/TXT。
   旧实现只认扩展名（`.html/.txt/.md/.json`），而 AAPT 会把 `res/raw/privacy`
   原样打包（**没有扩展名**）——实测 4 个样本因此被漏掉。
   现在按目录白名单 + 内容嗅探，不再依赖扩展名。

2. **外链 URL**：很多 App 不内嵌正文，只在 `strings.xml` 里放一个政策链接。
   用 `aapt2 dump resources` 拿到资源表里的字符串，按关键词筛出政策 URL，
   交给调用方去抓。实测本数据集 60 个样本里 6 个属于这一类；
   剩下 50 个两者都没有——那是样本属性，不是提取失败，必须如实报 not_found。
"""
from __future__ import annotations

import re
import subprocess
import zipfile
from pathlib import Path

MAX_BYTES = 4 * 1024 * 1024

# 隐私政策词：命中即归为**主政策**（primary）候选。
# 中英为主，兼顾德/法/西（F-Droid 样本大量是欧洲应用）。
POLICY_WORDS = (
    "隐私政策", "隐私保护", "隐私保护指引", "个人信息保护", "个人信息保护政策",
    "privacy policy", "privacy notice", "data protection",
    "datenschutz", "politique de confidentialité", "política de privacidad",
)

# 协议/条款词：命中即归为**应用协议**（app_agreement）候选。
# 2026-10-19 起不再丢弃——很多 App 把数据条款写在《用户协议》里，审计需要它，
# 但它**不能替代隐私政策**：披露比对、过度收集判定仍只认主政策。
# 归类规则见 `classify()`：同时含隐私词时算主政策（合并版文档就是政策）。
AGREEMENT_WORDS = (
    "用户协议", "服务协议", "使用协议", "用户服务协议", "软件许可及服务协议",
    "个人信息授权协议", "terms of service", "terms of use", "user agreement",
    "end user license agreement", "eula",
)

# URL 关键词：命中任一即视为"像政策页面"。
URL_HINTS = re.compile(r"privacy|policy|yinsi|zhengce|datenschutz|confidentialit|"
                       r"privacidad|terms|agreement|eula", re.I)

_URL_RE = re.compile(r"https?://[^\s\"'<>\\]+", re.I)

# 这些条目一定不是政策正文（许可证、第三方库说明）。
_SKIP = re.compile(r"(^|/)(LICENSE|NOTICE|COPYING|COPYRIGHT|AUTHORS?)(\.|$)|"
                   r"^META-INF/|\.(so|dex|png|jpe?g|webp|ttf|otf|zip|gz|mp3|mp4)$", re.I)


def classify(head: str) -> str | None:
    """按正文判断文档类型：`"privacy"` / `"agreement"` / `None`。

    隐私词优先：一份文档既写"隐私政策"又写"用户协议"时按主政策处理（合并版文档）。
    """
    low = head.lower()
    if any(w.lower() in low for w in POLICY_WORDS):
        return "privacy"
    if any(w.lower() in low for w in AGREEMENT_WORDS):
        return "agreement"
    return None


def _looks_like_policy(head: str) -> bool:
    return classify(head) is not None


def iter_text_entries(apk: Path):
    """遍历 APK 里**可能承载政策正文**的条目，产出 (name, bytes)。

    目录白名单：`assets/`、`res/raw/`；另外保留根目录下的 .html/.txt/.md。
    单条上限 4 MB（政策正文不会更大；更大的多半是模型/词库）。
    """
    with zipfile.ZipFile(apk) as zf:
        for info in zf.infolist():
            name = info.filename
            if info.is_dir() or info.file_size == 0 or info.file_size > MAX_BYTES:
                continue
            if _SKIP.search(name):
                continue
            low = name.lower()
            if not (low.startswith("assets/") or low.startswith("res/raw/")
                    or low.endswith((".html", ".htm", ".txt", ".md"))):
                continue
            try:
                raw = zf.read(info)
            except (OSError, RuntimeError, zipfile.BadZipFile):
                continue
            yield name, raw


def find_in_apk(apk: Path, *, include_agreements: bool = True) -> list[dict]:
    """内嵌文档候选，按「隐私政策优先、正文更长优先」排序。

    每条带 `doc_kind`：`"privacy"`（主政策）或 `"agreement"`（用户协议/服务协议）。
    调用方必须按 `doc_kind` 分开处理——协议能入库，但不能当主政策用。
    """
    out = []
    for name, raw in iter_text_entries(apk):
        head = raw[:4000].decode("utf-8", errors="ignore")
        # 扩展名不可信：先按内容嗅探，再要求不是二进制
        if not head.strip() or "\x00" in head[:200]:
            continue
        kind = classify(head)
        if kind is None or (kind == "agreement" and not include_agreements):
            continue
        # 主政策永远排在协议前面：后续消费方按顺序取第一条当时不能因此拿错。
        score = 20 if kind == "privacy" else 0
        if re.search(r"privacy|policy|隐私|datenschutz", name, re.I):
            score += 10
        if re.search(r"agreement|terms|protocol|eula|协议", name, re.I) and kind == "agreement":
            score += 5
        if name.lower().startswith("assets/"):
            score += 2
        out.append({"entry": name, "bytes": raw, "score": score,
                    "doc_kind": kind, "source_kind": "apk_asset"})
    out.sort(key=lambda x: (-x["score"], -len(x["bytes"])))
    return out


def mine_policy_urls(apk: Path, aapt2: str | None = None, limit: int = 3) -> list[str]:
    """从资源表里挖政策 URL。`aapt2` 不可用就返回空（不猜）。"""
    exe = aapt2 or "aapt2"
    try:
        p = subprocess.run([exe, "dump", "resources", str(apk)],
                           capture_output=True, text=True, encoding="utf-8",
                           errors="replace", timeout=120)
    except (OSError, subprocess.SubprocessError):
        return []
    if p.returncode != 0:
        return []
    seen, urls = set(), []
    for m in _URL_RE.finditer(p.stdout or ""):
        u = m.group(0).rstrip(".,;)")
        if u in seen or len(u) > 500:
            continue
        seen.add(u)
        if URL_HINTS.search(u):
            urls.append(u)
        if len(urls) >= limit:
            break
    return urls
