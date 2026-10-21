#!/usr/bin/env python3
"""隐私政策抓取的网络层与通用链接发现（从 policy_fetch.py 拆出）。

仅用于授权测试（已获授权的样本与设备）。

只负责「抓某个 URL 并如实返回状态 + 页面里挑最像政策的候选链接」，不带任何
站点特定选择器。抓取失败如实返回 error，不抛异常吞掉细节——这样「没抓到」
与「应用没有政策」才不会混为一谈。
"""
from __future__ import annotations

import hashlib
import re
import urllib.error
import urllib.parse
import urllib.request

UA = ("Mozilla/5.0 (Linux; Android 15) AppleWebKit/537.36 (KHTML, like Gecko) "
      "Chrome/120.0 Mobile Safari/537.36 VScannerMobile/1.0 (authorized-testing)")
MAX_BYTES = 4 * 1024 * 1024
TIMEOUT_S = 25

POLICY_HINTS = ["privacy", "policy", "yinsi", "zhengce", "agreement", "terms",
                "隐私", "政策", "协议", "个人信息保护"]


def sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def raw_code_url(url: str) -> str:
    """把「代码托管站的网页浏览地址」换成**直接取正文**的地址（2026-10-19）。

    实测：securecamera 的资源表里写的是
    `https://github.com/<owner>/<repo>/blob/main/PRIVACY.md`，抓回来是 GitHub 的
    浏览页——正文之外还裹着 "Skip to content / Navigation Menu / Sign in / Platform"
    这些导航文案（4766 字里大半是壳）。这些噪声会混进 `policy_mismatch` 的披露比对，
    把"没写在政策里"稀释成"好像提到了"。换 raw 地址后拿到的才是文件本身。

    只改 URL 形状，不改抓取逻辑；不是 GitHub/GitLab 的地址原样返回。
    """
    p = urllib.parse.urlsplit(url)
    host = p.netloc.lower()
    seg = [s for s in p.path.split("/") if s]
    if host in ("github.com", "www.github.com") and len(seg) >= 5 and seg[2] == "blob":
        return urllib.parse.urlunsplit(("https", "raw.githubusercontent.com",
                                        "/" + "/".join(seg[:2] + seg[3:]), "", ""))
    if host in ("gitlab.com", "www.gitlab.com") and "-" in seg and "blob" in seg:
        i = seg.index("-")
        if seg[i + 1:i + 2] == ["blob"]:
            return urllib.parse.urlunsplit(("https", "gitlab.com",
                                            "/" + "/".join(seg[:i] + ["raw"] + seg[i + 2:]), "", ""))
    return url


def fetch_url(url: str, *, timeout: int = TIMEOUT_S) -> dict:
    """抓一个 URL。**失败如实返回状态，不抛异常吞掉细节。**

    先走环境里的代理（若有），失败再**直连**重试一次（2026-10-19）：
    开发机/CI 常注入 `http_proxy=127.0.0.1:xxxx` 的转发代理，它对本机可达、
    对公网域名却经常直接断连（`RemoteDisconnected`）——一次失败就报"抓不到政策"
    会把代理的环境问题记成样本问题。直连也不通时，错误信息里两类原因都保留。
    """
    fetch_from = raw_code_url(url)
    req = urllib.request.Request(fetch_from, headers={"User-Agent": UA,
                                                      "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8"})
    errors = []
    for direct in (False, True):
        if direct:
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            do = lambda: opener.open(req, timeout=timeout)   # noqa: E731
        else:
            do = lambda: urllib.request.urlopen(req, timeout=timeout)   # noqa: E731
        try:
            with do() as resp:
                raw = resp.read(MAX_BYTES + 1)
                truncated = len(raw) > MAX_BYTES
                raw = raw[:MAX_BYTES]
                return {"ok": True, "url": url, "final_url": resp.geturl(),
                        "status": getattr(resp, "status", None),
                        "content_type": resp.headers.get("Content-Type", ""),
                        "bytes": raw, "byte_count": len(raw), "truncated": truncated,
                        "error": None, "via": "direct" if direct else "env-proxy"}
        except urllib.error.HTTPError as e:
            return {"ok": False, "url": url, "final_url": url, "status": e.code,
                    "content_type": "", "bytes": b"", "byte_count": 0, "truncated": False,
                    "error": f"HTTP {e.code} {e.reason}"}
        except Exception as e:  # noqa: BLE001 —— 网络异常种类多，如实记录即可
            errors.append(f"{'直连' if direct else '代理'}: {e.__class__.__name__}: {e}")
    return {"ok": False, "url": url, "final_url": url, "status": None,
            "content_type": "", "bytes": b"", "byte_count": 0, "truncated": False,
            "error": "; ".join(errors)}


def score_link(text: str, href: str) -> int:
    hay = (text + " " + href).lower()
    score = 0
    for hint in POLICY_HINTS:
        if hint in hay:
            score += 2 if hint in text.lower() else 1
    return score


def discover_policy_links(html: str, base_url: str, *, limit: int = 5) -> list[dict]:
    """页面里所有链接按"像不像政策"排序。**通用规则，不含站点特定选择器。**"""
    out = []
    for m in re.finditer(r"<a\b[^>]*href=[\"']([^\"']+)[\"'][^>]*>(.*?)</a>",
                         html or "", re.IGNORECASE | re.DOTALL):
        href, inner = m.group(1), re.sub(r"<[^>]+>", "", m.group(2))
        inner = re.sub(r"\s+", " ", inner).strip()
        s = score_link(inner, href)
        if s <= 0:
            continue
        out.append({"url": urllib.parse.urljoin(base_url, href), "text": inner[:120],
                    "score": s})
    out.sort(key=lambda x: (-x["score"], x["url"]))
    seen, uniq = set(), []
    for item in out:
        if item["url"] in seen:
            continue
        seen.add(item["url"])
        uniq.append(item)
    return uniq[:limit]