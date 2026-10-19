#!/usr/bin/env python3
"""隐私政策获取 —— 三种来源，全部把「原始字节 + 抽取正文 + 来源元数据」一起落盘。

仅用于授权测试（已获授权的样本与设备）。

三种来源：
    1) --url URL        直接抓（政策页本身，或应用商店详情页——会自动发现政策链接）
    2) --file PATH      本地导入（人工下载的 HTML/文本）
    3) --from-apk APK   从 APK 内部提取（assets/res 里的政策页）——**离线、最可靠**

关于"联网寻找"的诚实说明（重要）：
    本模块**不猜测各应用商店的页面结构**。原因：那种代码在没网、没法实测的环境里
    写出来就是编造——选择器猜错了，症状是"没找到政策链接"，与"这个应用真的没有
    政策"无法区分（本项目反复踩的静默失败）。所以走两条路：
      * 通用链接发现：把页面上所有链接按关键词打分，取最像政策的那条再抓一次。
        它不依赖任何站点特定结构，对"商店详情页里有政策入口"这一常见形态有效。
      * 显式给出：--url 直接给政策地址，或用 --sources 指定 包名→URL 映射表。
    两条都失败时**如实报 not_found**，不产出空政策——空政策会让下游把
    "没抓到"读成"这个 App 没有隐私政策"。

来源元数据必须落盘（url / 抓取时间 / sha256 / HTTP 状态），
否则报告里的"政策原文"无法回溯到它当时到底是什么。
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parents[1]))
import policy_extract  # noqa: E402
import policy_discover  # noqa: E402

try:      # aapt2 用来从资源表挖政策 URL；SDK 不在就退化为"只找内嵌正文"
    from core import sdk_paths  # noqa: E402
    _AAPT2 = str(sdk_paths.sdk_dir("build-tools", "36.1.0") / "aapt2.exe")
except Exception:  # noqa: BLE001
    _AAPT2 = "aapt2"

UA = ("Mozilla/5.0 (Linux; Android 15) AppleWebKit/537.36 (KHTML, like Gecko) "
      "Chrome/120.0 Mobile Safari/537.36 VScannerMobile/1.0 (authorized-testing)")
MAX_BYTES = 4 * 1024 * 1024
TIMEOUT_S = 25

POLICY_HINTS = ["privacy", "policy", "yinsi", "zhengce", "agreement", "terms",
                "隐私", "政策", "协议", "个人信息保护"]

# 旧「按扩展名筛选」路径的常量：extract_from_apk 改用 policy_discover 后**不再引用**，
# 保留是为了让退回旧实现的人拿到收紧后的正确取值（去掉 .json、去掉「用户协议」）。
# 新的筛选规则在 policy_discover.POLICY_WORDS / _SKIP / iter_text_entries，改那边才生效。
APK_CANDIDATE_RE = re.compile(r"\.(html?|txt|md)$", re.IGNORECASE)
APK_POLICY_WORDS = ["隐私政策", "隐私保护指引", "个人信息保护政策", "privacy policy"]


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
        # /<owner>/<repo>/blob/<ref>/<path...> -> raw.githubusercontent.com/<owner>/<repo>/<ref>/<path...>
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


def extract_from_apk(apk: Path, *, limit: int = 5) -> list[dict]:
    """从 APK 内部找政策正文。离线可用，通常是**最可靠的来源**。

    2026-10-19 起改用 `policy_discover`：不再靠扩展名（`res/raw/privacy` 没有扩展名），
    改为目录白名单 + 内容嗅探；否则 4/60 个内嵌政策的样本会被误报 not_found。

    返回的每条都带 `doc_kind`：`"privacy"`（主政策）或 `"agreement"`（用户协议/服务协议）。
    两类都收，但顺序固定为**主政策在前**；只有 `doc_kind == "privacy"` 的条目才能当隐私政策用。
    JSON 设置、词库、许可证仍一律排除（由 `policy_discover` 的 `_SKIP` 与内容嗅探落地）。
    """
    if not apk.exists():
        return []
    found = []
    for item in policy_discover.find_in_apk(apk):
        ex = policy_extract.extract(item["bytes"], content_type="text/html",
                                    source=f"apk:{item['entry']}")
        if ex["chars"] < policy_extract.MIN_USEFUL_CHARS:
            continue
        found.append({**item, "extract": ex})
    # 先按 doc_kind（privacy=0 < agreement=1），再按正文长度：协议再长也不能抢到主政策前面。
    found.sort(key=lambda x: (0 if x.get("doc_kind") == "privacy" else 1,
                              -x["extract"]["chars"]))
    return found[:limit]


def save(store_dir: Path, *, raw: bytes, extract: dict, meta: dict, tag: str) -> dict:
    store_dir.mkdir(parents=True, exist_ok=True)
    (store_dir / f"policy-{tag}.raw").write_bytes(raw)
    # Hash exactly the UTF-8 bytes persisted; write_text translated LF to CRLF on Windows.
    text_bytes = extract["text"].encode("utf-8")
    (store_dir / f"policy-{tag}.txt").write_bytes(text_bytes)
    record = {**meta, "tag": tag, "raw_sha256": sha256(raw),
              "text_chars": extract["chars"], "text_sha256": sha256(text_bytes),
              "extract_status": extract["status"], "extract_path": extract.get("path"),
              "cjk_ratio": extract.get("cjk_ratio"), "title": extract.get("title"),
              "raw_file": f"policy-{tag}.raw", "text_file": f"policy-{tag}.txt",
              "saved_at": time.strftime("%Y-%m-%dT%H:%M:%S")}
    (store_dir / f"policy-{tag}.meta.json").write_text(
        json.dumps(record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return record


def resolve(package: str, sources_path: Path | None) -> str | None:
    if not sources_path or not sources_path.exists():
        return None
    data = json.loads(sources_path.read_text(encoding="utf-8"))
    entry = (data.get("packages") or {}).get(package)
    if isinstance(entry, str):
        return entry
    if isinstance(entry, dict):
        return entry.get("url")
    return None


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--url")
    src.add_argument("--file")
    src.add_argument("--from-apk")
    ap.add_argument("--package", default=None, help="与 --sources 配合解析政策地址")
    ap.add_argument("--sources", default=None, help="包名→政策 URL 的映射表 JSON")
    ap.add_argument("--store", default="policy-store")
    ap.add_argument("--tag", default=None)
    ap.add_argument("--aapt2", default=_AAPT2,
                    help="aapt2 可执行文件；用于从资源表挖政策 URL（缺省走 SDK 路径）")
    ap.add_argument("--follow-discovered", action="store_true",
                    help="在给定页面上发现政策链接并跟进抓取（商店详情页用）")
    args = ap.parse_args()

    store_dir = Path(args.store)
    result: dict = {"status": None, "records": [], "candidates": [], "errors": []}

    if args.package and args.sources and not args.url:
        resolved = resolve(args.package, Path(args.sources))
        if resolved:
            args.url = resolved
        else:
            result["errors"].append(f"sources 表里没有 {args.package}")

    if args.file:
        p = Path(args.file)
        if not p.exists():
            sys.exit(f"[fatal] 文件不存在: {p}")
        raw = p.read_bytes()
        ex = policy_extract.extract(raw, source=f"file:{p.name}")
        rec = save(store_dir, raw=raw, extract=ex, tag=args.tag or p.stem,
                   meta={"source_kind": "file", "source": str(p), "url": None})
        result["status"] = "ok" if ex["status"] == "ok" else ex["status"]
        result["records"].append(rec)

    elif args.from_apk:
        apk_path = Path(args.from_apk)
        found = extract_from_apk(apk_path)
        if not found:
            # 第二步：APK 不内嵌正文时，从资源表挖"应用自己的政策链接"再抓。
            # 这是 2026-10-19 之前完全没有的路径——14 个样本 100% not_found，
            # 而其中好几个的资源里明明写着政策地址。
            urls = policy_discover.mine_policy_urls(apk_path, args.aapt2)
            result["candidates"] = urls
            result["tried"] = {"apk_assets": "no_match", "resource_urls": len(urls)}
            privacy_ref = False
            for ui, u in enumerate(urls[:2], 1):
                got = fetch_url(u)
                if not got["ok"]:
                    result["errors"].append(f"抓取 {u} 失败：{got['error']}")
                    continue
                ex = policy_extract.extract(got["bytes"],
                                            content_type=got["content_type"],
                                            source=got["final_url"])
                # 资源表里的链接可能是《用户协议》——同样归类，不直接当政策。
                kind = policy_discover.classify(ex.get("text") or "") or "privacy"
                rec = save(store_dir, raw=got["bytes"], extract=ex,
                           tag=f"{args.tag or 'apk'}-ref{ui}",
                           meta={"source_kind": "apk_referenced_url",
                                 "source": got["final_url"], "url": got["final_url"],
                                 "referenced_from": str(apk_path),
                                 "http_status": got["status"],
                                 "content_type": got["content_type"],
                                 "truncated": got["truncated"],
                                 "document_kind": ("app_policy" if kind == "privacy"
                                                   else "app_agreement")})
                result["records"].append(rec)
                if ex["status"] == "ok" and kind == "privacy":
                    privacy_ref = True
                    break
            if not result["records"]:
                result["status"] = "not_found"
                result["errors"].append(
                    "APK 内未找到政策正文，资源表里也没有可抓取的政策链接"
                    "（这不等于该应用没有政策；政策可能只在启动页动态下发）")
            elif not privacy_ref:
                result["status"] = "agreement_only"
                result["errors"].append(
                    "资源表里只抓到用户协议/服务协议，没有隐私政策："
                    "协议不能替代隐私政策（已入库为 document_kind=app_agreement）")
        if found:
            kinds = [i.get("doc_kind") or "privacy" for i in found]
            result.setdefault("tried", {})["apk_assets"] = (
                f"{len(found)} 条（privacy {kinds.count('privacy')} / "
                f"agreement {kinds.count('agreement')}）")
        for i, item in enumerate(found, 1):
            kind = item.get("doc_kind") or "privacy"
            rec = save(store_dir, raw=item["bytes"], extract=item["extract"],
                       tag=args.tag or f"apk{i}",
                       meta={"source_kind": "apk_asset", "source": args.from_apk,
                             "apk_entry": item["entry"], "url": None,
                             "document_kind": ("app_policy" if kind == "privacy"
                                               else "app_agreement")})
            result["records"].append(rec)
        if any((i.get("doc_kind") or "privacy") == "privacy" for i in found):
            result["status"] = "ok"
        elif found:
            # 只有协议：如实报 agreement_only，不冒充"已有隐私政策"。
            result["status"] = "agreement_only"
            result["errors"].append(
                "APK 内只有用户协议/服务协议，没有隐私政策正文：协议不能替代隐私政策，"
                "披露比对与过度收集判定仍不可用（协议已入库，document_kind=app_agreement）")

    else:
        first = fetch_url(args.url)
        if not first["ok"]:
            result["status"] = "fetch_failed"
            result["errors"].append(first["error"])
        else:
            ex = policy_extract.extract(first["bytes"], content_type=first["content_type"],
                                        source=first["final_url"])
            rec = save(store_dir, raw=first["bytes"], extract=ex, tag=args.tag or "url",
                       meta={"source_kind": "url", "source": first["final_url"],
                             "url": first["final_url"], "http_status": first["status"],
                             "content_type": first["content_type"],
                             "truncated": first["truncated"]})
            result["records"].append(rec)
            result["status"] = "ok" if ex["status"] == "ok" else ex["status"]
            if ex["status"] != "ok" or args.follow_discovered:
                html = first["bytes"].decode("utf-8", errors="ignore")
                links = discover_policy_links(html, first["final_url"])
                result["candidates"] = links
                if args.follow_discovered and links:
                    second = fetch_url(links[0]["url"])
                    if second["ok"]:
                        ex2 = policy_extract.extract(second["bytes"],
                                                     content_type=second["content_type"],
                                                     source=second["final_url"])
                        rec2 = save(store_dir, raw=second["bytes"], extract=ex2,
                                    tag=(args.tag or "url") + "-followed",
                                    meta={"source_kind": "url_discovered",
                                          "source": second["final_url"],
                                          "discovered_from": first["final_url"],
                                          "link_text": links[0]["text"],
                                          "http_status": second["status"],
                                          "content_type": second["content_type"],
                                          "truncated": second["truncated"]})
                        result["records"].append(rec2)
                        result["status"] = "ok" if ex2["status"] == "ok" else ex2["status"]
                    else:
                        result["errors"].append(f"跟进抓取失败: {second['error']}")

    print(json.dumps(result, ensure_ascii=False, indent=2))
    # 退出码：0 拿到可用正文；2 拿到页面但正文不可用；3 完全没拿到
    if any(r["extract_status"] == "ok" for r in result["records"]):
        return 0
    return 2 if result["records"] else 3


if __name__ == "__main__":
    raise SystemExit(main())
