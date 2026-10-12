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
import policy_extract  # noqa: E402

UA = ("Mozilla/5.0 (Linux; Android 15) AppleWebKit/537.36 (KHTML, like Gecko) "
      "Chrome/120.0 Mobile Safari/537.36 VScannerMobile/1.0 (authorized-testing)")
MAX_BYTES = 4 * 1024 * 1024
TIMEOUT_S = 25

POLICY_HINTS = ["privacy", "policy", "yinsi", "zhengce", "agreement", "terms",
                "隐私", "政策", "协议", "个人信息保护"]

APK_CANDIDATE_RE = re.compile(r"\.(html?|txt|md|json)$", re.IGNORECASE)
APK_POLICY_WORDS = ["隐私政策", "隐私保护", "个人信息保护", "privacy policy", "用户协议"]


def sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def fetch_url(url: str, *, timeout: int = TIMEOUT_S) -> dict:
    """抓一个 URL。**失败如实返回状态，不抛异常吞掉细节。**"""
    req = urllib.request.Request(url, headers={"User-Agent": UA,
                                               "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read(MAX_BYTES + 1)
            truncated = len(raw) > MAX_BYTES
            raw = raw[:MAX_BYTES]
            return {"ok": True, "url": url, "final_url": resp.geturl(),
                    "status": getattr(resp, "status", None),
                    "content_type": resp.headers.get("Content-Type", ""),
                    "bytes": raw, "byte_count": len(raw), "truncated": truncated,
                    "error": None}
    except urllib.error.HTTPError as e:
        return {"ok": False, "url": url, "final_url": url, "status": e.code,
                "content_type": "", "bytes": b"", "byte_count": 0, "truncated": False,
                "error": f"HTTP {e.code} {e.reason}"}
    except Exception as e:  # noqa: BLE001 —— 网络异常种类多，如实记录即可
        return {"ok": False, "url": url, "final_url": url, "status": None,
                "content_type": "", "bytes": b"", "byte_count": 0, "truncated": False,
                "error": f"{e.__class__.__name__}: {e}"}


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
    """从 APK 内部找政策文本。离线可用，通常是**最可靠的来源**。"""
    if not apk.exists():
        return []
    found = []
    with zipfile.ZipFile(apk) as zf:
        for info in zf.infolist():
            name = info.filename
            if info.file_size == 0 or info.file_size > MAX_BYTES:
                continue
            if not APK_CANDIDATE_RE.search(name):
                continue
            try:
                raw = zf.read(info)
            except Exception:  # noqa: BLE001
                continue
            head = raw[:4000].decode("utf-8", errors="ignore")
            if not any(w in head for w in APK_POLICY_WORDS) and \
               not any(w.lower() in head.lower() for w in ("privacy policy",)):
                continue
            ex = policy_extract.extract(raw, content_type="text/html", source=f"apk:{name}")
            if ex["chars"] < policy_extract.MIN_USEFUL_CHARS:
                continue
            found.append({"entry": name, "bytes": raw, "extract": ex,
                          "source_kind": "apk_asset"})
            if len(found) >= limit:
                break
    found.sort(key=lambda x: -x["extract"]["chars"])
    return found


def save(store_dir: Path, *, raw: bytes, extract: dict, meta: dict, tag: str) -> dict:
    store_dir.mkdir(parents=True, exist_ok=True)
    (store_dir / f"policy-{tag}.raw").write_bytes(raw)
    (store_dir / f"policy-{tag}.txt").write_text(extract["text"], encoding="utf-8")
    record = {**meta, "tag": tag, "raw_sha256": sha256(raw),
              "text_chars": extract["chars"], "text_sha256": sha256(
                  extract["text"].encode("utf-8")),
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
        found = extract_from_apk(Path(args.from_apk))
        if not found:
            result["status"] = "not_found"
            result["errors"].append(
                "APK 内未找到符合特征的政策文本（这不等于该应用没有政策；"
                "政策可能只存在于网络端或动态下发）")
        for i, item in enumerate(found, 1):
            rec = save(store_dir, raw=item["bytes"], extract=item["extract"],
                       tag=args.tag or f"apk{i}",
                       meta={"source_kind": "apk_asset", "source": args.from_apk,
                             "apk_entry": item["entry"], "url": None})
            result["records"].append(rec)
        if found:
            result["status"] = "ok"

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
