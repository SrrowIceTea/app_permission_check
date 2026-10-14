#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""fetch_apk 的传输与元数据原语（从 fetch_apk.py 拆出，§8.2 B-2）。

仅用于授权测试（自有设备 / 已授权的公开第三方样本）。

**为什么拆**：这里是"只碰网络与文件、不懂业务"的一层——详情页抓取、aapt2 解真实
包名、分块下载（含 curl 兜底）、流式摘要。`fetch_apk.py` 留下的是编排：什么时候下、
下到哪、核对什么、怎么落溯源记录。原文件越过了 300 行红线。

**UA 是这一层的协议常量，不是可调项**：同一个详情页，桌面 UA 只给「应用宝 PC 版」
的下载链接，移动端 UA 才给目标 App 自己的 APK 直链。实测换 UA 前 10 个包全部
`not_found`，而且**页面看起来完全正常**（标题都对）——与"包名确实不存在"无法区分。

**为什么详情页只取 og:title**：同一页面里混着应用宝自身的推广数据块，正则抓到的
第一个 `apk_size` / `privacy_agreement` / `developer` 其实是应用宝自己的
（十个不同 App 全部返回 31.3MB 与同一个政策地址）。需要元数据就从下载到的 APK
本身解——那才是这个样本的事实。
"""
from __future__ import annotations

import hashlib
import re
import urllib.request
from pathlib import Path

# **必须用移动端 UA**，原因见模块头。
UA = ("Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36")
PAGE = "https://sj.qq.com/myapp/detail.htm?apkName={pkg}"
TIMEOUT = 40
MAX_BYTES = 400 * 1024 * 1024


def _get(url: str, *, binary: bool = False, timeout: int = TIMEOUT):
    req = urllib.request.Request(url, headers={"User-Agent": UA,
                                               "Accept-Language": "zh-CN,zh;q=0.9"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read() if binary else resp.read().decode("utf-8", "replace")


def fetch_detail(package: str) -> dict:
    """详情页 → {found, name, developer, version, apk_url, privacy_agreement, permissions}"""
    url = PAGE.format(pkg=package)
    out: dict = {"page_url": url, "found": False, "error": None}
    try:
        html = _get(url)
    except Exception as e:  # noqa: BLE001
        out["error"] = f"{e.__class__.__name__}: {e}"
        return out

    # 直链：商店把包名写进 fsname（`<包名>_<版本>.apk`），以此精确匹配
    apk_urls = [u for u in re.findall(r"https?://[^\"'\s]+\.apk[^\"'\s]*", html)
                if f"fsname={package}_" in u]
    if apk_urls:
        out["apk_url"] = apk_urls[0]
        m = re.search(rf"fsname={re.escape(package)}_([^\"'&\s]+)\.apk", apk_urls[0])
        if m:
            out["version"] = m.group(1)

    # 只取 og:title 作名称——它是**这一页**的标题，随包名变化。其余字段一律不用，
    # 原因见模块头（那些是应用宝自己的推广数据，看起来一切正常）。
    m = re.search(r'<meta property="og:title" content="([^"]+)"', html)
    if m:
        out["name"] = m.group(1)

    # 直链文件名就是该 APK 的 MD5（应用宝的固定形态），是**针对这一次下载**的校验凭据。
    m = re.search(r"/([0-9A-Fa-f]{32})\.apk", out.get("apk_url") or "")
    if m:
        out["expected_md5"] = m.group(1).lower()
    out["found"] = bool(out.get("apk_url"))
    if not out["found"]:
        out["error"] = ("页面里没有以该包名为 fsname 的直链——"
                        "包名可能不存在，或商店回落到了自己的页面（实测过）")
    return out


def apk_identity(apk: Path, aapt2: str) -> dict:
    """用 aapt2 解出 APK 的真实包名/版本。解不出就是解不出，不猜。"""
    import subprocess
    try:
        proc = subprocess.run([aapt2, "dump", "badging", str(apk)],
                              capture_output=True, text=True, encoding="utf-8",
                              errors="replace", timeout=180)
    except Exception as e:  # noqa: BLE001
        return {"error": f"{e.__class__.__name__}: {e}"}
    if proc.returncode != 0:
        return {"error": (proc.stderr or "aapt2 非零退出").strip()[:300]}
    txt = proc.stdout

    def grab(pat):
        m = re.search(pat, txt)
        return m.group(1) if m else None
    return {"package": grab(r"package: name='([^']+)'"),
            "version_code": grab(r"versionCode='([^']+)'"),
            "version_name": grab(r"versionName='([^']+)'"),
            "min_sdk": grab(r"sdkVersion:'([^']+)'"),
            "target_sdk": grab(r"targetSdkVersion:'([^']+)'"),
            "app_label": grab(r"application-label:'([^']*)'"),
            # 启动 Activity：第三方检测要显式指定入口，缺了它只能靠 monkey 猜
            # （猜错的表现是"应用起来了但什么都没发生"）。
            "launchable_activity": grab(r"launchable-activity: name='([^']+)'")}


def _digest(path: Path) -> tuple[int, str, str]:
    sha, md5, size = hashlib.sha256(), hashlib.md5(), 0
    with path.open("rb") as fh:
        while True:
            chunk = fh.read(1 << 20)
            if not chunk:
                break
            size += len(chunk)
            sha.update(chunk)
            md5.update(chunk)
    return size, sha.hexdigest(), md5.hexdigest()


def _download_curl(url: str, dest: Path) -> None:
    """curl 兜底。

    实测：部分国内 CDN（喜马拉雅 apk.pcdn.xmcdn.com、小米 app.mi.com）对
    Python urllib 的 TLS 握手直接断连（`SSL: UNEXPECTED_EOF_WHILE_READING`），
    而同一个地址 curl 能正常下完。这不是网络问题、也不是防盗链——
    换客户端就好，所以值得留一条兜底，否则会以为是"这个源下不了"而放弃。
    """
    import shutil
    import subprocess
    curl = shutil.which("curl")
    if not curl:
        raise RuntimeError("urllib 失败且系统没有 curl 可兜底")
    proc = subprocess.run([curl, "-sSL", "--max-time", "900", "-A", UA,
                           "-o", str(dest), url],
                          capture_output=True, text=True, encoding="utf-8",
                          errors="replace", timeout=960)
    if proc.returncode != 0 or not dest.exists() or dest.stat().st_size == 0:
        raise RuntimeError(f"curl 也失败 rc={proc.returncode}: {proc.stderr.strip()[:200]}")


def download(url: str, dest: Path, log) -> dict:
    used = "urllib"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": UA})
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp, dest.open("wb") as fh:
            total = 0
            while True:
                chunk = resp.read(262144)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_BYTES:
                    raise RuntimeError(f"超过 {MAX_BYTES} 字节上限，已中止")
                fh.write(chunk)
    except Exception as first:  # noqa: BLE001
        used = f"curl（urllib 失败：{first.__class__.__name__}）"
        dest.unlink(missing_ok=True)
        _download_curl(url, dest)
    size, sha, md5 = _digest(dest)
    if size > MAX_BYTES:
        dest.unlink(missing_ok=True)
        raise RuntimeError(f"超过 {MAX_BYTES} 字节上限，已中止")
    log.write_text(f"{url}\n{size} bytes\nvia {used}\n", encoding="utf-8")
    return {"bytes": size, "sha256": sha, "md5": md5, "client": used}
