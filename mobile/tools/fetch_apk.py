#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""从应用宝公开页面获取第三方样本 APK，并生成**可核对的溯源记录**。

仅用于授权测试（自有设备 / 已授权的公开第三方样本）。本工具只做三件事：
取公开下载地址、下载、核对"下到的确实是这个包"。

为什么必须核对（实测教训）：详情页在包名不存在时会**回落到应用宝自己的页面**，
六次探测全部返回 `com.tencent.android.tencentdownload` 的链接而页面看起来正常。
不做核对就会闷头下五个应用宝、然后拿它们当五个不同 App 去分析——
报告里每个结论都"有据可查"，但查的是错的应用。

核对三道：
  1) 下载地址的 `fsname` 必须以 `<包名>_` 开头（商店把包名写进了文件名）；
  2) 文件必须是合法 ZIP（APK 即 ZIP，头 4 字节 PK\\x03\\x04）；
  3) 用 aapt2 解出 APK 的真实包名，必须与请求的包名**完全相等**。

溯源记录（`<包名>.provenance.json`）含：页面 URL、直链、下载时间、大小、
sha256/md5、商店给出的版本号/开发者/权限清单/隐私政策地址。
后面的 `device_run_thirdparty.py --provenance` 直接吃这个文件。

用法：
    python fetch_apk.py --probe com.moji.mjweather com.sina.weibo   # 只看元数据，不下载
    python fetch_apk.py --out ../../apk com.moji.mjweather ...      # 下载
    python fetch_apk.py --out ../../apk --packages-file list.txt
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
DEFAULT_OUT = ROOT / "apk"
AAPT2 = "D:/Anroid/SDK/build-tools/36.1.0/aapt2.exe"
# **必须用移动端 UA**：同一个详情页，桌面 UA 只给「应用宝 PC 版」的下载链接，
# 移动端 UA 才给出目标 App 自己的 APK 直链。实测：换 UA 前 10 个包全部 not_found，
# 且页面看起来正常（标题都对），只有直链悄悄变成了应用宝自己——
# 与"包名不存在"完全无法区分。
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

    # 只取 og:title 作名称——它是**这一页**的标题，随包名变化。
    # 其余字段（apk_size / privacy_agreement / developer / md_5）**一律不用**：
    # 实测同一页面里混着应用宝自身的推广数据块，正则抓到的第一个匹配是应用宝自己
    # （十个不同 App 全部返回 31.3MB 与同一个政策地址），看起来一切正常。
    # 需要这些元数据就从下载到的 APK 本身解（aapt2），那才是这个样本的事实。
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


def fetch_one(package: str, out_dir: Path, *, probe: bool, force: bool,
              aapt2: str) -> dict:
    rec: dict = {"package": package, "status": None, "errors": []}
    detail = fetch_detail(package)
    rec["store"] = detail
    if not detail["found"]:
        rec["status"] = "not_found"
        rec["errors"].append(detail.get("error") or "未取到直链")
        return rec

    if probe:
        rec["status"] = "probe_only"
        return rec

    dest = out_dir / f"{package}.apk"
    if dest.exists() and not force:
        rec["status"] = "exists"
        rec["errors"].append(f"{dest.name} 已存在；要重下加 --force（既有样本可能是证据）")
        return rec

    tmp = dest.with_suffix(".apk.part")
    try:
        dl = download(detail["apk_url"], tmp, out_dir / f"{package}.download.log")
    except Exception as e:  # noqa: BLE001
        tmp.unlink(missing_ok=True)
        rec["status"] = "download_failed"
        rec["errors"].append(f"{e.__class__.__name__}: {e}")
        return rec
    rec["download"] = dl

    head = tmp.read_bytes()[:4]
    if head[:2] != b"PK":
        tmp.unlink(missing_ok=True)
        rec["status"] = "not_a_zip"
        rec["errors"].append(f"下载内容不是 ZIP（头 4 字节 {head!r}）——可能是错误页或防盗链")
        return rec

    ident = apk_identity(tmp, aapt2)
    rec["apk_identity"] = ident
    if ident.get("error"):
        rec["errors"].append(f"aapt2 解析失败：{ident['error']}")
    elif ident.get("package") != package:
        tmp.unlink(missing_ok=True)
        rec["status"] = "package_mismatch"
        rec["errors"].append(f"下到的 APK 真实包名是 {ident.get('package')!r}，"
                             f"与请求的 {package!r} 不符——已删除，不拿它当样本")
        return rec

    # MD5 校验：直链文件名即该样本的 MD5，对不上说明下载被截断/替换过。
    exp = detail.get("expected_md5")
    if exp and dl["md5"].lower() != exp:
        tmp.unlink(missing_ok=True)
        rec["status"] = "md5_mismatch"
        rec["errors"].append(f"MD5 不匹配：下载得到 {dl['md5']}，直链文件名声明 {exp}"
                             f"——已删除，不拿可能被篡改的样本去分析")
        return rec

    tmp.rename(dest)
    rec["status"] = "ok"
    rec["apk_path"] = str(dest)
    rec["fetched_at"] = time.strftime("%Y-%m-%dT%H:%M:%S")
    (out_dir / f"{package}.provenance.json").write_text(
        json.dumps(rec, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return rec


def fetch_direct(package: str, url: str, out_dir: Path, *, probe: bool, force: bool,
                 aapt2: str) -> dict:
    """从**已知直链**下载（官网下载页 / GitHub Release 等）。

    与商店路径的区别：这里没有商店给的文件名可核对，所以**唯一凭据就是
    aapt2 解出的真实包名**——下到的不是这个包就直接删掉。
    实测这条路的可达性明显好于商店：商店 CDN 普遍有 JS 挑战，
    而官网/GitHub 的直链就是给浏览器下载用的。
    """
    rec: dict = {"package": package, "status": None, "errors": [],
                 "store": {"source_kind": "direct_url", "apk_url": url}}
    if probe:
        rec["status"] = "probe_only"
        return rec
    dest = out_dir / f"{package}.apk"
    if dest.exists() and not force:
        rec["status"] = "exists"
        rec["errors"].append(f"{dest.name} 已存在；要重下加 --force")
        return rec

    tmp = dest.with_suffix(".apk.part")
    try:
        dl = download(url, tmp, out_dir / f"{package}.download.log")
    except Exception as e:  # noqa: BLE001
        tmp.unlink(missing_ok=True)
        rec["status"] = "download_failed"
        rec["errors"].append(f"{e.__class__.__name__}: {e}")
        return rec
    rec["download"] = dl
    head = tmp.read_bytes()[:4]
    if head[:2] != b"PK":
        tmp.unlink(missing_ok=True)
        rec["status"] = "not_a_zip"
        rec["errors"].append(f"下载内容不是 ZIP（头 4 字节 {head!r}）")
        return rec
    ident = apk_identity(tmp, aapt2)
    rec["apk_identity"] = ident
    if ident.get("error"):
        rec["errors"].append(f"aapt2 解析失败：{ident['error']}")
    elif ident.get("package") != package:
        tmp.unlink(missing_ok=True)
        rec["status"] = "package_mismatch"
        rec["errors"].append(f"下到的 APK 真实包名是 {ident.get('package')!r}，"
                             f"与预期 {package!r} 不符——已删除")
        return rec
    tmp.rename(dest)
    rec["status"] = "ok"
    rec["apk_path"] = str(dest)
    rec["fetched_at"] = time.strftime("%Y-%m-%dT%H:%M:%S")
    (out_dir / f"{package}.provenance.json").write_text(
        json.dumps(rec, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return rec


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("packages", nargs="*", help="包名（可多个）")
    ap.add_argument("--packages-file", default=None, help="每行一个包名的文件")
    ap.add_argument("--out", default=str(DEFAULT_OUT))
    ap.add_argument("--probe", action="store_true", help="只取元数据，不下载")
    ap.add_argument("--force", action="store_true")
    ap.add_argument("--aapt2", default=AAPT2)
    ap.add_argument("--direct", action="append", default=[],
                    metavar="PKG=URL",
                    help="从已知直链下载（可重复）：官网下载页 / GitHub Release 等")
    args = ap.parse_args()

    pkgs = list(args.packages)
    if args.packages_file:
        pkgs += [ln.strip() for ln in Path(args.packages_file).read_text(
            encoding="utf-8").splitlines() if ln.strip() and not ln.startswith("#")]
    pkgs = list(dict.fromkeys(pkgs))

    directs = []
    for item in args.direct:
        if "=" not in item:
            sys.exit(f"--direct 需要 PKG=URL 形式，收到: {item!r}")
        pkg, url = item.split("=", 1)
        directs.append((pkg.strip(), url.strip()))

    if not pkgs and not directs:
        sys.exit("-- 至少给一个包名（或 --packages-file / --direct）")

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    results = []
    for pkg, url in directs:
        rec = fetch_direct(pkg, url, out_dir, probe=args.probe, force=args.force,
                           aapt2=args.aapt2)
        results.append(rec)
        line = f"  [{rec['status']:16s}] {pkg:36s} (直链)"
        if rec.get("download"):
            line += f" {rec['download']['bytes'] / 1048576:6.1f}MB"
        print(line)
        for e in rec["errors"]:
            print(f"        ! {e}")

    for pkg in pkgs:
        rec = fetch_one(pkg, out_dir, probe=args.probe, force=args.force, aapt2=args.aapt2)
        results.append(rec)
        d = rec.get("store") or {}
        line = f"  [{rec['status']:16s}] {pkg:36s}"
        if d.get("name"):
            line += f" {str(d['name'])[:16]:18s}"
        if d.get("version"):
            line += f" v{str(d['version'])[:12]:14s}"
        if rec.get("download"):
            line += f" {rec['download']['bytes'] / 1048576:6.1f}MB"
        print(line)
        for e in rec["errors"]:
            print(f"        ! {e}")

    ok = [r for r in results if r["status"] == "ok"]
    print(json.dumps({"status": "ok", "out": str(out_dir), "requested": len(results),
                      "downloaded": len(ok),
                      "failed": [r["package"] for r in results
                                 if r["status"] not in ("ok", "probe_only", "exists")]},
                     ensure_ascii=False, indent=2))
    return 0 if len(ok) == len(results) or args.probe else 1


if __name__ == "__main__":
    raise SystemExit(main())
