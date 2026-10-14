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
    python fetch_apk.py com.moji.mjweather ...                      # 下载到 apk/mobile/
    python fetch_apk.py --packages-file list.txt
    python fetch_apk.py --out <repo>/apk/vehicle <车机包名>          # 车载样本显式给目录
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
# 样本按平台分目录（见 apk/README.md）：本工具是移动端链路，默认落 apk/mobile/。
# 下**车载**样本时显式 --out apk/vehicle，否则会被移动端批处理当成手机 App 跑，
# 症状是设备检测卡在 app_started，看起来像冷启动问题。
DEFAULT_OUT = ROOT / "apk" / "mobile"
# SDK 路径解析统一走 core/sdk_paths（§8.2 B-4）：不再写死本机绝对路径。
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT))
from core import sdk_paths  # noqa: E402
# 传输与元数据原语拆到相邻模块（原文件越 300 行红线，§8.2 B-2）。
# `apk_identity` 继续从这个模块对外——`apk_meta.py` 用的是 `fetch_apk.apk_identity`。
from fetch_apk_io import apk_identity, download, fetch_detail  # noqa: E402

AAPT2 = sdk_paths.sdk_tool("build-tools", "36.1.0", "aapt2.exe")


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
