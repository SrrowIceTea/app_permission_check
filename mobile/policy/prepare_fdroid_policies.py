#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""为 F-Droid 样本批量准备本地应用政策库。

仅用于授权测试（已获授权的公开第三方样本）。

**为什么要它**：默认政策库只覆盖经过人工核对的样本，F-Droid 第三方包通常不在其中，
于是整批都得到 `policy.available=false`。这个状态本身是**诚实的**——它是
"未取得政策"，不是"该应用没有政策"——但 60 个样本全部如此，政策一致性维度
就等于完全不可判定。

**入库必须走 `register_policy`，不能用 `policy_fetch --url`**（2026-10-20 返工）：
`policy_library` 的查找契约是**按 package 绑定**的——
`_load_primary_policy()` 先读 `catalog.json` 按 `package` 过滤，`_read_record()`
遇到 meta 里没有 package 的记录直接 `raise ValueError`。而 `policy_fetch` 的 CLI
只写 `policy-<tag>.raw/.txt/.meta.json`，**既不写 catalog 也不把 package 写进 meta**；
若 `--tag` 又是常量，60 个包会互相覆盖，最后只剩一份。更要命的是：把这种目录
用 `--policy-store` 传进去会挡住 DEFAULT_STORE 回退，反而弄坏本来可用的样本。
所以本脚本直接用 `fetch_url()` 取字节 + `register_policy()` 建 catalog 条目。

**边界（不许越）**：
  * 抓不到就是抓不到，记 `not_found`，**绝不用 README、许可证或仓库描述冒充隐私政策**；
  * 只做"取得"，不做"判断"——正文够不够、是不是现行版本由 `policy_lint` 与
    `load_policy` 决定，本脚本的 `load_policy` 只是**回验入库成功**，不是判定合规；
  * 需要联网；离线时每个样本都落 `not_found`，这同样是合法结果。

用法:
  python prepare_fdroid_policies.py --apk-dir D:/数据集/数据集/F-Droid-60 \
      --store output/local-policy-library-fdroid
  python prepare_fdroid_policies.py --apk-dir ... --store ... --dry-run  # 只列候选，不抓
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from policy_fetch import fetch_url, UA                   # noqa: E402
from policy_library import register_policy, load_policy  # noqa: E402

# 开源项目里隐私政策最常见的落点，按命中率排序。
# 只猜**政策文件**，不猜 README：README 不是政策，拿它入库等于伪造证据。
POLICY_PATHS = (
    "PRIVACY.md", "PRIVACY_POLICY.md", "privacy.md", "privacy_policy.md",
    "docs/PRIVACY.md", "docs/privacy.md", ".github/PRIVACY.md",
    "PRIVACY.txt", "privacy.txt", "docs/privacy-policy.md",
)
REFS = ("HEAD", "master", "main")

# 三种托管平台都要认（2026-10-20）：实测 60 个 F-Droid 样本里 47 个 GitHub、
# 13 个是 GitLab/Codeberg（foggymaps、BarcodeScanner、Gadgetbridge、
# ImmichUploader、MileLog、portio、OpenTracks…），只认 github 会让那 13 个
# 直接落 no_source_code。
_GH = re.compile(r"https?://(?:www\.)?github\.com/([^/]+)/([^/#?]+)")
_GL = re.compile(r"https?://(?:www\.)?gitlab\.com/([^/]+)/([^/#?]+)")
_CB = re.compile(r"https?://(?:www\.)?codeberg\.org/([^/]+)/([^/#?]+)")


def repo_candidates(source_code: str) -> list[str]:
    """把源码仓库地址展开成一串 raw 政策文件候选地址。"""
    src = source_code or ""
    out: list[str] = []
    for pat, tpl in ((_GH, "https://raw.githubusercontent.com/{o}/{r}/{ref}/{p}"),
                     (_GL, "https://gitlab.com/{o}/{r}/-/raw/{ref}/{p}"),
                     (_CB, "https://codeberg.org/{o}/{r}/raw/branch/{ref}/{p}")):
        m = pat.search(src)
        if not m:
            continue
        o, r = m.group(1), m.group(2).removesuffix(".git")
        out.extend(tpl.format(o=o, r=r, ref=ref, p=p)
                   for ref in REFS for p in POLICY_PATHS)
    return out


def _head_ok(url: str, timeout: float = 6.0) -> bool:
    """HEAD 预筛：只问"在不在"，不取正文。网络问题一律当成没有，不中断整批。"""
    req = urllib.request.Request(url, method="HEAD", headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return 200 <= r.status < 300
    except Exception:  # noqa: BLE001
        return False


def _sha(prov: dict) -> str:
    for k in (("download", "sha256"), ("store", "index_sha256"),
              ("apk_identity", "sha256")):
        v = (prov.get(k[0]) or {}).get(k[1])
        if v and re.fullmatch(r"[0-9a-f]{64}", v):
            return v
    return ""


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--apk-dir", type=Path, required=True,
                    help="样本目录：内含 <pkg>.apk 与 <pkg>.provenance.json")
    ap.add_argument("--store", type=Path, required=True, help="本地政策库目录")
    ap.add_argument("--dry-run", action="store_true", help="只列出候选地址，不抓取")
    ap.add_argument("--limit", type=int, default=0, help="只处理前 N 个（调试用）")
    args = ap.parse_args()

    args.store.mkdir(parents=True, exist_ok=True)
    provs = sorted(args.apk_dir.glob("*.provenance.json"))
    if args.limit:
        provs = provs[:args.limit]
    if not provs:
        print(f"[prepare] {args.apk_dir} 下没有 provenance.json，无法确定源码仓库。")
        return 1

    got, miss, nosrc, noid = 0, 0, 0, 0
    report: list[dict] = []
    for pv in provs:
        try:
            prov = json.loads(pv.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        pkg = prov.get("package") or pv.name.replace(".provenance.json", "")
        store_meta = prov.get("store") or {}
        src = store_meta.get("source_code") or ""
        urls = repo_candidates(src)
        if not urls:
            nosrc += 1
            report.append({"package": pkg, "status": "no_source_code",
                           "source_code": src or None})
            continue
        if args.dry_run:
            print(f"[dry-run] {pkg}: {len(urls)} 候选，首个 {urls[0]}")
            continue
        sha = _sha(prov)
        vc = store_meta.get("version_code")
        if not sha or not vc:
            # register_policy 强制要 package + version_code + 64 位 sha256，
            # 缺一项就无法建绑定条目 —— 硬凑等于伪造身份，宁可记为未取得。
            noid += 1
            report.append({"package": pkg, "status": "missing_identity",
                           "sha256": sha or None, "version_code": vc})
            continue
        hit_url, hit_raw = None, None
        for u in urls:
            # 先用 HEAD 预筛：每个样本最多 30 个候选，直接对每个候选 fetch_url
            # （内部还要「代理 + 直连」两次）实测 60 个样本十几分钟都跑不完。
            # HEAD 只是"这个地址有没有"，命中了才真正取正文。
            if not _head_ok(u):
                continue
            f = fetch_url(u)
            if f.get("ok") and not f.get("truncated") and f.get("bytes"):
                hit_url, hit_raw = u, f["bytes"]
                break
        if hit_url is None:
            miss += 1
            report.append({"package": pkg, "status": "not_found",
                           "source_code": src, "tried": len(urls)})
            continue
        try:
            register_policy(args.store, raw=hit_raw, package=pkg,
                            version_code=str(vc), apk_sha256=sha,
                            source=hit_url, source_kind="source_repo_policy",
                            content_type="text/markdown",
                            notes=["F-Droid 样本：由源码仓库内的政策文件取得，"
                                   "未经人工核对，适用性与现行版本以 policy_lint 为准"])
            # 回验：能 load 出来才算真的进了库（只是验证入库，不是判定合规）。
            chk = load_policy(args.store, package=pkg, version_code=str(vc),
                              apk_sha256=sha)
            ok = bool(chk.get("available"))
        except (ValueError, OSError, KeyError) as exc:
            ok = False
            report.append({"package": pkg, "status": "register_failed",
                           "url": hit_url, "error": str(exc)[:200]})
            miss += 1
            continue
        if ok:
            got += 1
            report.append({"package": pkg, "status": "fetched", "url": hit_url,
                           "chars": chk.get("chars")})
        else:
            miss += 1
            report.append({"package": pkg, "status": "load_back_failed",
                           "url": hit_url, "status_detail": chk.get("status")})

    cov = args.store / "coverage.fdroid.json"
    cov.write_text(json.dumps({
        "v": "2", "samples": len(provs), "fetched": got, "not_found": miss,
        "no_source_code": nosrc, "missing_identity": noid, "items": report,
        "note": ("not_found / no_source_code / missing_identity 均表示**未取得政策**，"
                 "不等同于「该应用没有政策」，也不等同于合规通过。"),
    }, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"[prepare] 样本 {len(provs)}：取得 {got}，未取得 {miss}，"
          f"无源码地址 {nosrc}，身份不全 {noid} → {cov}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
