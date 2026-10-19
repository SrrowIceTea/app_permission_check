#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Flutter / 剥符号静态 BoringSSL：在 APK 里定位证书校验函数。

## 为什么需要它

`libflutter.so` 自带一份**静态链接且剥了符号**的 BoringSSL：`SSL_read`/`SSL_write`/
`SSL_CTX_set_keylog_callback` 全都不在导出表里（实测本地样本 `.dynsym` 里连
`SSL_read` 这个字符串都没有）。所以 `Module.findExportByName` 永远拿不到，
`hook_native_ssl.js` / `hook_tls_meta.js` 对这类构建**一条都挂不上**——这是能力边界，
不是 bug。

但"没有符号"不等于"没有代码"：函数体原样在 `.text` 里，只是名字被抹掉。定位它只需要
一个**不随版本漂移的解剖学特征**：

    ssl_crypto_x509_session_verify_cert_chain(hs, out_alert) {
        *out_alert = SSL_AD_INTERNAL_ERROR;   // 常量 0x50 = 80
        ...
    }

x86_64 上编译成 `c6 02 50`（`mov byte ptr [rdx], 0x50`）紧跟 `48 8b af ?? ?? ?? ??`
（`mov rbp, [rdi+off]`）。往回收 10 字节就是标准序言
`55 41 57 41 56 41 55 41 54 53`（push rbp; push r15/r14/r13/r12; push rbx）。

社区既有做法（NVISO 2019/2022、reFlutter）用的是**整段函数序言**做签名，版本一变
栈帧大小就变（本地样本是 `48 83 ec 38`，2019 年那份是 `... c6 02 50 48 8b af a8`，
偏移从 a8 变成 a0），签名直接失效。本工具改成**锚在解剖学常量上再回扫序言**，
对栈帧/结构体偏移的变化免疫。

## 用法

    python mobile/tools/flutter_probe.py --apk x.apk            # 人读
    python mobile/tools/flutter_probe.py --apk x.apk --json o.json

输出里 `found=false` 时 `reason` 说明是哪一步没命中（没有 libflutter / 没有锚点），
**不要**把它当成"这个 App 不可测"。
"""
from __future__ import annotations

import argparse
import json
import struct
import sys
import zipfile
from pathlib import Path

# 已知签名（整段序言）。只作为**快速通道**；命中不了就走解剖学锚点。
KNOWN_SIGS = {
    # NVISO 2019 x64（Flutter 1.x）：注意结尾是 48 8b af a8 —— 结构体偏移随版本变
    "x86_64": ["554157415641554154534883ec38c60250488bafa8000000"],
    # NVISO 2020 arm64
    "arm64": ["ffc301d1fd7b01a9????????94080a8052"],  # 带通配，仅示意
}

# 解剖学锚点：*out_alert = SSL_AD_INTERNAL_ERROR (0x50) 之后的 ssl 解引用
ANCHOR = {
    "x86_64": "c60250488baf",       # mov byte [rdx], 0x50 ; mov rbp, [rdi+off]
    "x86": "c60250",                # 32 位：mov byte [edx], 0x50（回扫序言另算）
    "arm64": "080a805248000039",    # mov w8,#0x50 ; strb w8,[x2]
}
PROLOGUE = {
    "x86_64": "554157415641554154 53".replace(" ", ""),  # push rbp;r15;r14;r13;r12;rbx
    "arm64": "ffc301d1",                                  # sub sp, sp, #0x70
}


def _sections(so: bytes) -> list[dict]:
    shoff = int.from_bytes(so[0x28:0x30], "little")
    es = int.from_bytes(so[0x3a:0x3c], "little")
    n = int.from_bytes(so[0x3c:0x3e], "little")
    si = int.from_bytes(so[0x3e:0x40], "little")
    if not shoff or not n:
        return []
    shstr = shoff + si * es
    stroff = int.from_bytes(so[shstr + 0x18:shstr + 0x20], "little")
    out = []
    for i in range(n):
        b = shoff + i * es
        nm = int.from_bytes(so[b:b + 4], "little")
        e = so.index(0, stroff + nm)
        out.append({"name": so[stroff + nm:e].decode("latin1", "replace"),
                    "type": int.from_bytes(so[b + 4:b + 8], "little"),
                    "addr": int.from_bytes(so[b + 0x10:b + 0x18], "little"),
                    "off": int.from_bytes(so[b + 0x18:b + 0x20], "little"),
                    "size": int.from_bytes(so[b + 0x20:b + 0x28], "little")})
    return out


def _text(secs: list[dict]) -> dict | None:
    for s in secs:
        if s["name"] == ".text":
            return s
    # 部分构建没有节头，退化为扫整个文件（快但慢）
    return None


def analyse_so(so: bytes, abi: str) -> dict:
    secs = _sections(so)
    sym = [s for s in secs if s["name"] in (".symtab", ".dynsym")]
    text = _text(secs)
    result = {
        "abi": abi, "size": len(so),
        "stripped": not any(s["name"] == ".symtab" for s in secs),
        "has_dynsym": any(s["name"] == ".dynsym" for s in secs),
        "sections": len(secs), "found": False, "reason": None,
        "how": None, "va": None, "file_offset": None, "anchor_va": None,
    }
    if not secs:
        result["reason"] = "no_section_headers"
        return result

    base, blob = (text["addr"], so[text["off"]:text["off"] + text["size"]]) if text \
        else (0, so)
    if text is None:
        result["reason"] = "no_.text_section"
        return result

    # 1) 快速通道：整段序言签名
    for hexsig in KNOWN_SIGS.get(abi, []):
        if "?" in hexsig:
            continue
        pat = bytes.fromhex(hexsig)
        i = blob.find(pat)
        if i >= 0:
            result.update(found=True, how="known_sig", va=base + i,
                          file_offset=(text["off"] + i))
            return result

    # 2) 解剖学锚点 + 回扫序言
    anchor = ANCHOR.get(abi)
    pro = bytes.fromhex(PROLOGUE.get(abi, "")) if PROLOGUE.get(abi) else b""
    if not anchor:
        result["reason"] = f"no_anchor_for_{abi}"
        return result
    pat = bytes.fromhex(anchor)
    hits = []
    p = 0
    while True:
        p = blob.find(pat, p)
        if p < 0:
            break
        hits.append(p)
        p += 1
    result["anchor_hits"] = len(hits)
    if not hits:
        result["reason"] = "anchor_not_found"
        return result
    if not pro:
        result["how"] = "anchor_only"
        result["anchor_va"] = base + hits[0]
        return result

    # 回扫：序言必须在锚点前 8..24 字节之间（push 序列 + sub rsp 一般是 10~16 字节）
    for off in hits:
        lo = max(0, off - 24)
        window = blob[lo:off]
        j = window.find(pro)
        while j >= 0:
            start = lo + j
            gap = off - (start + len(pro))
            if 0 <= gap <= 16:
                result.update(found=True, how="anatomy+prologue", va=base + start,
                              file_offset=text["off"] + start,
                              anchor_va=base + off, gap_bytes=gap)
                return result
            j = window.find(pro, j + 1)
    result["reason"] = f"anchor_found_but_no_prologue (hits={len(hits)})"
    return result


def run(apk: Path) -> dict:
    out: dict = {"apk": str(apk), "abis": {}, "found": False}
    if not apk.exists():
        out["error"] = "apk_not_found"
        return out
    with zipfile.ZipFile(apk) as z:
        libs = [n for n in z.namelist()
                if n.startswith("lib/") and n.endswith("/libflutter.so")]
        out["libflutter"] = libs
        if not libs:
            out["error"] = "no_libflutter_so（不是 Flutter 应用，或库被改名/加固）"
            return out
        for name in libs:
            abi = name.split("/")[1]
            try:
                info = analyse_so(z.read(name), abi)
            except Exception as exc:                      # noqa: BLE001
                info = {"abi": abi, "found": False, "reason": f"parse_error: {exc!r}"}
            out["abis"][abi] = info
            out["found"] = out["found"] or info.get("found", False)
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description="在 Flutter APK 里定位证书校验函数")
    ap.add_argument("--apk", required=True)
    ap.add_argument("--json", default=None, help="结果写 JSON（给运行时钩子用）")
    args = ap.parse_args()
    res = run(Path(args.apk).resolve())
    text = json.dumps(res, ensure_ascii=False, indent=2)
    if args.json:
        Path(args.json).write_text(text + "\n", encoding="utf-8")
    print(text)
    return 0 if res.get("found") else 1


if __name__ == "__main__":
    raise SystemExit(main())
