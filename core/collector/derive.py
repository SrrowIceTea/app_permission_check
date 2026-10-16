#!/usr/bin/env python3
"""派生值候选（C1）——「读到的原值」与「报文里出现的形态」之间的桥。

仅用于授权测试（已获授权的样本与设备）。

**为什么需要**：值级匹配原先只认「原值 sha256 前 16 位」一种形态（M005/M011）。
真实应用常把读到的值**变换后再外发**——base64/url 编码、hex 展开、gzip+base64、
或 md5/sha1/sha256 摘要。这些形态出现在报文里时，原值哈希对不上，
「确实发了这个值」就静默退化成「仅形态相似」，证据强度凭空掉档——
而且是**静默**掉的：没有任何报错或标注。

**两侧各取所需**，本模块保持纯函数、只依赖标准库、不抛异常：

  * 报文侧（tagging）：`reversible_decodings()` 把报文里的**可逆**编码解回原文，
    解码结果重新过形态扫描 → 令牌仍是「解码后原值的 hash16」，
    读取侧（value_hash）零改动即可命中；
  * 读取侧（value_matches）：`hash16_candidates()` 对**完整**原值算各摘要形态的
    hash16，与报文里 md5/sha1/sha256 十六进制串的令牌比对（单向哈希不可逆，
    只能从原值方向算）。

**诚实边界**（两条都不可妥协）：

  1. 单向摘要候选只来自**读取侧的原值**。报文侧看到的摘要串无法还原成原值，
     不会据此生成「原值令牌」——即「报文里有个 md5」本身不构成任何匹配，
     只有读取事件的原值摘要恰好等于它时才算命中（sha256 碰撞概率可忽略）。
  2. 可逆解码是**尽力而为**：任何失败都返回空。解码产物只有重新通过敏感形态
     扫描才产生**令牌**（值级，需要精确哈希对上，乱码凑不出碰撞）；
     但解码产物**不产生形态级标签**——乱码或巧合解码可能凑出假形态，
     形态级结论只允许来自报文原文（由调用方负责，见 tagging_mobile）。
"""
from __future__ import annotations

import base64
import binascii
import gzip
import hashlib
import re
import urllib.parse

# 参与解码尝试的规模上限：扫描在 mitmproxy 数据面逐报文调用，
# 不设上限等于把性能交给攻击者的报文长度。
MAX_TEXT = 65_536    # 整段文本超过此长度不做解码尝试（原文形态扫描不受影响）
MAX_RUN = 16_384     # 单个候选串（一段 base64 / hex）的上限
MAX_RUNS = 32        # 每段文本最多尝试的候选串个数（防炸弹式数量）

# 阈值按真实目标反推：15 位 IMEI 的 base64 = 20 字符、hex = 30 字符；
# 11 位手机号的 base64 = 16 字符、hex = 22 字符。门槛高于这些值等于把
# 最典型的「先编码再外发」场景挡在门外（首跑 test_derive 实测）。
# 误报由两层兜底：b64 需 charset 合法 + 长度对齐 4，解码产物还需可打印 UTF-8；
# 且解码产物只有重新通过敏感形态扫描才产生令牌（tagging 侧），乱码凑不出碰撞。
_B64_RUN = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
_HEX_RUN = re.compile(r"(?:[0-9a-f]{2}){10,}")
_GZIP_MAGIC = b"\x1f\x8b"


def hash16(s: str) -> str:
    """与 hook 侧 value_hash、tagging 侧令牌同一口径：sha256 前 16 个 hex。"""
    return hashlib.sha256(s.encode("utf-8")).hexdigest()[:16]


def oneway_hexes(value: str) -> dict[str, str]:
    """原值的各摘要形态（完整小写十六进制串）。这些串出现在报文里就是线索。"""
    raw = value.encode("utf-8")
    return {
        "md5": hashlib.md5(raw).hexdigest(),        # noqa: S324 仅作观测比对候选，不做安全用途
        "sha1": hashlib.sha1(raw).hexdigest(),      # noqa: S324
        "sha256": hashlib.sha256(raw).hexdigest(),
    }


def hash16_candidates(value: str) -> dict[str, str]:
    """读取侧候选：各摘要形态的 hash16。

    报文令牌是 `标签:hash16(报文里那段串)`；当报文里那段串恰好是
    md5/sha1/sha256(原值) 的十六进制时，令牌后缀与本函数返回值相等 → 命中。
    """
    return {form: hash16(hx) for form, hx in oneway_hexes(value).items()}


def _printable(text: str) -> bool:
    """解码产物是否基本可打印。二进制乱码不值得 rescans（浪费且徒增巧合面）。"""
    if not text:
        return False
    ok = sum(1 for c in text[:2048] if c.isprintable() or c in "\r\n\t")
    return ok / min(len(text), 2048) >= 0.9


def _utf8(raw: bytes) -> str | None:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    return text if _printable(text) else None


def _b64decode(run: str) -> bytes | None:
    if len(run) < 16 or len(run) > MAX_RUN or len(run) % 4:
        return None
    try:
        return base64.b64decode(run, validate=True)
    except (binascii.Error, ValueError):
        return None


def _gunzip(raw: bytes) -> bytes | None:
    if not raw.startswith(_GZIP_MAGIC):
        return None
    try:
        out = gzip.decompress(raw)
    except (OSError, EOFError, binascii.Error):
        return None
    return out if len(out) <= MAX_TEXT else None


def _try_b64(run: str, out: list[tuple[str, str]]) -> None:
    raw = _b64decode(run)
    if raw is None:
        return
    if raw.startswith(_GZIP_MAGIC):
        gz = _gunzip(raw)
        if gz is not None:
            text = _utf8(gz)
            if text:
                out.append(("gzip_b64", text))
            return                      # gzip 层里通常还有一段 b64 语义，但两层够了
    text = _utf8(raw)
    if text:
        out.append(("b64", text))


def reversible_decodings(text: str) -> list[tuple[str, str]]:
    """→ [(形态名, 解码产物)]，全部尽力而为、失败即跳过。

    形态名：`url` / `b64` / `gzip_b64` / `hex`。同一 (形态, 产物) 只出现一次。
    调用方（tagging）拿产物**重新过形态扫描**：解码出的原值参与值级令牌，
    但不得据此给报文添加形态级标签（见模块头的诚实边界 2）。
    """
    out: list[tuple[str, str]] = []
    if not text or len(text) > MAX_TEXT:
        return out
    seen: set[tuple[str, str]] = set()

    def add(form: str, decoded: str) -> None:
        if decoded and decoded != text and (form, decoded) not in seen:
            seen.add((form, decoded))
            out.append((form, decoded))

    # URL 编码：只在确有 %XX 痕迹时试，unquote_plus 对正常文本是无操作/有害的。
    if "%" in text:
        try:
            add("url", urllib.parse.unquote_plus(text))
        except Exception:  # noqa: BLE001 — unquote 对畸形序列也能容错，这里兜底
            pass

    runs = 0
    for m in _B64_RUN.finditer(text):
        runs += 1
        if runs > MAX_RUNS:
            break
        _try_b64(m.group(0), out)

    hex_runs = 0
    for m in _HEX_RUN.finditer(text):
        hex_runs += 1
        if hex_runs > MAX_RUNS:
            break
        run = m.group(0)
        if len(run) > MAX_RUN:
            continue
        try:
            raw = bytes.fromhex(run)
        except ValueError:
            continue
        text2 = _utf8(raw)
        if text2:
            add("hex", text2)

    dedup: list[tuple[str, str]] = []
    seen2: set[tuple[str, str]] = set()
    for pair in out:
        if pair not in seen2:
            seen2.add(pair)
            dedup.append(pair)
    return dedup
