"""Local tshark discovery, execution and field decoding. 仅用于授权测试。"""
from __future__ import annotations

import os
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from core.io_utils import split_jsonl_lines  # noqa: E402

# Filter the reserved transport, since a fixture may legitimately use a /ws route.
FRIDA_LOOPBACK = "tcp.port == 27043 and (ip.addr == 127.0.0.1 or ipv6.addr == ::1)"


_CANDIDATES = [
    # 项目内便携解出的那份（2026-11-15）：本机没有安装版 Wireshark，
    # 用 MSI 的 /a（管理安装）解出来放在 output/_tools，不注册系统、不装 Npcap。
    str(ROOT / "output" / "_tools" / "wireshark" / "tshark.exe"),
    r"C:\Program Files\Wireshark\tshark.exe",
    r"C:\Program Files (x86)\Wireshark\tshark.exe",
]


def find_tshark() -> str | None:
    """按 VSCAN_TSHARK → PATH → 项目便携目录 → 常见安装目录 找 tshark。找不到返回 None。

    不猜版本、不自动下载：抓不到就如实报缺口，由安装步骤解决。
    """
    p = os.environ.get("VSCAN_TSHARK")
    if p and Path(p).is_file():
        return p
    which = shutil.which("tshark")
    if which:
        return which
    for c in _CANDIDATES:
        if Path(c).is_file():
            return c
    return None


def tshark_preflight() -> tuple[int, str]:
    decoder = find_tshark()
    if not decoder:
        return 1, "未找到 tshark。仍保留 pcap，设置 VSCAN_TSHARK 后可离线解码。"
    try:
        result = subprocess.run([decoder, "--version"], capture_output=True,
                                text=True, errors="replace", timeout=10, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 1, f"无法启动 tshark（{decoder}）：{exc}"
    version = next((line for line in result.stdout.splitlines() if line.startswith("TShark")), "")
    if result.returncode or not version:
        return 1, f"tshark 版本检查失败（{decoder}，退出码 {result.returncode}）"
    return 0, f"{version} | {decoder}"


def keylog_from_events(session: Path, out: Path) -> tuple[int, str]:
    """从会话事件里抽取 NSS keylog 行，写成 tshark 认的文本。

    来源优先级：`tls_meta.jsonl`（分流后）→ `reads.jsonl`（合并模式未分流）。
    两者都可能存在，按行去重——同一连接重复握手会重复打点。
    """
    lines: list[str] = []
    seen: set[str] = set()
    for name in ("tls_meta.jsonl", "reads.jsonl"):
        f = session / name
        if not f.exists():
            continue
        for number, raw in enumerate(split_jsonl_lines(f.read_text(encoding="utf-8", errors="replace")), 1):
            if not raw:
                continue
            try:
                ev = json.loads(raw)
            except json.JSONDecodeError:
                print(f"[warn] {name}:{number} 无法解析，keylog 证据可能不完整", file=sys.stderr)
                continue
            if ev.get("ev") != "TLS_KEYLOG":
                continue
            line = str(ev.get("line") or "").strip()
            # 收的是 NSS keylog 行：`<LABEL> <client_random> <secret>`。
            # 只按结构校验（3 段、前两段是 hex）——**不要**用正则去枚举标签，
            # TLS 1.3 的 `CLIENT_HANDSHAKE_TRAFFIC_SECRET` 之类会漏，而且写错一个
            # 字符就会静默返回 0 行（本文件第一版就是这么挂的）。
            parts = line.split()
            if len(parts) != 3 or line in seen:
                continue
            if not all(re.fullmatch(r"[0-9a-fA-F]+", p) for p in parts[1:]):
                continue
            seen.add(line)
            lines.append(line)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
    labels = sorted({ln.split(" ")[0] for ln in lines})
    return len(lines), ",".join(labels)


def _run_tshark(tshark: str, pcap: Path, keylog: Path | None,
                extra: list[str], timeout: int = 600) -> tuple[int, str, str]:
    cmd = [tshark, "-r", str(pcap), "-n",
           "-o", "http.decompress_body:TRUE",
           "-o", "http.desegment_body:TRUE",
           "-o", "tcp.desegment_tcp_streams:TRUE"]
    if keylog and keylog.exists() and keylog.stat().st_size:
        cmd += ["-o", f"tls.keylog_file:{keylog}"]
    cmd += extra
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8",
                           errors="replace", timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 1, "", f"{type(exc).__name__}: {exc}"
    return r.returncode, r.stdout or "", r.stderr or ""


def _as_text(v) -> str:
    if v is None:
        return ""
    if isinstance(v, list):
        return ",".join(_as_text(x) for x in v)
    return str(v)


def _parse_hex(v: str) -> bytes | None:
    """`http.file_data` 在 `-T json` 里是 hex 串（无分隔）。非 hex 返回 None。"""
    s = re.sub(r"[^0-9a-fA-F]", "", v)
    if not s or len(s) % 2:
        return None
    return bytes.fromhex(s)


