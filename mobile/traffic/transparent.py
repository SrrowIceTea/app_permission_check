#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""让第三方 App 的流量**无法绕过**抓包：模拟器级强制代理 + 系统级 CA。

仅用于授权测试（自有设备 / 已授权的公开第三方样本）。

## 为什么不是 iptables

最直觉的方案是设备上 `iptables -t nat -A OUTPUT ... -j REDIRECT --to-ports 8888`，
把流量劫到代理。**但它在"代理跑在宿主机"这个布局下不成立**：

    REDIRECT/DNAT 只改写包的去向，**原始目标地址存在做重定向那台机器的 conntrack 里**。
    mitmproxy 在宿主机，收到的是来自 adbd 的普通 TCP 连接，
    `SO_ORIGINAL_DST` 查不到原目标 → 它不知道该连哪台服务器。

要让它成立，mitmproxy 必须与 iptables 同机（即跑在设备上，如 Termux 方案）。
所以在模拟器上用**等价且更可靠**的机制：

    emulator -http-proxy http://10.0.2.2:8888       # SLIRP 层强制走代理

它在虚拟路由器那一层把 TCP 连接交给代理，**不依赖应用是否读取系统代理设置**——
实测 NewPipe 用 loopj/AsyncHttpClient，`http_proxy` 设置了也完全不理会，
而 `-http-proxy` 对它有效。这正是之前 flows.jsonl 为空的原因。

## 还有一半是 CA

流量被导到代理之后，HTTPS 仍会因证书校验失败而断。
系统级 CA 能让**所有**应用信任代理证书（不必逐 App 上 TLS 绕过钩子）。
装系统 CA 需要可写 /system —— 实测本 AVD `adb remount` 报
"Device must be bootloader unlocked"，**必须用 `-writable-system` 启动模拟器**。

## 这两件事都要重启模拟器

所以本模块只做两件事：**把该加的启动参数算出来**、**把该装的 CA 装进去**；
什么时候重启模拟器由使用者决定（重启会打断同机上其他正在跑的采集）。
"""
from __future__ import annotations

import hashlib
import subprocess
import sys
from pathlib import Path

# SDK 路径解析统一走 core/sdk_paths（§8.2 B-4）：不再写死本机绝对路径。
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from core import sdk_paths  # noqa: E402

ADB = sdk_paths.sdk_tool("platform-tools", "adb.exe")
CA_PEM = Path.home() / ".mitmproxy" / "mitmproxy-ca-cert.pem"
SYSTEM_CA_DIR = "/system/etc/security/cacerts"
MITM_PORT = 8888
EMULATOR_HOST = "10.0.2.2"      # 模拟器里指向宿主机


# --------------------------------------------------------------------------
# 纯计算部分（可离线测试）
# --------------------------------------------------------------------------

def android_ca_name(pem_path: Path) -> tuple[str, str]:
    """证书 → Android 系统 CA 库要求的文件名 `<subject_hash_old>.0`。

    Android 用 OpenSSL 的 **old** subject hash（MD5，不是 SHA-1 的新式哈希）：
    对 DER 编码的 subject Name 求 MD5，取**前 4 字节按小端**读成整数，
    再格式化成 8 位十六进制。写成别的名字，系统会直接忽略这个证书，
    而且**不会报错**——表现是"CA 装了但 HTTPS 照样失败"。
    """
    from cryptography import x509
    cert = x509.load_pem_x509_certificate(pem_path.read_bytes())
    der = cert.subject.public_bytes()
    digest = hashlib.md5(der).digest()
    hash_int = int.from_bytes(digest[:4], byteorder="little")
    return f"{hash_int:08x}", f"{hash_int:08x}.0"


def emulator_capture_args(port: int = MITM_PORT, host: str = EMULATOR_HOST,
                          writable_system: bool = True) -> list[str]:
    """模拟器启动参数（追加到常规参数之后）。

    -http-proxy     SLIRP 层强制走代理：应用绕不过去
    -writable-system 允许 adb remount，装系统 CA 用
    -no-snapshot-load 每次都从干净状态起：抓包要的是**首次运行**行为
    """
    args = ["-http-proxy", f"http://{host}:{port}", "-no-snapshot-load"]
    if writable_system:
        args.append("-writable-system")
    return args


def iptables_rules(uid: int, port: int = MITM_PORT) -> dict[str, list[str]]:
    """**真机 + 设备侧代理**场景的规则（模拟器上不要用，见模块开头的说明）。

    只导出规则，不在设备上执行：给真机部署留一个可核对的接口。
    按 uid 限定，避免把系统流量一起劫走。
    """
    owner = ["-m", "owner", "--uid-owner", str(uid)]
    return {
        "check": ["iptables", "-t", "nat", "-C", "OUTPUT", "-p", "tcp", *owner,
                  "-j", "REDIRECT", "--to-ports", str(port)],
        "add": ["iptables", "-t", "nat", "-A", "OUTPUT", "-p", "tcp", *owner,
                "-j", "REDIRECT", "--to-ports", str(port)],
        "del": ["iptables", "-t", "nat", "-D", "OUTPUT", "-p", "tcp", *owner,
                "-j", "REDIRECT", "--to-ports", str(port)],
        "precondition": ("代理必须跑在**设备本机**（如 Termux 里的 mitmproxy）；"
                         "代理在宿主机时 SO_ORIGINAL_DST 取不到原目标，规则等于白加"),
    }


# --------------------------------------------------------------------------
# 设备操作
# --------------------------------------------------------------------------

def adb(*args: str, timeout: int = 60) -> subprocess.CompletedProcess:
    return subprocess.run([ADB, *args], capture_output=True, text=True,
                          encoding="utf-8", errors="replace", timeout=timeout)


def ca_installed(pem_path: Path = CA_PEM) -> tuple[bool, str]:
    _, fname = android_ca_name(pem_path)
    out = adb("shell", f"ls {SYSTEM_CA_DIR}/{fname}", timeout=30)
    return ("No such file" not in out.stdout and out.returncode == 0), fname


def install_system_ca(pem_path: Path = CA_PEM, log: Path | None = None) -> dict:
    """把 mitmproxy 的 CA 装进系统信任库。返回状态字典（不抛异常）。"""
    result: dict = {"installed": False, "steps": [], "error": None}
    if not pem_path.exists():
        result["error"] = f"找不到 CA：{pem_path}（先跑一次 mitmdump 会生成）"
        return result
    name, fname = android_ca_name(pem_path)
    result["ca_name"] = fname

    steps = [
        ("root", ["root"]),
        ("remount", ["remount"]),      # 需要模拟器以 -writable-system 启动
    ]
    for label, args in steps:
        p = adb(*args, timeout=120)
        result["steps"].append({"step": label, "rc": p.returncode,
                                "out": (p.stdout + p.stderr).strip()[:200]})
        if p.returncode != 0 and label == "remount":
            result["error"] = ("adb remount 失败——系统不可写。"
                               "必须用 `-writable-system` 重新启动模拟器"
                               "（见 emulator_capture_args()）。")
            if log:
                log.write_text(str(result), encoding="utf-8")
            return result

    push = adb("push", str(pem_path), f"/sdcard/{fname}", timeout=120)
    result["steps"].append({"step": "push", "rc": push.returncode,
                            "out": (push.stdout + push.stderr).strip()[:200]})
    move = adb("shell",
               f"cp /sdcard/{fname} {SYSTEM_CA_DIR}/{fname} && "
               f"chmod 644 {SYSTEM_CA_DIR}/{fname} && "
               f"chown root:root {SYSTEM_CA_DIR}/{fname} && "
               f"ls -l {SYSTEM_CA_DIR}/{fname}", timeout=120)
    result["steps"].append({"step": "install", "rc": move.returncode,
                            "out": (move.stdout + move.stderr).strip()[:200]})
    ok, _ = ca_installed(pem_path)
    result["installed"] = ok
    if not ok:
        result["error"] = "证书已拷贝但复核没通过——检查文件名与权限（644/root:root）"
    if log:
        log.write_text(str(result), encoding="utf-8")
    return result


def capture_verdict() -> dict:
    """当前设备状态下，抓包的**哪一半**已经具备。用来解释"为什么没有 flows"。"""
    proxy = adb("shell", "settings", "get", "global", "http_proxy", timeout=30).stdout.strip()
    ok_ca, fname = ca_installed()
    return {
        "global_http_proxy": proxy,
        "global_proxy_note": ("应用可以不理会它——实测 NewPipe(loopj) 就完全不走；"
                              "它只是「尽力而为」，不是强制"),
        "system_ca_installed": ok_ca,
        "system_ca_name": fname,
        "recommended": {
            "force_proxy": "emulator -http-proxy http://10.0.2.2:8888（SLIRP 层强制，应用绕不过）",
            "trust_ca": "emulator -writable-system + install_system_ca()",
            "note": "两者都要重启模拟器；重启会打断同机上其他正在跑的采集",
        },
    }


if __name__ == "__main__":
    import argparse
    import json
    import sys
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--status", action="store_true")
    ap.add_argument("--install-ca", action="store_true")
    ap.add_argument("--emulator-args", action="store_true")
    ap.add_argument("--uid", type=int, help="打印该 uid 的 iptables 规则（真机场景）")
    args = ap.parse_args()

    if args.emulator_args:
        print(" ".join(emulator_capture_args()))
    elif args.install_ca:
        print(json.dumps(install_system_ca(), ensure_ascii=False, indent=2))
    elif args.uid is not None:
        print(json.dumps(iptables_rules(args.uid), ensure_ascii=False, indent=2))
    else:
        print(json.dumps(capture_verdict(), ensure_ascii=False, indent=2))
