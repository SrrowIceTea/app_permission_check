"""Fixed self-owned fixture gate and explicit read-only enumeration. 仅用于授权测试。"""
from __future__ import annotations
import hashlib
import os
import re
import shutil
import subprocess
from pathlib import Path
from mobile.workbench.store import ROOT, now
PKG = "com.vscanner.privacydemo"
APK_ROOT = ROOT / "mobile/fixture-app/app/build/outputs/apk"
SERIAL = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")


def sha(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        while block := handle.read(1 << 20):
            digest.update(block)
    return digest.hexdigest()


def adb_path():
    explicit = os.environ.get("VSCAN_ADB")
    if explicit:
        found = shutil.which(explicit) or (explicit if Path(explicit).is_file() else None)
        if not found:
            raise ValueError("服务端指定 ADB 不存在")
        return str(Path(found).resolve())
    for key in ("VSCAN_SDK", "ANDROID_SDK_ROOT", "ANDROID_HOME"):
        if os.environ.get(key):
            for name in ("adb.exe", "adb"):
                path = Path(os.environ[key]) / "platform-tools" / name
                if path.is_file():
                    return str(path.resolve())
    found = shutil.which("adb") or shutil.which("adb.exe")
    if not found:
        raise ValueError("服务端 ADB 未就绪；工作台不会自动安装工具")
    return found


def devices():
    result = subprocess.run([adb_path(), "devices", "-l"], capture_output=True, text=True,
                            encoding="utf-8", errors="replace", timeout=15)
    if result.returncode:
        raise ValueError(result.stderr.strip() or "设备枚举失败")
    values = []
    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) < 2 or parts[0] == "List" or not SERIAL.fullmatch(parts[0]):
            continue
        fields = dict(p.split(":", 1) for p in parts[2:] if ":" in p)
        values.append({"serial": parts[0], "state": parts[1], "model": fields.get("model")})
    return {"devices": values, "observed_at": now(), "reason": "只读枚举；没有启动设备或采集"}


def fixture_binding(store, task):
    if task.get("origin") != "uploaded_apk" or task["apk"].get("package") != PKG:
        raise ValueError("设备采集仅支持已完成静态识别的自有隐私夹具上传任务")
    source = store.cache_dir(task)
    uploaded = source / "uploaded.apk" if source else None
    if not uploaded or not uploaded.is_file() or sha(uploaded) != task["apk"].get("sha256"):
        raise ValueError("上传 APK 缺失或摘要已改变")
    gadget = APK_ROOT / "gadget/app-gadget.apk"
    debug = APK_ROOT / "debug/app-debug.apk"
    if not gadget.is_file():
        raise ValueError("固定自有 Gadget 夹具尚未构建")
    digests = {"gadget": sha(gadget)}
    if debug.is_file():
        digests["debug"] = sha(debug)
    variant = next((k for k, v in digests.items() if v == task["apk"]["sha256"]), None)
    if not variant:
        raise ValueError("上传摘要不属于服务端固定自有 Debug/Gadget 夹具，禁止替换被测 APK")
    return {"package": PKG, "source_apk_sha256": task["apk"]["sha256"],
            "capture_apk_sha256": digests["gadget"], "uploaded_variant": variant,
            "capture_variant": "gadget", "same_apk_bytes": variant == "gadget",
            "relation": "same_fixture_build_variants_declared" if variant == "debug" else "identical_apk_bytes",
            "relation_note": "固定自有源码夹具的构建变体；Debug 与 Gadget 不是同一 APK，动态结果来自 Gadget"}
