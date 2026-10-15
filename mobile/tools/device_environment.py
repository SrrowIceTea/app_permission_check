"""Portable ADB and isolated fixture transport. 仅用于授权测试（自有 APK/设备）。"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MOBILE = ROOT / "mobile"
PKG = "com.vscanner.privacydemo"


def resolve_adb(override: str | None = None) -> str:
    """Explicit override → SDK → PATH → current-user SDK; invalid override fails."""
    explicit = override or os.environ.get("VSCAN_ADB")
    if explicit:
        found = shutil.which(explicit) or (explicit if Path(explicit).is_file() else None)
        if not found:
            raise FileNotFoundError(f"找不到指定 ADB: {explicit}")
        return str(Path(found).resolve())
    candidates = []
    for env in ("VSCAN_SDK", "ANDROID_SDK_ROOT", "ANDROID_HOME"):
        if os.environ.get(env):
            candidates.append(Path(os.environ[env]) / "platform-tools")
    for base in candidates:
        for name in ("adb.exe", "adb"):
            if (base / name).is_file():
                return str((base / name).resolve())
    found = shutil.which("adb") or shutil.which("adb.exe")
    if found:
        return str(Path(found).resolve())
    for base in (Path.home() / "AppData/Local/Android/Sdk", Path.home() / "Android/Sdk",
                 Path.home() / "Library/Android/sdk", Path.home() / "Android/sdk"):
        for name in ("adb.exe", "adb"):
            if (base / "platform-tools" / name).is_file():
                return str((base / "platform-tools" / name).resolve())
    raise FileNotFoundError("找不到 adb；设 VSCAN_ADB 或 ANDROID_SDK_ROOT")


class AdbClient:
    def __init__(self, executable: str, serial: str | None):
        self.executable, self.serial = executable, serial

    def __call__(self, *args: str, timeout: int = 60) -> subprocess.CompletedProcess:
        command = [self.executable]
        if self.serial:
            command += ["-s", self.serial]
        return subprocess.run(command + list(args), capture_output=True, text=True,
                              encoding="utf-8", errors="replace", timeout=timeout)

    def environment(self) -> dict:
        env = dict(os.environ)
        env["VSCAN_ADB"] = self.executable
        env["PATH"] = str(Path(self.executable).parent) + os.pathsep + env.get("PATH", "")
        if self.serial:
            env["ANDROID_SERIAL"] = self.serial
        else:
            env.pop("ANDROID_SERIAL", None)
        return env

    def select_device(self) -> str:
        result = self("devices", "-l")
        if result.returncode:
            raise RuntimeError(result.stderr.strip() or "adb devices 失败")
        available = [line.split()[0] for line in result.stdout.splitlines()
                     if len(line.split()) > 1 and line.split()[1] == "device"]
        if self.serial:
            if self.serial not in available:
                raise RuntimeError(f"指定设备未就绪: {self.serial}")
        elif len(available) == 1:
            self.serial = available[0]
        else:
            raise RuntimeError(f"需要明确 --serial；在线设备={available}")
        return self.serial


def wait_boot(adb: AdbClient, timeout_s: int = 240) -> bool:
    end = time.monotonic() + timeout_s
    while time.monotonic() < end:
        if adb("shell", "getprop", "sys.boot_completed", timeout=20).stdout.strip() == "1":
            return True
        time.sleep(4)
    return False


def wait_for_app(adb: AdbClient, timeout_s: int = 40) -> str | None:
    end = time.monotonic() + timeout_s
    while time.monotonic() < end:
        pid = adb("shell", "pidof", PKG, timeout=20).stdout.strip()
        if pid:
            return pid
        time.sleep(1.5)
    return None


def collect_device_profile(adb: AdbClient, mode: str) -> dict:
    identity = adb("shell", "id")
    match = re.search(r"\buid=(\d+)", identity.stdout)
    profile = {"serial": adb.serial, "shell_id": identity.stdout.strip(),
               "shell_uid": int(match[1]) if match else None,
               "identity_exit_code": identity.returncode}
    for name in ("ro.debuggable", "ro.build.type", "ro.build.fingerprint",
                 "ro.product.cpu.abilist", "ro.product.cpu.abi"):
        result = adb("shell", "getprop", name)
        profile[name] = result.stdout.strip() if result.returncode == 0 else None
    profile["nonroot_shell_observed"] = (identity.returncode == 0
                                             and profile["shell_uid"] not in (None, 0))
    profile["environment_class"] = (
        "production-user-nonroot-path" if profile["ro.build.type"] == "user"
        and profile["ro.debuggable"] == "0" and profile["nonroot_shell_observed"]
        else "restricted-path-on-debuggable-image" if mode == "gadget"
        else "root-server-path")
    profile["boundary"] = "shell uid 非 0 不证明设备没有 su；userdebug 不等同锁定生产机"
    return profile


def ensure_transport(adb: AdbClient, mode: str, port: int, log: Path) -> bool:
    """Gadget path only forwards an app-owned loopback listener; no root fallback."""
    if mode == "gadget":
        result = adb("forward", "--no-rebind", f"tcp:{port}", f"tcp:{port}")
        log.write_text(result.stdout + result.stderr, encoding="utf-8")
        return result.returncode == 0
    # Legacy root route is explicit and intentionally separate from Gadget.
    output = []
    for command in (("root",), ("wait-for-device",)):
        result = adb(*command)
        output.append(result.stdout + result.stderr)
        if result.returncode:
            log.write_text("\n".join(output), encoding="utf-8")
            return False
        time.sleep(3)
    ps = adb("shell", "ps -A -o USER,NAME | grep frida-server").stdout
    if "root" not in ps:
        # Do not kill an unknown pre-existing service or silently replace its binary.
        adb("shell", f"nohup /data/local/tmp/frida-server -l 127.0.0.1:{port} "
            ">/dev/null 2>&1 &")
        time.sleep(5)
        ps = adb("shell", "ps -A -o USER,NAME | grep frida-server").stdout
    existing = adb("forward", "--list").stdout
    pair = f"{adb.serial} tcp:{port} tcp:{port}"
    reuse = any(line.strip() == pair for line in existing.splitlines())
    forward = (subprocess.CompletedProcess([], 0, "", "") if reuse else
               adb("forward", "--no-rebind", f"tcp:{port}", f"tcp:{port}"))
    log.write_text("\n".join(output) + "\n" + ps + forward.stderr, encoding="utf-8")
    return "root" in ps and "frida-server" in ps and forward.returncode == 0
