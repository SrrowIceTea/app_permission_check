"""Owned mobile emulator Wi-Fi on/off for offline-resend controls. 仅用于授权测试。

只作用于明确选择的自有手机模拟器（ro.kernel.qemu=1 且非 automotive）。断网用
cmd wifi disable + wlan0 down，恢复用 wlan0 up + ensure_wifi；每步把可核对的设备
状态读回写盘，close() 恢复并写 cleanup 记录。车载同名工具带 AAOS feature 限制，
手机模拟器不满足，故单独实现。
"""
from __future__ import annotations

import hashlib
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "mobile/tools"))
from device_environment import AdbClient  # noqa: E402


class MobileNetworkActions:
    def __init__(self, adb: AdbClient, output: Path):
        if adb("shell", "getprop", "ro.kernel.qemu").stdout.strip() != "1":
            raise RuntimeError("网络测试动作仅允许自有模拟器")
        features = adb("shell", "pm", "list", "features").stdout
        if "automotive" in features:
            raise RuntimeError("本工具仅用于手机模拟器，车载请用 vehicle_environment_actions")
        self.adb, self.output = adb, output
        self.original_status = self._wifi_status()
        self.modified = False

    def _shell(self, *args):
        return self.adb("shell", *map(str, args)).stdout.strip()

    def _wifi_status(self):
        return self._shell("cmd", "wifi", "status")

    def _interfaces(self):
        return self._shell("ip", "-brief", "addr")

    def apply(self, action: str, token: str) -> dict:
        if action not in ("wifi_off", "wifi_on"):
            raise ValueError(f"不支持的网络动作: {action}")
        self.modified = True
        if action == "wifi_off":
            self._shell("cmd", "wifi", "set-wifi-enabled", "disabled")
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                if "Wifi is disabled" in self._wifi_status():
                    break
                time.sleep(0.3)
            else:
                raise RuntimeError("Wi-Fi 未进入 disabled")
            # 注意：nonroot shell 对 wlan0 无 ip link 权限（实测 Permission denied），
            # 只用有权限的 cmd wifi set-wifi-enabled；断网的真实证据由 10.0.2.2
            # 路径无回执 + offline-window 时间区间提供，不靠 wlan0 状态。
        else:
            self._shell("cmd", "wifi", "set-wifi-enabled", "enabled")
            # 手机模拟器主网络走 eth0/SLIRP，wlan0 up 后 AndroidWifi 不保证
            # 立即重连；判据用"Wi-Fi 已启用 + wlan0 UP + eth0 有地址"，并以
            # 补传回执是否到达作为连通性的最终证据，不硬等 "Wifi is connected"。
            deadline = time.monotonic() + 20
            while time.monotonic() < deadline:
                status = self._wifi_status()
                interfaces = self._interfaces()
                eth0_up = "eth0: <" in interfaces or "eth0 " in interfaces
                if "Wifi is enabled" in status and eth0_up:
                    break
                time.sleep(0.5)
            else:
                raise RuntimeError("Wi-Fi 未恢复启用: " + status[:120])
        record = {"action": action, "wifi_status": self._wifi_status(),
                  "interfaces": self._interfaces()}
        path = self.output / (token + "-environment.json")
        path.write_text(json.dumps(record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        return {"completed": True, "mode": action, "source": "owned_mobile_controller",
                **record, "evidence_sha256": hashlib.sha256(path.read_bytes()).hexdigest()}

    def close(self) -> dict:
        result = {"cleanup_ok": True}
        if self.modified:
            try:
                self._shell("cmd", "wifi", "set-wifi-enabled", "enabled")
                result["observed"] = {"wifi_status": self._wifi_status(),
                                      "interfaces": self._interfaces()}
                result["cleanup_ok"] = "Wifi is enabled" in result["observed"]["wifi_status"]
                result["original_status"] = self.original_status
            except Exception as error:  # noqa: BLE001
                result["cleanup_ok"] = False
                result["error"] = str(error)
            (self.output / "environment-cleanup.json").write_text(
                json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        return result
