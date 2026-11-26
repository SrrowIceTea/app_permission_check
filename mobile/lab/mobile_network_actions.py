"""Owned mobile emulator network cut/restore for offline-resend controls. 仅用于授权测试。

只作用于明确选择的自有手机模拟器（ro.kernel.qemu=1 且非 automotive）。

断网手段的选择有实测依据（API 36 google_apis 镜像）：
- `cmd wifi set-wifi-enabled disabled` **不能**断网：wlan0 关掉后 eth0 立即接管
  并保有 10.0.2.15，10.0.2.2 仍可达（实测 ping 0% 丢包）。
- `cmd connectivity airplane-mode enable` 能同时放倒 eth0/wlan0，10.0.2.2 返回
  "Network is unreachable"，且 adb 与 adb reverse 不受影响（走调试通道，不走客户机 IP 网络）。
因此断网用飞行模式，判据要求"无回环以外的 IPv4 地址"。

每一步都把可核对的设备状态读回写盘；close() 恢复联网并写 cleanup 记录。
车载同名工具带 AAOS feature 限制，手机模拟器不满足，故单独实现。
"""
from __future__ import annotations

import hashlib
import json
import re
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "mobile/tools"))
from device_environment import AdbClient  # noqa: E402

INET = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}/\d+\b")


class MobileNetworkActions:
    def __init__(self, adb: AdbClient, output: Path):
        if adb("shell", "getprop", "ro.kernel.qemu").stdout.strip() != "1":
            raise RuntimeError("网络测试动作仅允许自有模拟器")
        features = adb("shell", "pm", "list", "features").stdout
        if "automotive" in features:
            raise RuntimeError("本工具仅用于手机模拟器，车载请用 vehicle_environment_actions")
        self.adb, self.output = adb, output
        self.original_airplane = self._airplane()
        self.modified = False

    def _shell(self, *args):
        result = self.adb("shell", *map(str, args))
        if result.returncode != 0:
            raise RuntimeError(f"ADB shell {args[:2]} 失败: {result.stderr.strip()[:120]}")
        return result.stdout.strip()

    def _airplane(self) -> str:
        return self._shell("settings", "get", "global", "airplane_mode_on")

    def _wifi_status(self) -> str:
        return self._shell("cmd", "wifi", "status")

    def _interfaces(self) -> str:
        return self._shell("ip", "-brief", "addr")

    def _routable(self):
        """UP 且非回环的 IPv4 地址；空表示客户机没有可用数据网络。

        `ip -brief addr` 在接口 DOWN 后仍会显示残留地址（飞行模式下 eth0 就是
        `DOWN 10.0.2.15/24`），所以必须先看链路状态，否则断网会被判成没生效。
        """
        found = []
        for line in self._interfaces().splitlines():
            parts = line.split()
            if len(parts) < 2:
                continue
            name, state = parts[0].rstrip(":"), parts[1]
            if name in ("lo", "") or state != "UP":
                continue
            found.extend(INET.findall(" ".join(parts[2:])))
        return found

    def _wait(self, predicate, description, seconds):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if predicate():
                return
            time.sleep(0.3)
        raise RuntimeError(f"{description}（airplane={self._airplane()} "
                           f"addr={self._routable()}）")

    def apply(self, action: str, token: str) -> dict:
        if action not in ("net_off", "net_on"):
            raise ValueError(f"不支持的网络动作: {action}")
        self.modified = True
        if action == "net_off":
            self._shell("cmd", "connectivity", "airplane-mode", "enable")
            # 必须"飞行模式已开 **且** 没有可路由地址"才算断网成立；
            # 只看设置项会被 eth0 兜底骗过。
            self._wait(lambda: self._airplane() == "1" and not self._routable(),
                       "断网未生效", 20)
        else:
            self._shell("cmd", "connectivity", "airplane-mode", "disable")
            self._wait(lambda: self._airplane() == "0" and bool(self._routable()),
                       "网络未恢复", 25)
            # 让 DHCP/路由稳定下来，避免紧接着的补传打在切换瞬间。
            time.sleep(1)
        record = {"action": action, "airplane_mode": self._airplane(),
                  "wifi_status": self._wifi_status(), "routable": self._routable(),
                  "interfaces": self._interfaces()}
        path = self.output / (token + "-environment.json")
        path.write_text(json.dumps(record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        return {"completed": True, "mode": action, "source": "owned_mobile_controller",
                **record, "evidence_sha256": hashlib.sha256(path.read_bytes()).hexdigest()}

    def close(self) -> dict:
        result = {"cleanup_ok": True}
        if self.modified:
            try:
                self._shell("cmd", "connectivity", "airplane-mode", "disable")
                self._wait(lambda: self._airplane() == "0" and bool(self._routable()),
                           "联网未恢复", 25)
                result["observed"] = {"airplane_mode": self._airplane(),
                                      "routable": self._routable(),
                                      "interfaces": self._interfaces()}
                result["cleanup_ok"] = self._airplane() == "0" and bool(result["observed"]["routable"])
                result["original_airplane"] = self.original_airplane
            except Exception as error:  # noqa: BLE001
                result["cleanup_ok"] = False
                result["error"] = str(error)
            (self.output / "environment-cleanup.json").write_text(
                json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        return result
