"""Single explicitly selected root emulator, bounded observation. 仅用于授权测试。"""
from __future__ import annotations
import json
import hashlib
import re
import subprocess
import threading
import time
import xml.etree.ElementTree as ET
from pathlib import Path
import frida


def session_identifier(session: Path) -> str:
    """One stable, attempt-specific identity shared by hooks and proxy."""
    return session.parent.name[:80] + "-" + hashlib.sha256(str(session.resolve()).encode()).hexdigest()[:16]


def save(path: Path, value):
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


class Android:
    def __init__(self, adb: str, serial: str):
        if not re.fullmatch(r"emulator-\d+", serial):
            raise ValueError("this runner accepts a dedicated emulator only, never a USB phone")
        self.adb, self.serial = adb, serial
        self.folder = None
        self.sequence = 0

    def call(self, *args, check=True, binary=False, timeout=60):
        result = subprocess.run([self.adb, "-s", self.serial, *map(str, args)],
                                capture_output=True, timeout=timeout)
        if binary:
            if check and result.returncode:
                raise RuntimeError(result.stderr.decode("utf-8", errors="replace"))
            return result.stdout
        out, err = (x.decode("utf-8", errors="replace") for x in (result.stdout, result.stderr))
        if self.folder:
            self.sequence += 1
            save(self.folder / f"adb-{self.sequence:03d}.json", {"args": list(map(str, args)),
                 "exit_code": result.returncode, "stdout": out, "stderr": err})
        if check and result.returncode:
            raise RuntimeError(f"adb {args[0]} failed: {err or out}")
        return out

    def shell(self, *args, **kwargs):
        return self.call("shell", *args, **kwargs)

    def profile(self):
        if "uid=0(" not in self.shell("id"):
            raise RuntimeError("selected emulator is not root; prepare the dedicated emulator first")
        return {"serial": self.serial, "android_api": self.shell("getprop", "ro.build.version.sdk").strip(),
                "model": self.shell("getprop", "ro.product.model").strip(), "root": True,
                "mode": "root-emulator-frida-server", "apk_modified": False,
                "system_ca_modified": False}

    def screen(self, name):
        self.shell("uiautomator", "dump", "/data/local/tmp/vscanner-root-ui.xml", timeout=30)
        raw = self.shell("cat", "/data/local/tmp/vscanner-root-ui.xml")
        if self.folder:
            (self.folder / (name + ".xml")).write_text(raw, encoding="utf-8")
        return ET.fromstring(raw)

    def tap(self, view, resource_id):
        nodes = [n for n in view.iter("node") if n.get("resource-id") == resource_id
                 and n.get("enabled") == "true"]
        if len(nodes) != 1:
            raise RuntimeError("expected one enabled UI target: " + resource_id)
        x1, y1, x2, y2 = map(int, re.findall(r"\d+", nodes[0].get("bounds", "")))
        self.shell("input", "tap", (x1 + x2) // 2, (y1 + y2) // 2)

    def ready_screen(self):
        view = self.screen("launch-ui")
        messages = " ".join(n.get("text", "") for n in view.iter("node"))
        if "older version of Android" in messages or "此应用专为旧版 Android" in messages:
            self.tap(view, "android:id/button1")
            view = self.screen("ready-ui")
        return view

    def fill(self, view, resource_id, value):
        if re.fullmatch(r"[A-Za-z0-9_@.,-]+", value) is None:
            raise ValueError("only declared synthetic ASCII input is accepted")
        self.tap(view, resource_id)
        self.shell("input", "text", value)
        self.shell("input", "keyevent", "4")


class Observer:
    def __init__(self, device, package, bundle, folder, session_id):
        self.device, self.folder, self.package = device, folder, package
        self.session_id = session_id
        self.events, self.errors = [], []
        self.ready = threading.Event()
        self.file = (folder / "events.jsonl").open("w", encoding="utf-8")
        self.session, self.script, self.pid = None, None, None
        self.source = "globalThis.__VSCAN_AUDIT_PACKAGES__=" + json.dumps([package]) + ";\n" + bundle

    def message(self, message, data):
        if message.get("type") == "send":
            row = message.get("payload", {})
            if isinstance(row, dict) and isinstance(row.get("line"), str):
                row = json.loads(row["line"])
            if not isinstance(row, dict):
                return
            row["session_id"] = self.session_id
            self.events.append(row)
            if row.get("ev") == "ARMED":
                self.ready.set()
        else:
            self.errors.append(message)
            row = {"ev": "SCRIPT_ERROR", "message": message, "session_id": self.session_id}
        self.file.write(json.dumps(row, ensure_ascii=False) + "\n")
        self.file.flush()

    def start(self):
        self.pid = self.device.spawn([self.package])
        self.session = self.device.attach(self.pid)
        self.script = self.session.create_script(self.source)
        self.script.on("message", self.message)
        self.script.load()
        self.device.resume(self.pid)
        if not self.ready.wait(25):
            raise RuntimeError("probe did not become ARMED: " + json.dumps(self.errors)[:500])
        return self.pid

    def close(self):
        for obj, method in ((self.script, "unload"), (self.session, "detach")):
            if obj:
                try:
                    getattr(obj, method)()
                except Exception as exc:
                    self.errors.append({"cleanup": str(exc)})
        self.file.close()
        save(self.folder / "observer-errors.json", self.errors)


class Capture:
    def __init__(self, android, folder, token, interface):
        self.android, self.folder = android, folder
        self.remote = "/data/local/tmp/vscanner-" + token + ".pcap"
        if interface not in {"lo", "eth0", "wlan0", "any"}:
            raise ValueError("unsupported explicitly selected capture interface")
        command = (f"tcpdump -i {interface} -s 0 -U -w {self.remote} 'tcp port 5000' "
                   f">{self.remote}.log 2>&1 </dev/null & echo $!")
        self.pid = android.shell(command).strip()
        if not self.pid.isdigit():
            raise RuntimeError("tcpdump did not return its own PID")
        time.sleep(.4)
        android.shell("kill", "-0", self.pid)

    def close(self, canary):
        from mobile.lab.pcap_inventory import inventory
        from mobile.lab.root_tcp import reassemble
        self.android.shell("kill", "-2", self.pid)
        time.sleep(.7)
        self.android.call("pull", self.remote, self.folder / "traffic.pcap")
        self.android.call("pull", self.remote + ".log", self.folder / "tcpdump.log")
        with (self.folder / "traffic.pcap").open("rb") as source, (self.folder / "packets.jsonl").open("w", encoding="utf-8") as output:
            value = inventory(source, lambda r: output.write(json.dumps(r) + "\n"), canary.encode())
        streams = reassemble(self.folder / "traffic.pcap", canary)
        save(self.folder / "tcp-streams.json", streams)
        value["tcp_streams"] = streams["summary"]
        save(self.folder / "pcap-summary.json", value)
        return value
