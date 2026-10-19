"""App-owned Gadget transport for the original four-hook session. 仅用于授权测试。

No server, spawn, privilege escalation, app return-value changes or CA modification.
The repackager must load a loopback listen/wait Gadget during Application startup.
"""
from __future__ import annotations
import json
import threading
import time
import frida
from core.frida_host.bundle_config import configure
from mobile.lab.core_observer import CoreObserver, MODULES, compile_session


class GadgetObserver(CoreObserver):
    def __init__(self, package, session, serial, android, port=27042):
        super().__init__(package, session, serial, android, endpoint=None)
        self.endpoint = f"127.0.0.1:{port}"

    def start(self):
        cache = self.path.parent / "compiled-hooks"
        cache.mkdir()
        body = "globalThis.__VSCAN_AUDIT_PACKAGES__=" + json.dumps([self.package]) + ";\n" + compile_session(cache)
        for name in [*MODULES, "audit"]:
            self.files[name] = (self.path / (name + ".jsonl")).open("w", encoding="utf-8")
            self.events[name], self.ready[name] = [], threading.Event()
        resolved = self.android.shell("cmd", "package", "resolve-activity", "--brief", "-c",
                                     "android.intent.category.LAUNCHER", self.package)
        components = [s.strip() for s in resolved.splitlines() if "/" in s and " " not in s.strip()]
        if len(components) != 1 or not components[0].startswith(self.package + "/"):
            raise RuntimeError("target has no unique device-resolved launcher: " + resolved)
        # -W would wait for an Activity whose application is intentionally paused in Gadget.
        self.android.shell("am", "start", "-n", components[0])
        deadline, processes = time.monotonic() + 30, []
        while time.monotonic() < deadline:
            try:
                if self.device is None:
                    self.device = frida.get_device_manager().add_remote_device(self.endpoint)
                processes = self.device.enumerate_processes()
                if processes:
                    break
            except (frida.TransportError, frida.ServerNotRunningError, frida.TimedOutError):
                pass
            time.sleep(.2)
        pids = self.android.shell("pidof", self.package, check=False).strip().split()
        if len(processes) != 1 or len(pids) != 1 or str(processes[0].pid) != pids[0]:
            raise RuntimeError("Gadget PID does not uniquely match the selected package: " + repr(pids))
        self.pid = processes[0].pid
        self.session = self.device.attach(self.pid)
        self.session.on("detached", lambda *args: self.dead.set())
        script = self.session.create_script(configure(body, [self.package]))
        script.on("message", lambda msg, data: self.receive("reads", msg, data))
        script.load()
        self.scripts["combined"] = script
        self.device.resume(self.pid)
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline and not self.dead.is_set():
            if all(e.is_set() for e in self.ready.values()):
                break
            time.sleep(.1)
        missing = [name for name, event in self.ready.items() if not event.is_set()]
        if missing:
            raise RuntimeError("Gadget hooks did not arm: " + repr(missing) + "; " + repr(self.errors))
        return self.pid
