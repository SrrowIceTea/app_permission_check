"""Real original-hook sessions on one explicitly selected root emulator."""
from __future__ import annotations
import json
from pathlib import Path
import tempfile
import threading
import time
import frida
from core.frida_host.bundle_config import configure
from mobile.lab.root_runtime import save, session_identifier

ROOT = Path(__file__).resolve().parents[2]
MODULES = {"reads": "hook_privacy", "consent": "hook_consent", "egress": "hook_egress_tp"}


def compile_session(cache, *, android_jar=None, android_api=None):
    """One Java bridge per process: separate early bridges recurse in ART attach."""
    hooks = ROOT / "mobile/hooks"
    staging = []
    try:
        def stage(source):
            with tempfile.NamedTemporaryFile("w", dir=hooks, suffix=".js", prefix=".core-",
                                             encoding="utf-8", delete=False) as handle:
                path = Path(handle.name)
                handle.write(source)
                staging.append(path)
                return "./" + path.name
        bootstrap = stage("import Java from './node_modules/frida-java-bridge/index.js'; globalThis.Java=Java;\n")
        imports = [bootstrap]
        calls = []
        scoped_targets = None
        if android_jar:
            from mobile.lab.sdk_hook_scope import prepare
            text, _scope = prepare(Path(android_jar), str(android_api), cache)
            scoped_targets = stage(text)
        for index, name in enumerate(MODULES.values()):
            hook_path = "./" + name + ".js"
            if scoped_targets and name in {"hook_privacy", "hook_consent"}:
                source = (hooks / (name + ".js")).read_text(encoding="utf-8")
                hook_path = stage(source.replace("'./targets.generated.js'", "'" + scoped_targets + "'"))
            imports.append("import { main as hook%d } from %s;" % (index, json.dumps(hook_path)))
            calls.append("hook%d();" % index)
        audit = (ROOT / "mobile/audit/storage_crypto.js").read_text(encoding="utf-8")
        audit = audit.replace("import Java from 'frida-java-bridge';",
                              "import Java from './node_modules/frida-java-bridge/index.js';")
        imports.append("import " + json.dumps(stage(audit)) + ";")
        imports[0] = "import '" + bootstrap + "';"
        entry_name = stage("\n".join(imports) + "\nJava.perform(function () {" + "".join(calls) + "});")
        body = frida.Compiler().build(str(hooks / entry_name[2:]), project_root=str(ROOT),
                                     compression="none", source_maps="omitted", bundle_format="iife")
        (cache / "core-session.js").write_text(body, encoding="utf-8")
        return body
    finally:
        for path in staging:
            path.unlink(missing_ok=True)


class CoreObserver:
    def __init__(self, package, session, serial, android, *, endpoint="127.0.0.1:27043"):
        self.package, self.path, self.android = package, session, android
        self.device = frida.get_device_manager().add_remote_device(endpoint) if endpoint else None
        self.scripts, self.files, self.ready, self.events, self.errors = {}, {}, {}, {}, []
        self.session, self.pid = None, None
        self.dead = threading.Event()
        self.session_id = session_identifier(session)
        self.serial = serial
        self.startup_mode = "spawn"

    def receive(self, name, message, data):
        if message.get("type") == "send":
            payload = message.get("payload", {})
            try:
                row = json.loads(payload["line"]) if isinstance(payload.get("line"), str) else payload
                if not isinstance(row, dict):
                    raise ValueError("event must be a JSON object")
            except (AttributeError, TypeError, ValueError) as exc:
                self.errors.append({"module": name, "message": "invalid event: " + str(exc)})
                return
            name = {"privacy": "reads", "consent": "consent", "egress": "egress",
                    "storage_crypto": "audit"}.get(row.get("src"), name)
            row.update(session_id=self.session_id, host_received_ts=int(time.time() * 1000))
            if row.get("ev") in {"ERROR", "PROBE_ERROR", "OBSERVATION_ERROR", "NOT_READY", "ARM_FAIL"}:
                self.errors.append({"module": name, "event": row})
            self.events[name].append(row)
            if row.get("ev") == "ARMED":
                self.ready[name].set()
            self.files[name].write(json.dumps(row, ensure_ascii=False) + "\n")
            self.files[name].flush()
        elif message.get("type") == "error":
            self.errors.append({"module": name, "message": message})

    def start(self):
        cache = self.path.parent / "compiled-hooks"
        cache.mkdir()
        body = "globalThis.__VSCAN_AUDIT_PACKAGES__=" + json.dumps([self.package]) + ";\n" + compile_session(cache, android_jar=getattr(self, "android_jar", None), android_api=getattr(self, "android_api", None))
        for name in [*MODULES, "audit"]:
            self.files[name] = (self.path / (name + ".jsonl")).open("w", encoding="utf-8")
            self.events[name], self.ready[name] = [], threading.Event()
        if self.startup_mode == "attach":
            resolved = self.android.shell("cmd", "package", "resolve-activity", "--brief", "-c",
                "android.intent.category.LAUNCHER", self.package)
            components = [line.strip() for line in resolved.splitlines() if "/" in line and " " not in line.strip()]
            if not components:
                raise RuntimeError("no device-resolved launcher for late attach")
            self.android.shell("am", "start", "-n", components[-1])
            time.sleep(3)
            if getattr(self, "before_attach", None):
                self.before_attach()
                time.sleep(3)
            pids = self.android.shell("pidof", self.package, check=False).strip().split()
            if len(pids) > 1:
                pids = [pid for pid in pids if pid.isdigit() and
                    self.android.call("exec-out", "cat", "/proc/" + pid + "/cmdline", binary=True)
                    .split(b"\0", 1)[0].decode("utf-8", errors="replace") == self.package]
            if len(pids) > 1:
                front = self.device.get_frontmost_application()
                if front and front.identifier == self.package and str(front.pid) in pids:
                    pids = [str(front.pid)]
            if len(pids) != 1 or not pids[0].isdigit():
                raise RuntimeError("original app did not remain running before late attach: " + repr(pids))
            self.pid = int(pids[0])
        else:
            self.pid = self.device.spawn([self.package])
        self.session = self.device.attach(self.pid)
        self.session.on("detached", lambda *args: self.dead.set())
        script = self.session.create_script(configure(body, [self.package]))
        script.on("message", lambda msg, data: self.receive("reads", msg, data))
        script.load()
        self.scripts["combined"] = script
        if self.startup_mode == "spawn":
            self.device.resume(self.pid)
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline and not self.dead.is_set():
            if all(event.is_set() for event in self.ready.values()):
                break
            time.sleep(.1)
        missing = [name for name in self.ready if not self.ready[name].is_set()]
        if missing:
            raise RuntimeError("hooks did not arm: " + repr(missing) + "; " + repr(self.errors))
        return self.pid

    def close(self):
        for script in ([] if self.dead.is_set() else self.scripts.values()):
            try:
                script.unload()
            except frida.InvalidOperationError:
                pass
        if self.session and not self.dead.is_set():
            try:
                self.session.detach()
            except frida.InvalidOperationError:
                pass
        for handle in self.files.values():
            handle.close()
        save(self.path / "observer-errors.json", self.errors)

    def summary(self):
        kinds = {"PRIVACY_READ", "PERM_REQ", "PERM_RESULT", "PERM_CHECK", "POLICY_VIEW",
                 "EGRESS_CONNECT", "EGRESS_URL", "FILE_WRITE", "FILE_OPEN", "PREF_PUT_STRING",
                 "CIPHER_INIT", "CIPHER_FINAL"}
        return {name: {"events": len(rows), "behavior_events": sum(e.get("ev") in kinds for e in rows)}
                for name, rows in self.events.items()}

    def healthy(self):
        if self.errors or not all(event.is_set() for event in self.ready.values()):
            return False
        for name, rows in self.events.items():
            armed = next((row for row in rows if row.get("ev") == "ARMED"), {})
            if armed.get("failed") or armed.get("missing"):
                return False
            hooks = armed.get("hooks", 0)
            if not hooks or name == "egress" and not armed.get("libcore_hooks"):
                return False
        return True
