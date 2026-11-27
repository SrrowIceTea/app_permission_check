"""One app-owned Gadget session, multiple audited scripts. 仅用于授权测试（自有夹具）。

Reuses core bundle configuration and EventStore; on_load=resume attaches once,
never spawn/resume per script and never invokes adb/root/frida-server.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from core.event_store import EventStore
from core.frida_host.bundle_config import configure

PKG = "com.vscanner.privacydemo"


class MultiCapture:
    def __init__(self, session: str, store: EventStore):
        self.session, self.store = session, store
        self.lock = threading.RLock()
        self.failures = []

    def save(self, path: Path, record: dict) -> None:
        record["session_id"] = self.session
        record["host_received_ts"] = int(time.time() * 1000)
        with self.lock:
            with path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(record, ensure_ascii=False) + "\n")
            self.store.append(self.session, str(path.resolve()), record)

    def callback(self, path: Path):
        def on_message(message, _data):
            try:
                if message.get("type") == "send":
                    line = (message.get("payload") or {}).get("line")
                    if line:
                        self.save(path, json.loads(line))
                elif message.get("type") == "error":
                    self.failures.append("script_error:" + path.name)
                    self.save(path, {"ev": "SCRIPT_ERROR", "src": "driver", "message": message})
            except Exception as exc:
                self.failures.append("capture_error:" + path.name)
                record = {"ev": "CAPTURE_ERROR", "src": "driver", "error": str(exc)}
                print(json.dumps(record, ensure_ascii=False), file=sys.stderr, flush=True)
                try:
                    self.save(path, record)
                except Exception:
                    pass  # stderr plus nonzero status remain the failure evidence.
        return on_message


def attach_scripts(device, plan: list, session_dir: Path, capture: MultiCapture):
    processes = device.enumerate_processes()
    if len(processes) != 1:
        raise RuntimeError("Gadget listener 必须只有一个进程，拒绝猜测目标")
    process = processes[0]
    session = device.attach(process.pid)
    scripts = []
    try:
        session.on("detached", lambda *info: capture.failures.append("detached:" + str(info)))
        for item in plan:
            body = Path(item["script"]).read_text(encoding="utf-8")
            if "frida-java-bridge" not in body:
                raise ValueError(f"{item['script']} 未包含 Java bridge")
            tls_bypass = os.environ.get("VSCAN_TLS_BYPASS", "").strip() == "1"
            script = session.create_script(configure(body, [PKG], tls_bypass=tls_bypass))
            script.on("message", capture.callback(session_dir / item["output"]))
            script.load()
            scripts.append(script)
        return session, scripts, {"pid": process.pid, "remote_name": process.name,
                                  "attach_calls": 1, "spawn_calls": 0, "resume_calls": 0}
    except Exception:
        session.detach()
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--session-dir", type=Path, required=True)
    parser.add_argument("--session", required=True)
    parser.add_argument("--port", type=int, default=27044)
    parser.add_argument("--seconds", type=float, default=600)
    parser.add_argument("--stop-file", type=Path, required=True)
    args = parser.parse_args()
    args.session_dir.mkdir(parents=True, exist_ok=True)
    store = EventStore(args.session_dir / "events.sqlite")
    capture = MultiCapture(args.session, store)
    session, scripts = None, []
    metadata = {"mode": "gadget", "scope": "self-owned-source-fixture",
                "package": PKG, "startup_coverage": "not_observed (on_load=resume)"}
    try:
        import frida
        metadata["host_frida_version"] = frida.__version__
        plan = json.loads(args.plan.read_text(encoding="utf-8"))
        device = frida.get_device_manager().add_remote_device(f"127.0.0.1:{args.port}")
        session, scripts, attachment = attach_scripts(device, plan, args.session_dir, capture)
        metadata.update(attachment)
        print(json.dumps(metadata, ensure_ascii=False), flush=True)
        end = time.monotonic() + args.seconds
        while time.monotonic() < end and not args.stop_file.exists() and not capture.failures:
            time.sleep(.25)
        if not args.stop_file.exists() and not capture.failures:
            capture.failures.append("capture_deadline_expired_before_controller_stop")
    except Exception as exc:
        capture.failures.append(f"driver_error:{type(exc).__name__}:{exc}")
        print(capture.failures[-1], file=sys.stderr, flush=True)
    finally:
        # Snapshot before intentional detach so it cannot look like an unexpected loss.
        metadata["failures"] = list(capture.failures)
        metadata["passed"] = not capture.failures
        if session:
            try:
                session.detach()
            except Exception as exc:
                metadata["failures"].append(f"detach_error:{exc}")
                metadata["passed"] = False
        store.close()
        (args.session_dir / "hook-driver-verification.json").write_text(
            json.dumps(metadata, ensure_ascii=False, indent=2), encoding="utf-8")
    return 0 if metadata["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
