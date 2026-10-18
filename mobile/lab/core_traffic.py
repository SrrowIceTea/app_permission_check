"""Bounded proxy + whole-emulator PCAP; neither claims all-protocol decryption."""
from __future__ import annotations
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import threading
import time
from mobile.lab.root_runtime import save, session_identifier

ROOT = Path(__file__).resolve().parents[2]


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class Traffic:
    def __init__(self, android, session, package, fixture=False):
        self.android, self.session, self.package = android, session, package
        self.port, self.fixture = free_port(), fixture
        self.proc, self.capture_pid, self.sink, self.log = None, None, None, None
        self.previous_proxy = android.shell("settings", "get", "global", "http_proxy").strip()
        self.remote = "/data/local/tmp/vscanner-core-" + str(time.time_ns()) + ".pcap"

    def start_sink(self):
        folder = self.session
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                data = self.rfile.read(min(int(self.headers.get("Content-Length", "0")), 65536))
                with (folder / "sink-requests.jsonl").open("a", encoding="utf-8") as handle:
                    handle.write(json.dumps({"method": "POST", "path": self.path,
                        "body": data.decode("utf-8", errors="replace"), "ts": time.time()}) + "\n")
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'{"received":true}')

            def do_GET(self):
                with (folder / "sink-get-requests.jsonl").open("a", encoding="utf-8") as handle:
                    handle.write(json.dumps({"method": "GET", "path": self.path,
                        "ts": time.time(), "scope": "local synthetic public RSS endpoint"}) + "\n")
                self.send_response(200)
                self.send_header("Content-Type", "application/rss+xml")
                self.end_headers()
                self.wfile.write(b'<?xml version="1.0"?><rss version="2.0"><channel><title>Local audit feed</title><link>http://example.invalid</link><description>Public synthetic fixture feed</description><item><title>Audit article</title><guid>local-audit-1</guid><description>Network observation check.</description></item></channel></rss>')
        self.sink = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.sink.serve_forever, daemon=True).start()

    def start(self):
        self.start_sink()
        for name in ("flows.jsonl", "flows-unanswered.jsonl", "egress.jsonl"):
            (self.session / name).touch()
        env = dict(os.environ)
        env.update(VSCAN_FLOW_LOG=str(self.session / "flows.jsonl"),
                   VSCAN_UNANSWERED_LOG=str(self.session / "flows-unanswered.jsonl"),
                   VSCAN_ATTRIB_SOURCES=str(self.session / "egress.jsonl"),
                   VSCAN_PACKAGES=self.package, VSCAN_SESSION=session_identifier(self.session),
                   VSCAN_TAGGING=str(ROOT / "mobile/traffic/tagging_mobile.py"), PYTHONUNBUFFERED="1")
        if not self.fixture:
            env["VSCAN_ATTRIB_TARGET_CHECK"] = "1"
        args = [str(Path(sys.executable).with_name("mitmdump.exe")), "-s",
                str(ROOT / "mobile/traffic/addon_mobile.py"), "--listen-host", "127.0.0.1",
                "--listen-port", str(self.port), "--set", "flow_detail=0"]
        if self.fixture:
            args += ["--mode", "reverse:http://127.0.0.1:" + str(self.sink.server_port)]
        self.log = (self.session / "mitm.log").open("w", encoding="utf-8")
        self.proc = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=self.log,
                                     stderr=subprocess.STDOUT, env=env)
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                raise RuntimeError("proxy exited; inspect session/mitm.log")
            with socket.socket() as probe:
                if probe.connect_ex(("127.0.0.1", self.port)) == 0:
                    break
            time.sleep(.2)
        else:
            raise RuntimeError("proxy did not become ready")
        if not self.fixture:
            self.android.shell("settings", "put", "global", "http_proxy", "10.0.2.2:" + str(self.port))
        self.capture_pid = self.android.shell(
            f"tcpdump -i any -s 0 -U -w {self.remote} >{self.remote}.log 2>&1 </dev/null & echo $!").strip()
        if not self.capture_pid.isdigit():
            raise RuntimeError("tcpdump did not identify its PID")
        time.sleep(.3)
        self.android.shell("kill", "-0", self.capture_pid)

    def close(self):
        errors = []
        if self.capture_pid:
            try:
                self.android.shell("kill", "-2", self.capture_pid)
                time.sleep(.5)
                self.android.call("pull", self.remote, self.session / "traffic.pcap")
                self.android.call("pull", self.remote + ".log", self.session / "tcpdump.log")
                from mobile.lab.pcap_inventory import inventory
                with (self.session / "traffic.pcap").open("rb") as handle:
                    summary = inventory(handle, lambda row: None)
                save(self.session / "pcap-summary.json", summary)
            except Exception as exc:
                errors.append("pcap: " + str(exc))
        if self.proc:
            time.sleep(2.5)  # collector pending-attribution grace period
            self.proc.terminate()
            try:
                self.proc.wait(5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(5)
        if self.log:
            self.log.close()
        if self.sink:
            self.sink.shutdown()
            self.sink.server_close()
        if not self.fixture:
            old = self.previous_proxy
            if old in {"", "null"}:
                self.android.shell("settings", "delete", "global", "http_proxy")
            else:
                self.android.shell("settings", "put", "global", "http_proxy", old)
            restored = self.android.shell("settings", "get", "global", "http_proxy").strip()
            if restored != (old or "null"):
                errors.append("proxy restore did not match previous setting")
        save(self.session / "traffic-scope.json", {"capture_interface": "any", "bpf": None,
             "proxy": "http-observable-only; HTTPS CA not installed; no pinning bypass",
             "system_ca_modified": False, "cleanup_errors": errors,
             "previous_proxy": self.previous_proxy})
        if errors:
            raise RuntimeError("; ".join(errors))
