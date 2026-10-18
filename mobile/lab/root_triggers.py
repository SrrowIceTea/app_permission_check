"""Deterministic original Ghera paths and independent oracles. 仅用于授权测试。"""
from __future__ import annotations
import hashlib
import re
import socket
import ssl
import threading
import time
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from mobile.lab.local_probe_servers import prepare_certificate
from mobile.lab.root_runtime import save


class TLSSink:
    """Only localhost:5000, a temporary untrusted lab certificate; no CA installation."""
    def __init__(self, folder, marker):
        self.folder, self.marker, self.requests = folder, marker, []
        self.server, self.thread = None, None

    def start(self):
        prepare_certificate(self.folder, self.folder / "public-test-anchor.pem")
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                body = owner.marker.encode()
                owner.requests.append({"path": self.path, "ts": time.time(), "response": owner.marker})
                self.send_response(200 if self.path == "/test/" else 404)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 5000), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.folder / "lab-cert.pem", self.folder / "lab-key.pem")
        self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        if self.server:
            self.server.shutdown()
            self.server.server_close()
            self.thread.join(timeout=3)
        save(self.folder / "server-receipts.json", self.requests)


def _id(spec, name):
    return spec["package"] + ":id/" + name


def trigger(android, spec, folder, pid, sink=None):
    kind, variant, package = spec["kind"], spec["variant"], spec["package"]
    view = android.ready_screen()
    oracle = {"kind": kind, "synthetic_input": spec["canary"]}
    if kind == "ecb":
        email = "email" if variant == "Benign" else "emailEdit"
        button = "get_token_btn" if variant == "Benign" else "getToken"
        android.fill(view, _id(spec, email), spec["canary"])
        for index in range(2):
            view = android.screen(f"ecb-before-{index}")
            android.tap(view, _id(spec, button))
            time.sleep(.4)
    elif kind == "cbc":
        for index in range(2):
            android.tap(view, _id(spec, "button"))
            view = android.screen(f"cbc-add-{index}")
            android.fill(view, _id(spec, "stu_name"), spec["canary"])
            view = android.screen(f"cbc-name-{index}")
            android.fill(view, _id(spec, "stu_grade"), "C")
            view = android.screen(f"cbc-grade-{index}")
            android.tap(view, _id(spec, "save_btn"))
            view = android.screen(f"cbc-saved-{index}")
        raw = android.call("exec-out", "cat", f"/data/data/{package}/files/scores.txt", binary=True)
        (folder / "scores.txt").write_bytes(raw)
        oracle.update(disk_base64=raw.decode("ascii"), disk_bytes=len(raw),
                      disk_sha256=hashlib.sha256(raw).hexdigest())
    elif kind == "storage":
        path = (f"/sdcard/Android/data/{package}/files/ssn_bkup.jpg" if variant == "Benign"
                else f"/data/data/{package}/files/ssn_bkup.jpg")
        raw = android.call("exec-out", "cat", path, binary=True)
        (folder / "stored-resource.jpg").write_bytes(raw)
        with zipfile.ZipFile(spec["apk"]) as archive:
            names = [n for n in archive.namelist() if n.startswith("res/raw/") and "ssn" in n]
            if len(names) != 1:
                raise RuntimeError("expected exactly one author-supplied ssn image resource")
            expected = archive.read(names[0])
        oracle.update(disk_path=path, bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(),
                      resource_sha256=hashlib.sha256(expected).hexdigest(), resource_matches=raw == expected,
                      personal_data_read=False, cross_app_readability_tested=False)
    elif kind == "socket":
        android.tap(view, _id(spec, "button"))
        port = android.call("forward", "tcp:0", "tcp:5000").strip()
        if not port.isdigit():
            raise RuntimeError("ADB did not allocate a dedicated socket forward")
        try:
            end = time.monotonic() + 8
            while True:
                try:
                    with socket.create_connection(("127.0.0.1", int(port)), timeout=2) as client:
                        raw = bytearray()
                        while block := client.recv(4096):
                            raw.extend(block)
                            if len(raw) > 4096:
                                raise RuntimeError("benchmark response exceeded bound")
                    if raw:
                        break
                except (ConnectionError, TimeoutError, OSError):
                    if time.monotonic() >= end:
                        raise
                    time.sleep(.3)
            (folder / "socket-receipt.bin").write_bytes(raw)
            oracle.update(received=raw.decode("ascii", errors="replace"),
                          payload_marker=raw.decode("ascii", errors="replace"),
                          bytes=len(raw), contains_personal_data=False)
        finally:
            android.call("forward", "--remove", "tcp:" + port)
    elif kind == "tls":
        deadline = time.monotonic() + 15
        while True:
            view = android.screen("tls-result-ui")
            texts = " ".join(n.get("text", "") for n in view.iter("node"))
            if spec["canary"] in texts or "SSL Handshake failed" in texts or time.monotonic() >= deadline:
                break
            time.sleep(.5)
        oracle.update(response_seen=spec["canary"] in texts,
                      handshake_rejected="SSL Handshake failed" in texts,
                      server_requests=len(sink.requests), ui_text=texts,
                      certificate_trusted=False, ca_installed=False)
    logs = android.call("logcat", "-d", "--pid=" + str(pid), "-v", "threadtime")
    (folder / "logcat.txt").write_text(logs, encoding="utf-8")
    if kind == "ecb":
        oracle["tokens"] = re.findall(r"Token = ([A-Za-z0-9+/=]+)", logs)
    oracle["pid_alive"] = str(pid) in android.shell("pidof", package, check=False).split()
    (folder / "screenshot.png").write_bytes(android.call("exec-out", "screencap", "-p", binary=True))
    android.screen("final-ui")
    save(folder / "oracle.json", oracle)
    return oracle
