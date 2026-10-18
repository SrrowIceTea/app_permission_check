"""Explicit-address synthetic sinks for the owned Gadget fixture; 仅用于授权测试。

No proxy setting, CA installation or external destination is changed.
The temporary TLS private key is written only into the ignored output directory.
"""
from __future__ import annotations

import datetime as dt
import ipaddress
import json
import os
import shutil
import socket
import socketserver
import ssl
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


def ipv4(value: str) -> str:
    address = ipaddress.IPv4Address(value)
    if address.is_unspecified or address.is_multicast or str(address) == "255.255.255.255":
        raise ValueError("an explicit unicast IPv4 address is required")
    return str(address)


def transport_config(kind="emulator", host=None, udp_host=None, bind_host=None, udp_bind_host=None):
    if kind == "lan" and not host:
        raise ValueError("LAN transport requires --host <local LAN IPv4>")
    host = ipv4(host or ("127.0.0.1" if kind == "usb" else "10.0.2.2"))
    if kind == "usb" and host != "127.0.0.1":
        raise ValueError("USB reverse requires --host 127.0.0.1")
    if kind == "lan" and ipaddress.ip_address(host).is_loopback:
        raise ValueError("LAN transport requires a non-loopback host")
    bind = ipv4(bind_host or (host if kind == "lan" else "127.0.0.1"))
    udp = ipv4(udp_host) if udp_host else (None if kind == "usb" else host)
    udp_bind = ipv4(udp_bind_host or (udp if kind == "usb" else bind)) if udp else None
    return {"transport": kind, "host": host, "bind_host": bind, "udp_host": udp,
            "udp_bind_host": udp_bind, "coverage": "full" if udp else "partial",
            "unsupported": [] if udp else ["udp: adb reverse supports TCP only"],
            "endpoints": {"http": [host, 18890], "https": [host, 18891],
                          "tcp": [host, 18889], "udp": [udp, 18888] if udp else None}}


def atomic_write(path: Path, data: bytes):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".phone.tmp")
    temporary.write_bytes(data)
    os.replace(temporary, path)


def prepare_certificate(out: Path, asset: Path, hosts=(), replace=False) -> None:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    out.mkdir(parents=True, exist_ok=True)
    existing = [path for path in (out / "lab-cert.pem", out / "lab-key.pem", asset) if path.exists()]
    if existing and not replace:
        raise ValueError("certificate exists; use explicit --replace-test-certificate")
    if existing:
        backup = out / ("certificate-backup-" + str(time.time_ns()))
        backup.mkdir()
        for index, path in enumerate(existing):
            shutil.copy2(path, backup / (str(index) + "-" + path.name))
    addresses = sorted({"10.0.2.2", "127.0.0.1", *(ipv4(host) for host in hosts)})
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "owned-local-audit-lab")])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(days=2)).not_valid_after(now + dt.timedelta(days=7))
            .add_extension(x509.SubjectAlternativeName([
                x509.IPAddress(ipaddress.ip_address(host)) for host in addresses]), critical=False)
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .sign(key, hashes.SHA256()))
    pem = cert.public_bytes(serialization.Encoding.PEM)
    atomic_write(out / "lab-cert.pem", pem)
    atomic_write(out / "lab-key.pem", key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    atomic_write(asset, pem)  # Public test anchor only, excluded by existing *.pem ignore.


class LocalProbeServers:
    def __init__(self, out: Path, bind_host="127.0.0.1", udp_bind_host=None, enable_udp=True):
        self.out, self.servers, self.threads = out, [], []
        self.bind_host = ipv4(bind_host)
        self.udp_bind_host = ipv4(udp_bind_host or bind_host)
        self.enable_udp, self.startup_checks = enable_udp, []
        self.lock = threading.Lock()
        self.records = []

    def record(self, protocol: str, data: bytes):
        if not data:
            return
        event = {"ts": int(time.time() * 1000), "protocol": protocol,
                 "byte_length": len(data), "synthetic_payload": data.decode("ascii", "replace")}
        with self.lock:
            self.records.append(event)
            with (self.out / "sink-receipts.jsonl").open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(event) + "\n")

    def __enter__(self):
        owner = self

        class HTTP(BaseHTTPRequestHandler):
            def do_POST(self):
                data = self.rfile.read(min(int(self.headers.get("Content-Length", 0)), 4096))
                owner.record("https" if isinstance(self.connection, ssl.SSLSocket) else "http", data)
                self.send_response(200)
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"OK")

            def log_message(self, *_args):
                pass

        class TCP(socketserver.BaseRequestHandler):
            def handle(self):
                self.request.settimeout(8)
                data = self.request.recv(4096)
                owner.record("tcp", data)
                self.request.sendall(data)

        class UDP(socketserver.BaseRequestHandler):
            def handle(self):
                data, sock = self.request
                owner.record("udp", data)
                sock.sendto(data, self.client_address)

        try:
            self.servers.append(ThreadingHTTPServer((self.bind_host, 18890), HTTP))
            tls = ThreadingHTTPServer((self.bind_host, 18891), HTTP)
            self.servers.append(tls)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(self.out / "lab-cert.pem", self.out / "lab-key.pem")
            tls.socket = context.wrap_socket(tls.socket, server_side=True)
            self.servers.append(socketserver.ThreadingTCPServer((self.bind_host, 18889), TCP))
            if self.enable_udp:
                self.servers.append(socketserver.ThreadingUDPServer((self.udp_bind_host, 18888), UDP))
            for server in self.servers:
                server.daemon_threads = True
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()
                self.threads.append(thread)
            for port in (18890, 18891, 18889):
                with socket.create_connection((self.bind_host, port), timeout=2):
                    self.startup_checks.append({"port": port, "bound": self.bind_host, "listening": True})
            if self.enable_udp:
                self.startup_checks.append({"port": 18888, "bound": self.udp_bind_host, "listening": True})
            return self
        except Exception:
            self.__exit__(None, None, None)
            raise

    def __exit__(self, *_args):
        for i, server in enumerate(self.servers):
            if i < len(self.threads):
                server.shutdown()
            server.server_close()
        for thread in self.threads:
            thread.join(timeout=3)
