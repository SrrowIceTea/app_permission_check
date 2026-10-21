#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""validate_keylog 的宿主侧 TLS 探测服务器：完成握手即计数。仅用于授权测试连通性。

自签证书（cryptography 生成）：只为让应用侧握手能走完，好让进程内的 keylog 回调
（hook_tls_meta）在握手期发出密钥行；本服务器不做任何应用数据语义解析。
"""
from __future__ import annotations

import socket
import ssl
import threading
from datetime import datetime, timedelta, timezone
from os import unlink
from tempfile import NamedTemporaryFile


class TlsProbeServer:
    def __init__(self, port: int):
        self.port = port
        self.conns: list[str] = []
        self.err: str | None = None
        self._stop = threading.Event()
        self._ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "vscan-keylog-test")])
        now = datetime.now(timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                .public_key(key.public_key()).serial_number(1)
                .not_valid_before(now - timedelta(days=1))
                .not_valid_after(now + timedelta(days=30))
                .sign(key, hashes.SHA256()))
        # load_cert_chain 要文件；ssl 模块不认内存 cert，落临时文件（进程私有，stop 时删除）。
        pem = cert.public_bytes(serialization.Encoding.PEM) + key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption())
        self._tmp = NamedTemporaryFile(suffix=".pem", delete=False)
        self._tmp.write(pem)
        self._tmp.close()
        self._ctx.load_cert_chain(self._tmp.name)

    def start(self) -> bool:
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self._sock.bind(("127.0.0.1", self.port))
        except OSError as e:
            self.err = f"bind 127.0.0.1:{self.port} 失败: {e}"
            return False
        self._sock.listen(8)
        threading.Thread(target=self._serve, daemon=True).start()
        return True

    def _serve(self) -> None:
        self._sock.settimeout(0.5)
        while not self._stop.is_set():
            try:
                raw, addr = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._one, args=(raw, addr), daemon=True).start()

    def _one(self, raw: socket.socket, addr) -> None:
        try:
            with self._ctx.wrap_socket(raw, server_side=True) as s:
                self.conns.append(f"{addr[0]}:{addr[1]} ok")
                try:
                    s.settimeout(3)
                    s.recv(4096)    # 应用发来的第一个应用层片段
                except (socket.timeout, ssl.SSLError):
                    pass
        except (ssl.SSLError, OSError) as e:
            self.conns.append(f"{addr[0]}:{addr[1]} fail:{type(e).__name__}")

    def stop(self) -> None:
        self._stop.set()
        try:
            self._sock.close()
        except OSError:
            pass
        try:
            unlink(self._tmp.name)
        except OSError:
            pass