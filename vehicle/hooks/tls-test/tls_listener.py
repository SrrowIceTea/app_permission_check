#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# 仅用于授权测试（自有设备与自有 APK）/ For authorized testing on owned devices and APKs only.
# V-Scanner Phase 3 验证辅助（宿主机端）：TLS 监听器，使用自签证书 cert.pem/key.pem，
# 用于验证 ssl_pinning_bypass.js 是否真的让模拟器内白名单应用完成握手并把流量送达宿主机。
# 这是流量收集/验证工具（Python 侧），不含任何钩子逻辑。
# 用法:
#   openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 3 -nodes \
#     -subj "/CN=vscanner-audit-test" -addext "subjectAltName=IP:10.0.2.2"
#   python tls_listener.py [port=8443]
import datetime
import socket
import ssl
import sys

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8443

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain('cert.pem', 'key.pem')

with socket.socket() as s:
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('0.0.0.0', PORT))
    s.listen(4)
    print('[listener] https://0.0.0.0:%d  cert=cert.pem  (emulator reaches host via 10.0.2.2)' % PORT, flush=True)
    while True:
        conn, addr = s.accept()
        print('[conn] %s %s' % (addr, datetime.datetime.now().isoformat()), flush=True)
        try:
            with ctx.wrap_socket(conn, server_side=True) as tls:
                data = b''
                deadline = datetime.datetime.now() + datetime.timedelta(seconds=10)
                while datetime.datetime.now() < deadline:
                    chunk = tls.recv(8192)
                    if not chunk:
                        break
                    data += chunk
                    if len(data) > 1_000_000:
                        break
                print('[req] ' + data.decode('utf-8', 'replace')[:4000], flush=True)
                tls.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK')
        except Exception as e:
            print('[tls-err] %s: %s' % (type(e).__name__, e), flush=True)
