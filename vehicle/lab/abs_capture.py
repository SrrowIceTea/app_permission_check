"""Bounded loopback HTTP capture for the isolated ABS fixture. 仅用于授权测试。"""
import hashlib
import json
import math
import re
import struct
import subprocess
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from threading import Event

from vehicle.pipeline.contracts import AuditError

SYNC = re.compile(rb'POST /api/session/([0-9a-fA-F-]{36})/sync HTTP/1\.[01]\Z')
FIELDS = ('currentTime', 'timeListened', 'duration')
LIMIT = 65536


def capture_error(code, message, **details):
    return AuditError(code, message, '检查隔离 ABS 与模拟器抓包，保留失败验收后重跑。', **details)


def _messages(buffer, stamp, port, connection, requests):
    while (end := buffer.find(b'\r\n\r\n')) >= 0:
        first, *headers = buffer[:end].split(b'\r\n')
        lengths = [line.partition(b':')[2].strip() for line in headers
                   if line.lower().startswith(b'content-length:')]
        if (len(lengths) > 1 or lengths and (not lengths[0].isdigit() or len(lengths[0]) > 5)
                or any(line.lower().startswith(b'transfer-encoding:') for line in headers)):
            return b''
        size = int(lengths[0]) if lengths else 0
        if size > LIMIT:
            return b''
        cut = end + 4 + size
        if len(buffer) < cut:
            break
        route = SYNC.fullmatch(first)
        if route and size:
            try:
                raw = buffer[end + 4:cut]
                parsed = json.loads(raw)
                if isinstance(parsed, dict) and all(type(parsed.get(k)) in (int, float)
                        and 0 <= parsed[k] <= 10**9 and math.isfinite(parsed[k]) for k in FIELDS):
                    evidence = {'session_id': route[1].decode().lower(), 'device_ts_ms': stamp,
                                'connection_port': port, 'body': {k: parsed[k] for k in FIELDS}}
                    if connection:
                        evidence['connection_id'] = connection
                    pairs = json.loads(raw, object_pairs_hook=list)
                    if raw.isascii() and len(pairs) == len(FIELDS) and set(parsed) == set(FIELDS):
                        evidence.update(body_sha256=hashlib.sha256(raw).hexdigest(), body_bytes=len(raw))
                    requests.append(evidence)
            except (ValueError, UnicodeError, RecursionError):
                pass
        buffer = buffer[cut:]
    return buffer


def _tcp(frame):
    # Android lo exposes Ethernet frames. The BPF filter narrows to local IPv4
    # requests, and the parser repeats that check before reading any payload.
    if len(frame) < 54 or frame[12:14] != b'\x08\x00':
        return None
    ip = frame[14:]
    offset = (ip[0] & 15) * 4
    size = int.from_bytes(ip[2:4], 'big')
    if (ip[9] != 6 or ip[12:20] != b'\x7f\x00\x00\x01' * 2 or not 20 <= offset <= size <= len(ip)
            or int.from_bytes(ip[6:8], 'big') & 0x3fff):
        return None
    tcp = ip[offset:size]
    if len(tcp) < 20 or tcp[2:4] != (18125).to_bytes(2, 'big'):
        return None
    header = (tcp[12] >> 4) * 4
    if not 20 <= header <= len(tcp):
        return None
    return int.from_bytes(tcp[:2], 'big'), int.from_bytes(tcp[4:8], 'big'), tcp[13], tcp[header:]


def read_pcap(stream, ready):
    header = stream.read(24)
    orders = {b'\xd4\xc3\xb2\xa1': '<', b'\xa1\xb2\xc3\xd4': '>'}
    order = orders.get(header[:4])
    if len(header) != 24 or not order or struct.unpack_from(order + 'I', header, 20)[0] != 1:
        raise capture_error('abs_pcap_format', '回环抓包没有输出已支持的 Ethernet pcap。')
    ready.set()
    requests, streams = [], OrderedDict()
    connections, next_connection = OrderedDict(), 0
    while raw := stream.read(16):
        if len(raw) != 16:
            raise capture_error('abs_pcap_truncated', '回环抓包记录不完整。')
        seconds, micros, length, original = struct.unpack(order + 'IIII', raw)
        if length > 262144 or length != original:
            raise capture_error('abs_pcap_truncated', '回环抓包帧长度无效或已截断。',
                                captured_bytes=length, wire_bytes=original)
        frame = stream.read(length)
        if len(frame) != length:
            raise capture_error('abs_pcap_truncated', '回环抓包帧不完整。')
        packet = _tcp(frame)
        if not packet:
            continue
        port, seq, flags, payload = packet
        if flags & 2:
            streams.pop(port, None)
            next_connection += 1
            connections[port] = next_connection
            connections.move_to_end(port)
            if len(connections) > 512:
                connections.popitem(last=False)
            seq += 1
        if payload:
            expect, buffer = streams.pop(port, (seq, b''))
            delta = (seq - expect + 2**31) % 2**32 - 2**31
            if delta > 0:
                buffer = b''  # Lost bytes cannot contribute to a complete request.
            if delta > -len(payload):
                buffer = _messages(buffer + payload[max(-delta, 0):], seconds * 1000 + micros // 1000,
                                   port, connections.get(port), requests)
                expect = (seq + len(payload)) % 2**32
            streams[port] = (expect, buffer if len(buffer) <= LIMIT else b'')
            if len(streams) > 32:
                streams.popitem(last=False)
            if len(requests) > 256:
                raise capture_error('abs_capture_limit', '隔离回环请求数超出验收上限。')
        if flags & 5:
            streams.pop(port, None)
            connections.pop(port, None)
    return requests


@contextmanager
def capture_syncs(device):
    # The launcher becomes tcpdump via exec, so its PID is the capture PID.
    command = "sh -c 'echo $$; exec tcpdump -i lo -s 0 -U -w - ip and tcp dst port 18125 2>/dev/null'"
    with subprocess.Popen([device.adb, '-s', device.serial, 'exec-out', command],
                          stdout=subprocess.PIPE, stderr=subprocess.DEVNULL) as proc:
        pid = None
        with ThreadPoolExecutor(max_workers=1) as pool:
            def collect():
                nonlocal pid
                line = proc.stdout.readline(32).strip()
                if line.isdigit():
                    pid = int(line)
                if not pid or pid < 2:
                    raise capture_error('abs_capture_start', '未获取到本轮抓包进程 PID。')
                return read_pcap(proc.stdout, ready)

            ready = Event()
            future = pool.submit(collect)
            try:
                if not ready.wait(10):
                    if future.done():
                        future.result()
                    raise capture_error('abs_capture_start', '隔离回环抓包就绪超时。')
                yield future
            finally:
                try:
                    if pid and proc.poll() is None:
                        device.call('shell', f'if [ "$(cat /proc/{pid}/comm 2>/dev/null)" = tcpdump ]; '
                                    f'then kill -INT {pid}; fi')
                    proc.wait(timeout=10)
                finally:
                    if proc.poll() is None:
                        proc.kill()
                        proc.wait(timeout=5)
            if proc.returncode:
                raise capture_error('abs_capture_exit', '隔离回环抓包异常退出。')
