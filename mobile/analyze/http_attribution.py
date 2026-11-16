"""Match packet endpoints with window-local socket evidence. 仅用于授权测试。"""
from bisect import bisect_left, bisect_right
from collections import Counter, defaultdict
from ipaddress import ip_address
import math

SAMPLE_MAX_GAP_MS = 175
EVENT_MAX_GAP_MS = 75


def _number(value, *, scale=1):
    if isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value):
        return float(value) * scale
    return None


def _endpoint(ip, port):
    try:
        address = ip_address(ip)
        port = int(port)
    except (ValueError, TypeError):
        return ()
    if address.version == 6 and address.ipv4_mapped:
        address = address.ipv4_mapped
    if address.is_unspecified or not 1 <= port <= 65535:
        return None
    return str(address), port


def _packet_endpoint(value):
    ip, _, port = str(value or "").rpartition(":")
    return _endpoint(ip.strip("[]"), port)


def _packet_key(packet, protocol, *, reverse=False):
    src = _packet_endpoint(packet.get("src"))
    dst = _packet_endpoint(packet.get("dst"))
    if not src or not dst:
        return None
    return (protocol, dst, src) if reverse else (protocol, src, dst)


class SocketEvidence:
    def __init__(self, conns, operations, target_uid):
        self.uid = target_uid
        self.samples = defaultdict(lambda: defaultdict(list))
        events = defaultdict(list)
        self.target_ports = set()
        for row in conns:
            key = self._key(row, str(row.get("family", ""))[:3])
            ts = _number(row.get("ts"))
            inode = row.get("socket_inode")
            uid = row.get("uid")
            if key and ts is not None and isinstance(inode, int) and inode > 0 and isinstance(uid, int):
                self.samples[key][(uid, inode)].append(ts)
                if uid == self.uid:
                    self.target_ports.add(key[1][1])
        for row in operations:
            key = self._key(row, row.get("transport"))
            start = _number(row.get("started_ms"))
            end = _number(row.get("ended_ms"))
            if (key and self.uid is not None and row.get("uid") == self.uid
                    and start is not None and end is not None and start <= end):
                operation = row.get("operation")
                if operation in ("connect", "send", "recv"):
                    # A TCP SYN is timed at call entry, UDP at send/receive completion.
                    anchor = start if operation == "connect" else end
                    identity = (row.get("pid"), row.get("fd"), start if operation == "connect" else None)
                    events[key, operation].append((anchor, identity))
                    self.target_ports.add(key[1][1])
        self.events = {key: tuple(zip(*sorted(rows, key=lambda row: row[0])))
                       for key, rows in events.items()}
        for identities in self.samples.values():
            for times in identities.values():
                times.sort()

    @staticmethod
    def _key(row, protocol):
        local = _endpoint(row.get("local_ip"), row.get("local_port"))
        remote = _endpoint(row.get("remote_ip"), row.get("remote_port"))
        if protocol in ("tcp", "udp") and local and remote:
            return protocol, local, remote
        return None

    def sample_identity(self, key, timestamp):
        if self.uid is None or not key or timestamp is None:
            return None
        candidates = []
        nearby = set()
        for (uid, inode), times in self.samples.get(key, {}).items():
            index = bisect_left(times, timestamp)
            before = timestamp - times[index - 1] if index else math.inf
            after = times[index] - timestamp if index < len(times) else math.inf
            if min(before, after) <= SAMPLE_MAX_GAP_MS:
                nearby.add((uid, inode))
            if uid == self.uid and max(before, after) <= SAMPLE_MAX_GAP_MS:
                candidates.append((uid, inode))
        if len(candidates) == len(nearby) == 1:
            return candidates[0]
        return None

    def sample(self, key, timestamp):
        if self.sample_identity(key, timestamp):
            return "socket_inode_bracket"
        return None

    def operation(self, key, timestamp, operation):
        if not key or timestamp is None:
            return None
        times, identities = self.events.get((key, operation), ((), ()))
        lo = bisect_left(times, timestamp - EVENT_MAX_GAP_MS)
        hi = bisect_right(times, timestamp + EVENT_MAX_GAP_MS)
        matched = set(identities[lo:hi])
        if len(matched) == 1:
            return "socket_call_time"
        return None


def attribute(messages, conns, target_uid=None, *, packets=(), operations=()):
    """HTTP uses an observed opening SYN or bracketing samples. UDP is attributed per datagram."""
    evidence = SocketEvidence(conns, operations, target_uid)
    streams = {}
    conflicts = set()
    udp_total = quic_total = 0
    udp_attributed = []
    for packet in packets:
        ts = _number(packet.get("ts"), scale=1000)
        if packet["transport"] == "tcp":
            key = _packet_key(packet, "tcp")
            how = evidence.operation(key, ts, "connect") or evidence.sample(key, ts)
            stream = packet.get("tcp_stream")
            if how and stream:
                if stream in streams and streams[stream][0] != key:
                    conflicts.add(stream)
                streams[stream] = (key, how)
            continue
        udp_total += 1
        quic_total += bool(packet.get("quic"))
        outgoing = _packet_key(packet, "udp")
        incoming = _packet_key(packet, "udp", reverse=True)
        sides = [(direction, how) for direction, key, operation in
                 (("outgoing", outgoing, "send"), ("incoming", incoming, "recv"))
                 if (how := evidence.operation(key, ts, operation) or evidence.sample(key, ts))]
        if len(sides) == 1:
            direction, how = sides[0]
            udp_attributed.append(dict(packet, direction=direction, attribution=how))

    attributed = 0
    for message in messages:
        key = _packet_key(message, "tcp", reverse=message.get("kind") == "response")
        ts = _number(message.get("ts"), scale=1000)
        stream = message.get("tcp_stream")
        opening = streams.get(stream)
        if opening and key == opening[0] and stream not in conflicts:
            how = "tcp_stream_" + opening[1]
        else:
            how = evidence.sample(key, ts)
        message["attributed"] = bool(how)
        message["attribution"] = how or "unattributed"
        attributed += bool(how)
    return {
        "total": len(messages), "attributed": attributed, "target_ports": len(evidence.target_ports),
        "basis": "socket_tuple_time" if target_uid is not None else None,
        "udp_total": udp_total, "quic_total": quic_total,
        "udp_attributed": len(udp_attributed),
        "quic_attributed": sum(bool(row.get("quic")) for row in udp_attributed),
        "datagrams": udp_attributed,
    }


def attribute_lines(lines, conns, target_uid=None, *, packets=()):
    """Attribute complete lines by UID/inode and exact TCP-stream identity."""
    evidence = SocketEvidence(conns, (), target_uid)
    listen_ports = {row["local_port"] for row in conns
                    if target_uid is not None and row.get("uid") == target_uid
                    and row.get("state") == "LISTEN" and isinstance(row.get("local_port"), int)}
    opened = defaultdict(set)
    for packet in packets:
        if packet.get("transport") == "tcp" and packet.get("tcp_stream") and packet.get("tcp_seq"):
            key = _packet_key(packet, "tcp")
            if key:
                opened[packet["tcp_stream"]].add((key, packet.get("tcp_seq")))
    bindings = defaultdict(set)
    observations = []
    for row in lines:
        stream = row.get("tcp_stream")
        timestamp = _number(row.get("ts"), scale=1000)
        sides = {side: _packet_key(row, "tcp", reverse=side == "to_app")
                 for side in ("from_app", "to_app")}
        matches = [(side, key, identity) for side, key in sides.items()
                   if (identity := evidence.sample_identity(key, timestamp))]
        if matches:
            bindings[stream].update((key, identity) for _, key, identity in matches)
        observations.append((row, sides, matches))
    basis = Counter()
    protos = Counter()
    proto_egress = Counter()
    directions = Counter()
    candidate_directions = Counter()
    for row, sides, matches in observations:
        stream = row.get("tcp_stream")
        proto = row.get("proto") or "unknown"
        protos[proto] += 1
        identity = direction = None
        how = "unattributed"
        if len(matches) == 1:
            direction, _, identity = matches[0]
            how = "socket_inode_bracket"
        elif not matches and len(opened[stream]) == len(bindings[stream]) == 1:
            (opening, _), = opened[stream]
            (target, uid_inode), = bindings[stream]
            if opening in sides.values() and target in sides.values():
                direction = next(side for side, key in sides.items() if key == target)
                identity = uid_inode
                how = "tcp_stream_socket_inode"
        if identity:
            row.update(uid=identity[0], socket_inode=identity[1])
            directions[direction] += 1
            if direction == "from_app":
                proto_egress[proto] += 1
        elif not matches:
            possibilities = [side for side, key in sides.items() if key and key[1][1] in listen_ports]
            if len(possibilities) == 1:
                how = "listen_port"
                row["candidate_direction"] = possibilities[0]
                candidate_directions[possibilities[0]] += 1
        row.update(attribution=how, direction=direction or "unknown", attributed=bool(identity))
        if how != "unattributed":
            basis[how] += 1
    count = sum(directions.values())
    return {"total": len(lines), "attributed": count, "uid_verified": count,
            "from_app": directions["from_app"], "to_app": directions["to_app"],
            "candidate_from_app": candidate_directions["from_app"],
            "by_basis": dict(basis), "by_proto": dict(protos),
            "proto_from_app": dict(proto_egress), "listen_ports": sorted(listen_ports)}
