"""Translate UID-verified, outbound NMEA fixes into same-session flow evidence."""
import math
import re

NAME = "pcap-line-egress.jsonl"
SOURCE = "pcap_line"
VERIFIED = {"socket_inode_bracket", "tcp_stream_socket_inode"}
COORDINATE_GETTERS = {
    "android.location.Location.getLatitude()D",
    "android.location.Location.getLongitude()D",
}


def _coordinate(value, hemisphere, axes, width, limit):
    if hemisphere not in axes or not re.fullmatch(rf"[0-9]{{{width + 2}}}(?:\.[0-9]+)?", value):
        return False
    deg, minutes = int(value[:width]), float(value[width:])
    return minutes < 60 and (deg < limit or (deg == limit and minutes == 0))


def _valid_fix(row):
    if row.get("proto") != "nmea" or row.get("checksum_ok") is not True:
        return False
    fields = (row.get("line") or "").partition("*")[0].split(",")
    if row.get("sentence") == "RMC" and len(fields) >= 7 and fields[2] == "A":
        lat, ns, lon, ew = fields[3:7]
    elif row.get("sentence") == "GGA" and len(fields) >= 7 and fields[6] in {"1","2","3","4","5","6","7","8"}:
        lat, ns, lon, ew = fields[2:6]
    else:
        return False
    return (_coordinate(lat, ns, ("N", "S"), 2, 90)
            and _coordinate(lon, ew, ("E", "W"), 3, 180))


def build_flows(rows, *, session, package, uid, pcap_sha256):
    """Create traceable event IDs only for complete, verified outbound fixes."""
    if uid is None:
        return []
    evidence = []
    for number, row in enumerate(rows, 1):
        timestamp = row.get("ts")
        if (row.get("attributed") is not True or row.get("direction") != "from_app"
                or row.get("uid") != uid or row.get("attribution") not in VERIFIED
                or row.get("partial_tail") or not _valid_fix(row)
                or not isinstance(timestamp, (int, float)) or not math.isfinite(timestamp)):
            continue
        evidence.append({
            "src": SOURCE, "evt_id": number, "session_id": session, "package": package,
            "ts": round(timestamp * 1000), "uid": uid, "attribution": row["attribution"],
            "request_tags": ["coordinate_shape"], "request_tokens": [],
            "capture_ref": {"file": "line-messages.jsonl", "line": number,
                            "pcap_sha256": pcap_sha256, "first_frame": row["first_frame"],
                            "frame": row["frame"], "tcp_stream": row["tcp_stream"],
                            "socket_inode": row["socket_inode"]},
        })
    return evidence


def admitted_flows(rows, *, session, package):
    return [row for row in rows if isinstance(row, dict) and row.get("src") == SOURCE
            and row.get("attribution") in VERIFIED and row.get("package") == package
            and row.get("session_id") == session and isinstance(row.get("uid"), int)
            and isinstance(row.get("capture_ref"), dict) and isinstance(row.get("evt_id"), int)
            and isinstance(row.get("ts"), int)]
