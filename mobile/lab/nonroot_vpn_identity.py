"""Read-only target UID versus the owned user's PCAPdroid VPN configuration.

Unsupported dumpsys forms are unknown, never evidence of a matching UID filter.
"""
from __future__ import annotations
import re

SIDECAR = "com.emanuelef.remote_capture"


def target_uid(text, package):
    matches = re.findall(r"(?m)^package:" + re.escape(package) + r"\s+uid:(\d+)\s*$", text)
    return int(matches[0]) if len(matches) == 1 else None


def vpn_uid_filter(text, uid):
    out = {"target_uid": uid, "matches": None, "status": "unknown", "ranges": [],
           "source": "ordinary-shell dumpsys vpn_management, owned user 0 PCAPdroid block"}
    if uid is None:
        out["reason"] = "selected package UID could not be uniquely resolved"
        return out
    headers = list(re.finditer(r"(?m)^\s*(?:User\s+)?(\d+):[^\n]*", text))
    blocks = []
    for index, match in enumerate(headers):
        if match[1] == "0":
            end = headers[index + 1].start() if index + 1 < len(headers) else len(text)
            blocks.append(text[match.start():end])
    owned = [block for block in blocks if re.search(
        r"(?:Active package name|mPackage)\s*[=:]\s*" + re.escape(SIDECAR) + r"\b", block)]
    if len(owned) != 1:
        out["reason"] = "no unique owned-user PCAPdroid block"
        return out
    values = list(dict.fromkeys(re.findall(r"\bUids:\s*(<\{[^}]*\}>|\{[^}]*\}|\[[^\]]*\])", owned[0])))
    if len(values) != 1 or not re.fullmatch(r"[<>{}\[\]\s,\d-]+", values[0]):
        out["reason"] = "VPN UID range syntax not supported or not uniquely present"
        return out
    ranges = [[int(start), int(end or start)] for start, end in re.findall(r"\b(\d+)(?:\s*-\s*(\d+))?\b", values[0])]
    if not ranges or any(start > end for start, end in ranges):
        out["reason"] = "no valid VPN UID ranges"
        return out
    out.update(ranges=ranges, matches=any(start <= uid <= end for start, end in ranges), status="observed")
    return out
