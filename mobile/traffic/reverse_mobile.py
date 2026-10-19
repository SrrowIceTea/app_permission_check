"""Explicit local RSS endpoint adapter; normal responses and original attribution. 仅用于授权测试。

Reverse mode rewrites request.host to its upstream. Keep the actually received
Host header and target-check against process connect events, not the rewritten
127.0.0.1 upstream. No forced package, synthetic flow or system proxy changes.
"""
import os
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from core.collector import addon
from mobile.traffic.reverse_target import local_target

load, response, error, done = addon.load, addon.response, addon.error, addon.done


def request(flow):
    addon.request(flow)
    target = local_target(flow.request.host_header, os.environ.get('VSCAN_LOCAL_REVERSE_PORT'))
    if target:
        found = addon.ATTRIB.resolve(flow.metadata['vscan_ts_ms'], target)
        if found.resolved and found.package in addon.WHITELIST:
            flow.metadata['vscan_found'] = found
