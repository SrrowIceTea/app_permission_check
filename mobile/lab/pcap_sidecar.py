"""Non-root PCAPdroid v2.0.2 sidecar for one explicitly authorized package.

start/status/stop never bypass the phone's control or Android VPN consent.
CLI: pcap_sidecar.py start --serial SERIAL --name unique-session.pcap
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time

PKG = "com.vscanner.privacydemo"
SIDECAR = "com.emanuelef.remote_capture"
COMPONENT = SIDECAR + "/.activities.CaptureCtrl"
DOWNLOAD = "/sdcard/Download/PCAPdroid"


def valid_name(name):
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,100}\.pcap", name or ""):
        raise ValueError("--name must be a simple unique .pcap filename")
    return name


def run_command(command):
    return subprocess.run(command, capture_output=True, text=True, timeout=30, check=False)


def vpn_is_connected(text):
    headers = list(re.finditer(r"(?m)^\s*(?:User\s+)?(\d+):[^\n]*", text))
    for index, match in enumerate(headers):
        if match.group(1) != "0":
            continue
        end = headers[index + 1].start() if index + 1 < len(headers) else len(text)
        block = text[match.start():end]
        owned = re.search(r"(?:Active package name|mPackage)\s*[=:]\s*"
                          r"com\.emanuelef\.remote_capture\b", block)
        interface = re.search(r"mInterface\s*[=:]\s*(?!null\b|none\b)[A-Za-z0-9_.-]+", block)
        native = "Transports: VPN" in block and "sessionId=PCAPdroid VPN" in block
        if owned and (interface or native):
            return True
    return False


class Sidecar:
    def __init__(self, adb, serial, package=PKG, runner=run_command, sleeper=time.sleep, *, authorize_package=False):
        if not re.fullmatch(r"[A-Za-z]\w*(?:\.\w+)+", package or ""):
            raise ValueError("one exact package name is required")
        if package != PKG and not authorize_package:
            raise ValueError("explicit authorization required for a non-fixture package")
        self.package = package
        self.scope = "owned_fixture_only" if package == PKG else "explicit_authorized_package"
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", serial or ""):
            raise ValueError("explicit valid --serial is required")
        self.prefix, self.runner, self.sleep = [str(adb), "-s", serial], runner, sleeper

    def call(self, *args):
        return self.runner(self.prefix + list(args))

    def size(self, name):
        remote = DOWNLOAD + "/" + valid_name(name)
        script = ("if [ ! -r /sdcard/Download ]; then echo PCAP_STATE_INACCESSIBLE; "
                  f"elif [ -e {remote} ]; then stat -c %s {remote}; "
                  "else echo PCAP_STATE_MISSING; fi")
        result = self.call("shell", script)
        value = result.stdout.strip()
        if result.returncode or value == "PCAP_STATE_INACCESSIBLE":
            raise RuntimeError("cannot inspect capture file through ordinary adb shell")
        if value == "PCAP_STATE_MISSING":
            return None
        if not value.isdigit():
            raise RuntimeError("capture file size is unavailable")
        return int(value)

    def status(self, name=None, observe=False):
        services = self.call("shell", "dumpsys", "activity", "services", SIDECAR)
        text = services.stdout
        readable = not services.returncode and not re.search(
            r"Permission Denial|Can't find service|Error:|Exception", text + services.stderr)
        service = readable and bool(re.search(
            r"ServiceRecord\{[^\n]*\bu0\s+com\.emanuelef\.remote_capture/[^\n]*CaptureService", text))
        vpn = self.call("shell", "dumpsys", "vpn_management")
        vpn_text = vpn.stdout if not vpn.returncode else ""
        # Require the owned user's block; another user's VPN cannot prove capture.
        vpn_connected = vpn_is_connected(vpn_text)
        before = self.size(name) if name else None
        after = before
        if observe and name and service and not vpn_connected:
            self.sleep(1)
            after = self.size(name)
        growing = before is not None and after is not None and after > max(24, before)
        confirmed = bool(service and (vpn_connected or growing))
        state = "running" if confirmed else "unknown" if service or not readable else "stopped"
        # FileDumper may buffer even its header until the first captured packet.
        named = bool(name and after is not None)
        return {"status": state, "capture_service": bool(service),
                "vpn_connected": bool(vpn_connected), "file_growing": growing,
                "named_capture_observed": named,
                "requested_capture_confirmed": bool(confirmed and named),
                "pcap_bytes": after, "name": name, "package": self.package,
                "scope": self.scope, "root_capture": False,
                "tls_decryption": False}

    def control(self, action, extras=()):
        result = self.call("shell", "am", "start", "-W", "--es", "action", action,
                           *extras, "-n", COMPONENT)
        if result.returncode or re.search(r"Error:|Exception|Permission Denial", result.stdout + result.stderr):
            raise RuntimeError("PCAPdroid control intent failed; inspect the device")

    def start(self, name):
        name = valid_name(name)
        current = self.status()
        if current["capture_service"] or current["status"] == "unknown":
            raise RuntimeError("existing or uninspectable capture; do not replace it")
        if self.size(name) is not None:
            raise FileExistsError("remote capture name already exists; use a new --name")
        extras = ["--es", "pcap_dump_mode", "pcap_file", "--es", "pcap_name", name,
                  "--es", "app_filter", self.package, "--es", "ip_mode", "both",
                  "--es", "block_quic", "never"]
        for key, value in (("root_capture", False), ("tls_decryption", False),
                           ("auto_block_private_dns", False), ("full_payload", True),
                           ("pcapng_format", False), ("dump_extensions", False),
                           ("socks5_enabled", False)):
            extras += ["--ez", key, str(value).lower()]
        # v2.0.2 pcapdroid.c: <=0 means no per-flow packet limit.
        # pcap_dump.c: max_dump_size is enforced only when >0.
        for key, value in (("snaplen", 65535), ("max_pkts_per_flow", 0), ("max_dump_size", 0)):
            extras += ["--ei", key, str(value)]
        self.control("start", extras)
        self.sleep(1)
        result = self.status(name, observe=True)
        if not result["requested_capture_confirmed"]:
            result["status"] = "pending_capture_file_or_consent"
        result["next_action"] = ("capture confirmed" if result["status"] == "running" else
                                 "check phone consent/startup, then run status with --name")
        return result

    def stop(self, name=None):
        if name:
            valid_name(name)
        self.control("stop")
        result = self.status(name)
        deadline = time.monotonic() + 15
        for _ in range(14):
            remaining = deadline - time.monotonic()
            if result["status"] == "stopped" or remaining <= 0:
                break
            self.sleep(min(1, remaining))
            result = self.status(name)
        if result["status"] != "stopped":
            result["next_action"] = "check phone control consent and run status again"
        return result

    def pull(self, name, out):
        name, out = valid_name(name), Path(out).resolve()
        if out.exists():
            raise FileExistsError("local destination already exists; refusing to overwrite")
        state = self.status(name)
        if state["status"] != "stopped":
            raise RuntimeError("stop and confirm the capture has stopped before pulling")
        if state["pcap_bytes"] is None or state["pcap_bytes"] <= 24:
            raise RuntimeError("capture is missing or contains no packet records")
        out.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(prefix=".pcap-pull-", suffix=".part", dir=out.parent)
        os.close(fd)
        tmp = Path(tmp)
        try:
            result = self.call("pull", DOWNLOAD + "/" + name, str(tmp))
            if result.returncode or tmp.stat().st_size != state["pcap_bytes"]:
                raise RuntimeError("capture pull failed or transferred size differs")
            with tmp.open("rb") as stream:
                if stream.read(4) not in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4"):
                    raise RuntimeError("downloaded file is not the requested classic PCAP")
            os.link(tmp, out)  # Atomic creation; never replaces an existing destination.
        finally:
            tmp.unlink(missing_ok=True)
        return {"status": "pulled", "name": name, "out": str(out),
                "bytes": out.stat().st_size, "scope": self.scope}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    for action in ("start", "stop", "status", "pull"):
        command = sub.add_parser(action)
        command.add_argument("--serial", required=True)
        command.add_argument("--package", default=PKG)
        command.add_argument("--authorize-package", action="store_true")
        command.add_argument("--adb", type=Path)
        command.add_argument("--name", required=action in ("start", "pull"))
        if action == "pull":
            command.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        adb = args.adb
        if adb is None:
            sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
            from device_environment import resolve_adb
            adb = resolve_adb()
        sidecar = Sidecar(adb, args.serial, args.package, authorize_package=args.authorize_package)
        result = (sidecar.start(args.name) if args.action == "start" else
                  sidecar.stop(args.name) if args.action == "stop" else
                  sidecar.pull(args.name, args.out) if args.action == "pull" else
                  sidecar.status(args.name, observe=True))
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0 if result["status"] in ("running", "stopped", "pulled") else 2
    except (ValueError, OSError, RuntimeError, subprocess.SubprocessError) as error:
        print(json.dumps({"status": "error", "error": str(error)}, ensure_ascii=False))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
