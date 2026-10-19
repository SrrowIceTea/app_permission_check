"""Unprivileged target-filtered VPN packets + optional owned-fixture HTTP sink.

仅用于授权测试。No system proxy/CA changes; no arbitrary protocol decryption.
VPN consent is handled by PCAPdroid/Android, never bypassed by this runner.
"""
from __future__ import annotations
import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path
from mobile.lab.core_traffic import Traffic, free_port, ROOT
from mobile.lab.pcap_sidecar import Sidecar
from mobile.lab.root_runtime import save, session_identifier
from mobile.lab.nonroot_vpn_identity import target_uid, vpn_uid_filter


class NonRootTraffic(Traffic):
    def __init__(self, android, session, package, fixture=False, *, sidecar=False, consent_timeout=120, scenario=None):
        self.android, self.session, self.package = android, session, package
        self.port, self.fixture = free_port(), fixture
        self.feed = scenario == "readyou" and package == "me.ash.reader"
        self.proc, self.log, self.sink = None, None, None
        self.sidecar = Sidecar(android.adb, android.serial, package, authorize_package=True) if sidecar else None
        self.name = "vscanner-gadget-" + str(time.time_ns()) + ".pcap"
        self.consent_timeout, self.requested = consent_timeout, False
        self.network = {"mode": "nonroot-vpn" if sidecar else "not_requested", "state": "not_started",
                        "package": package, "root_capture": False, "tls_decryption": False,
                        "system_ca_modified": False, "system_proxy_modified": False,
                        "scope": "configured target UID filter; plain PCAP has no per-packet UID and may include system DNS/sidecar probes; opaque TLS/QUIC remains ciphertext",
                        "gaps": []}

    def uid_diagnostic(self, label):
        try:
            packages = self.android.shell("cmd", "package", "list", "packages", "-U", self.package)
            raw = self.android.shell("dumpsys", "vpn_management")
            (self.session / (label + "-vpn-management.txt")).write_text(raw, encoding="utf-8")
            state = vpn_uid_filter(raw, target_uid(packages, self.package))
            save(self.session / (label + "-vpn-uid.json"), state)
            self.network["uid_filter"] = state
            if state["matches"] is False:
                note = "Observed VPN UID ranges do not include the currently installed target UID; stale package routing/filter is possible."
                if note not in self.network["gaps"]:
                    self.network["gaps"].append(note)
        except Exception as exc:
            self.network["uid_filter"] = {"matches": None, "status": "unknown", "reason": str(exc)}

    def start(self):
        for name in ("flows.jsonl", "flows-unanswered.jsonl", "egress.jsonl"):
            (self.session / name).touch()
        if self.fixture or self.feed:
            self.start_sink()
            env = {**os.environ, "VSCAN_FLOW_LOG": str(self.session / "flows.jsonl"),
                   "VSCAN_UNANSWERED_LOG": str(self.session / "flows-unanswered.jsonl"),
                   "VSCAN_ATTRIB_SOURCES": str(self.session / "egress.jsonl"),
                   "VSCAN_PACKAGES": self.package, "VSCAN_SESSION": session_identifier(self.session),
                   "VSCAN_TAGGING": str(ROOT / "mobile/traffic/tagging_mobile.py"), "PYTHONUNBUFFERED": "1"}
            if self.feed:
                env["VSCAN_ATTRIB_TARGET_CHECK"] = "1"
                env["VSCAN_LOCAL_REVERSE_PORT"] = str(self.port)
                self.network["declared_scenario"] = "User-visible Read You subscription to a local synthetic public RSS feed; no system proxy or CA changes"
            self.log = (self.session / "mitm.log").open("w", encoding="utf-8")
            self.proc = subprocess.Popen([str(Path(sys.executable).with_name("mitmdump.exe")),
                "-s", str(ROOT / ("mobile/traffic/reverse_mobile.py" if self.feed else "mobile/traffic/addon_mobile.py")), "--listen-host", "127.0.0.1",
                "--listen-port", str(self.port), "--mode", "reverse:http://127.0.0.1:" + str(self.sink.server_port),
                "--set", "flow_detail=0", "--set", "keep_host_header=true"], stdin=subprocess.DEVNULL, stdout=self.log, stderr=subprocess.STDOUT, env=env)
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                if self.proc.poll() is not None:
                    raise RuntimeError("owned-fixture HTTP proxy exited; inspect mitm.log")
                with socket.socket() as probe:
                    if probe.connect_ex(("127.0.0.1", self.port)) == 0:
                        break
                time.sleep(.2)
            else:
                raise RuntimeError("owned-fixture HTTP proxy did not become ready")
        if self.sidecar:
            try:
                self.requested = True
                state = self.sidecar.start(self.name)
                save(self.session / "capture-request.json", state)
                print("PCAPdroid 控制/VPN 请求等待确认；不使用 root。", flush=True)
                end = time.monotonic() + self.consent_timeout
                while not (state.get("capture_service") and state.get("vpn_connected")) and time.monotonic() < end:
                    time.sleep(1)
                    state = self.sidecar.status(self.name, observe=True)
                save(self.session / "capture-running.json", state)
                if not (state.get("capture_service") and state.get("vpn_connected")):
                    raise RuntimeError("target-filtered VPN was not confirmed before application startup")
                self.network["state"] = "running"
                self.uid_diagnostic("start")
            except Exception as exc:
                self.network.update(state="unavailable", error=str(exc))
                self.network["gaps"].append("VPN sidecar did not start; packet coverage unavailable.")
        else:
            self.network.update(state="not_requested")
            self.network["gaps"].append("VPN packet capture not requested; process hooks do not represent every packet.")

    def close(self):
        if self.sidecar and self.requested:
            try:
                self.uid_diagnostic("before-stop")
                state = self.sidecar.status(self.name, observe=True)
                save(self.session / "capture-before-stop.json", state)
                if self.network["state"] == "running" and not state.get("requested_capture_confirmed"):
                    self.network["gaps"].append("Named target-filtered PCAP was not observed during runtime.")
                stopped = self.sidecar.stop(self.name)
                if stopped.get("status") != "stopped":
                    print("请在设备确认 PCAPdroid 停止控制请求；等待真实停采后导出。", flush=True)
                    deadline = time.monotonic() + self.consent_timeout
                    while stopped.get("status") != "stopped" and time.monotonic() < deadline:
                        time.sleep(1)
                        stopped = self.sidecar.status(self.name)
                save(self.session / "capture-stop.json", stopped)
                if stopped.get("status") != "stopped":
                    raise RuntimeError("VPN capture did not stop; stop PCAPdroid before another experiment")
                self.network["stopped"] = True
                if self.network["state"] == "running":
                    save(self.session / "capture-pull.json", self.sidecar.pull(self.name, self.session / "traffic.pcap"))
                    from mobile.lab.pcap_inventory import inventory
                    fixture_packets = 0
                    def count_fixture_packet(row):
                        nonlocal fixture_packets
                        if self.port in (row.get("src_port"), row.get("dst_port")):
                            fixture_packets += 1
                    with (self.session / "traffic.pcap").open("rb") as handle:
                        summary = inventory(handle, count_fixture_packet)
                    if not summary.get("transport_decoded_packets"):
                        self.network["gaps"].append("No decodable transport packet in exported VPN PCAP; metadata-only/empty capture is not network coverage.")
                    if self.fixture:
                        self.network["fixture_http_port"] = self.port
                        self.network["fixture_http_packets"] = fixture_packets
                    save(self.session / "pcap-summary.json", summary)
                    self.network.update(state="done", pcap=summary)
            except Exception as exc:
                self.network.update(state="partial" if self.network["state"] == "running" else self.network["state"], error=str(exc))
                self.network["gaps"].append("VPN packet export incomplete: " + str(exc))
        if self.proc:
            time.sleep(2.5)
            self.proc.terminate()
            try:
                self.proc.wait(5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(5)
        if self.log:
            self.log.close()
        if self.sink:
            self.sink.shutdown()
            self.sink.server_close()
        save(self.session / "traffic-scope.json", self.network)
