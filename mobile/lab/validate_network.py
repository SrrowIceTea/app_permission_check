"""Compare controlled local endpoint traffic against PCAP, not arbitrary app UID attribution.

仅用于授权测试。TLS payload should remain encrypted; missing plaintext is not a leak verdict.
"""
from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path

from pcap_inventory import inventory

PORTS = {"http": 18890, "https": 18891, "tcp": 18889, "udp": 18888}


def validate(packets: list[dict], receipts: list[dict], canary: str, context: str = "emulator"):
    if context not in ("emulator", "physical-vpn"):
        raise ValueError("unsupported capture context")
    received = Counter(row["protocol"] for row in receipts if row.get("synthetic_payload") == canary)
    results = {}
    for name, port in PORTS.items():
        rows = [row for row in packets if port in (row.get("src_port"), row.get("dst_port"))]
        matches = sum(row.get("canary") == "found" for row in rows)
        observed = bool(rows)
        plaintext_ok = matches == 0 if name == "https" else matches > 0
        results[name] = {"sink_received": received[name], "packets": len(rows),
                         "plaintext_canary_packets": matches,
                         "passed": received[name] > 0 and observed and plaintext_ok,
                         "protocol_counts": dict(Counter(row.get("protocol") for row in rows))}
    not_exercised = ["QUIC", "native custom TLS", "multi_process_app", "network_switch"]
    if context == "emulator":
        not_exercised += ["VpnService_sidecar", "production_user_image"]
    scope = ("controlled endpoints captured by physical device VPN; app filter is separate evidence"
             if context == "physical-vpn" else
             "controlled synthetic local ports; not independent app UID attribution")
    return {"passed": all(row["passed"] for row in results.values()), "controls": results,
            "capture_context": context,
            "capture_context_verification": "caller_declared_not_vpn_configuration_attestation",
            "scope": scope,
            "claim": "endpoint_positive_controls_only_not_universal_capture_proof",
            "tls_decrypted": False,
            "not_exercised": not_exercised,
            "unverified": ["IPv6 end-to-end payload", "all possible interfaces", "packet loss rate"]}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pcap", type=Path, action="append", required=True)
    parser.add_argument("--receipts", type=Path, required=True)
    parser.add_argument("--canary", required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--capture-context", choices=("emulator", "physical-vpn"), default="emulator",
                        help="caller-declared capture context, not VPN configuration attestation")
    args = parser.parse_args(argv)
    if not args.canary.startswith("VSCAN_TEST_"):
        parser.error("explicit synthetic VSCAN_TEST_ token required")
    if args.out.exists():
        parser.error("do not overwrite an earlier control result")
    packets, summaries = [], {}
    for path in args.pcap:
        with path.open("rb") as source:
            summary = inventory(source, packets.append, args.canary.encode())
            if args.capture_context == "physical-vpn":
                summary = {**summary, "globalcoverage": "observed_vpn_capture_only",
                           "app_uid_attribution": "unavailable_from_plain_pcap"}
            summaries[str(path)] = summary
    receipts = [json.loads(line) for line in args.receipts.read_text(encoding="utf-8").splitlines() if line.strip()]
    result = {**validate(packets, receipts, args.canary, context=args.capture_context),
              "pcap_summaries": summaries}
    args.out.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(result, ensure_ascii=False))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
