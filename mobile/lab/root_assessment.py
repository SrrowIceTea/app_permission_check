"""仅用于授权测试：facts-first assessment for controlled published APK benchmarks.

Author variant labels never select findings. observed means the target behavior
or refusal control was measured, not that a privacy violation was established.
"""
from __future__ import annotations

import base64
from collections import Counter, defaultdict
from pathlib import Path
import re
import sys

AUDIT = Path(__file__).resolve().parents[1] / "audit"
if str(AUDIT) not in sys.path:
    sys.path.insert(0, str(AUDIT))
from assess_probe import assess
from cipher_storage import complete_bytes

KINDS = {"ecb", "cbc", "storage", "socket", "tls"}


def positive_int(value):
    return type(value) is int and value > 0


def event_refs(rows):
    return ["event:" + str(row["evt_id"]) for row in rows if row.get("evt_id") is not None]


def fingerprint(value):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-fA-F]{64}", value) is not None


def encryptions(rows):
    return [row for row in rows if row.get("ev") == "CIPHER_FINAL" and row.get("success") is True
            and type(row.get("opmode")) is int and row["opmode"] == 1
            and row.get("input_role") == "plaintext" and row.get("output_role") == "ciphertext"
            and complete_bytes(row.get("input")) is not None
            and bool(complete_bytes(row.get("output")))]


def summarize(spec: dict, events: list[dict], oracle: dict, session_id: str) -> dict:
    if not isinstance(session_id, str) or not session_id.strip():
        raise ValueError("a nonempty exact session_id is required")
    kind, package = spec.get("kind"), spec.get("package")
    if kind not in KINDS:
        raise ValueError("unsupported benchmark kind")
    canary = spec.get("canary_exact", spec.get("canary"))
    rows = [row for row in events if isinstance(row, dict) and row.get("pkg") == package
            and row.get("session_id") == session_id and row.get("src") == "storage_crypto"]
    probe = assess(rows, canary, "device", package=package)
    findings, observations = [], {"kind": kind, "event_counts": probe["event_counts"],
        "probe_armed": bool(probe["event_counts"].get("ARMED")),
        "evidence_scope": "controlled_benchmark_not_general_app_compliance"}

    def finding(name, rule, refs, detail):
        findings.append({"kind": name, "rule_id": rule, "evidence_ids": list(dict.fromkeys(refs)),
                         "detail": detail})

    finals = encryptions(rows)
    observed, reason = False, "Target behavior was not confirmed by the supplied observations"
    if kind in {"ecb", "cbc"}:
        init = [row for row in rows if row.get("ev") == "CIPHER_INIT" and row.get("success") is True
                and type(row.get("opmode")) is int and row["opmode"] == 1]
        algorithms = sorted({str(row.get("algorithm", "")) for row in init + finals})
        unresolved = any("/" not in algorithm for algorithm in algorithms)
        samples = [(complete_bytes(row.get("input")), complete_bytes(row.get("output"))) for row in finals]
        observations.update(encryption_calls=len(finals), algorithms=algorithms,
                            provider_default_mode_unresolved=unresolved,
                            same_input_output_repeat_observed=any(n > 1 for n in Counter(samples).values()))
        observed = bool(finals)
        reason = "Successful complete encryption calls observed" if observed else reason
        if kind == "ecb":
            explicit = [row for row in init + finals
                        if "/ECB/" in str(row.get("algorithm", "")).upper().replace(" ", "")]
            observations["explicit_ecb_observed"] = bool(explicit)
            tokens = oracle.get("tokens", [])
            tokens = tokens if isinstance(tokens, list) else []
            tokens = [token for token in tokens if isinstance(token, str) and token]
            observations.update(token_count=len(tokens), token_repeat_observed=len(tokens) > len(set(tokens)))
            if explicit:
                finding("ecb_configuration_observed", "BENCH-CRYPTO-ECB", event_refs(explicit),
                        "Successful encrypt operations explicitly named ECB; configuration risk, not exfiltration proof.")
            if unresolved:
                reason += "; provider-default mode remains unresolved (bare AES is not labeled ECB)"
        else:
            groups = defaultdict(list)
            for row in init:
                iv_hash, iv_length = row.get("iv_sha256_16"), row.get("iv_len")
                algorithm = str(row.get("algorithm", ""))
                if "/CBC/" not in algorithm.upper().replace(" ", ""):
                    continue
                if positive_int(row.get("pid")) and positive_int(iv_length) and isinstance(iv_hash, str) \
                        and re.fullmatch(r"[0-9a-fA-F]{16}", iv_hash):
                    groups[(row["pid"], algorithm.upper(), iv_length, iv_hash.lower())].append(row)
            repeated = [group for group in groups.values() if len(group) > 1]
            observations["iv_reuse_observed"] = bool(repeated)
            observations["iv_fingerprint_groups"] = len(groups)
            if repeated:
                finding("iv_reuse_observed", "BENCH-CRYPTO-IV-REUSE",
                        event_refs([row for group in repeated for row in group]),
                        "CBC initialization reused an IV fingerprint in this process/session; key identity and permanent constancy are unverified.")
            disk = oracle.get("disk_base64")
            # The published case appends each full Base64.DEFAULT result. Preserve
            # observed call order and require the complete disk file, not a substring.
            matches = [row for row in finals if complete_bytes(row["input"]) == canary.encode("utf-8")]
            expected_disk = b"".join(base64.encodebytes(complete_bytes(row["output"])) for row in matches)
            observations["disk_base64_matches_ciphertext"] = bool(matches) and isinstance(disk, str) and \
                disk.encode("utf-8") == expected_disk
            observations["disk_expected_base64_segments"] = len(matches)
            observations["exact_crypto_write_relations"] = len(probe["encrypted_storage_evidence"])
            if probe["weak_ciphertext_storage_observed"]:
                finding("weak_ciphertext_storage_observed", "BENCH-STORAGE-WEAK-CIPHER",
                        ["oracle:disk_base64"] + event_refs(matches),
                        "Probe matched complete ciphertext or its explicit Base64.DEFAULT transformation to a successful write; disk oracle is reported separately.")
    elif kind == "storage":
        path, sha, resource_sha = oracle.get("disk_path"), oracle.get("sha256"), oracle.get("resource_sha256")
        confirmed = (isinstance(path, str) and bool(path) and positive_int(oracle.get("bytes"))
                     and fingerprint(sha) and fingerprint(resource_sha)
                     and sha.lower() == resource_sha.lower() and oracle.get("resource_matches") is True)
        external = isinstance(path, str) and path.startswith(("/sdcard/", "/storage/", "/mnt/sdcard/"))
        observations.update(disk_path=path, disk_bytes=oracle.get("bytes"),
                            resource_matches=bool(confirmed), placement="external" if external else "internal_or_other")
        observed = bool(confirmed)
        reason = "Written file exactly matches the benchmark resource" if observed else reason
        if confirmed and external:
            finding("external_storage_placement", "BENCH-STORAGE-EXTERNAL", ["oracle:disk_path", "oracle:sha256"],
                    "Benchmark resource was stored at the observed external path; root readability does not prove another app can read it on this Android version.")
    elif kind == "socket":
        pcap = oracle.get("pcap") if isinstance(oracle.get("pcap"), dict) else {}
        stats = pcap.get("canary") if isinstance(pcap.get("canary"), dict) else {}
        marker, received = oracle.get("payload_marker", canary), oracle.get("received")
        payload_seen = isinstance(marker, str) and bool(marker) and isinstance(received, str) and marker in received
        packet_seen = positive_int(stats.get("matched_packets"))
        streams = pcap.get("tcp_streams") if isinstance(pcap.get("tcp_streams"), dict) else {}
        declared_marker = oracle.get("payload_marker")
        stream_marker_matches = isinstance(declared_marker, str) and bool(declared_marker) and \
            streams.get("marker") == declared_marker
        stream_seen = positive_int(streams.get("matched_streams")) and stream_marker_matches
        observed = payload_seen and (packet_seen or stream_seen)
        actual = received.strip() if isinstance(received, str) else ""
        refusal = observed and actual == "Rejected"
        file_content = observed and actual == "Enter SSN"
        observations.update(endpoint_payload_observed=payload_seen, plaintext_packet_observed=packet_seen,
                            plaintext_stream_observed=stream_seen,
                            matched_packets=stats.get("matched_packets", 0),
                            matched_streams=streams.get("matched_streams", 0),
                            stream_marker_matches=stream_marker_matches,
                            transport_plaintext_observed=observed, refusal_control_observed=refusal,
                            target_file_content_observed=file_content, personal_information_proven=False)
        reason = "Endpoint and packet payload or validated TCP stream observed the declared transport text" if observed else reason
        if refusal:
            reason = "Endpoint and packet payload or validated TCP stream observed the explicit Rejected refusal control"
        elif file_content:
            finding("plaintext_network_exposure", "BENCH-NET-PLAINTEXT", ["oracle:received", "oracle:pcap"],
                    "The benchmark file text Enter SSN was received and matched in plaintext packet payload or marker-validated TCP stream; fixed demonstration text is not proof of personal-data leakage.")
    else:
        response, rejected, requests = oracle.get("response_seen"), oracle.get("handshake_rejected"), oracle.get("server_requests")
        accepted = response is True and rejected is not True and positive_int(requests)
        refusal = rejected is True and response is not True and type(requests) is int and requests == 0
        observations.update(response_seen=response is True, handshake_rejected=rejected is True,
                            server_requests=requests, self_signed_certificate_accepted=accepted)
        observed = accepted or refusal
        if accepted:
            reason = "Controlled self-signed TLS endpoint returned an application response"
            finding("certificate_validation_risk", "BENCH-TLS-CERT-VALIDATION",
                    ["oracle:response_seen", "oracle:server_requests"],
                    "The controlled self-signed endpoint was accepted with an application response; this is the tested certificate-validation condition, not universal TLS decryption.")
        elif refusal:
            reason = "Controlled self-signed TLS handshake was explicitly rejected; rejection control observed, not a general safety claim"
        elif response is True and rejected is True:
            reason = "Conflicting TLS acceptance/refusal signals; no single control result confirmed"
    return {"findings": findings, "observations": observations,
            "verdict": "observed" if observed else "not_observed", "reason": reason,
            "probe_assessment": probe}
