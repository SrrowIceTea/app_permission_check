"""Original-APK static candidates and scoped network metadata. 仅用于授权测试。

ST never means executed; N never means personal-data transfer or plaintext.
Full grouped source indices stay in the bundle; only explicit projections reach AI.
"""
from __future__ import annotations
from collections import Counter
import hashlib
import json
from pathlib import Path
from urllib.parse import urlsplit
from mobile.lab.pcap_inventory import inventory


def artifact(path):
    return {"name": path.name, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}


def grouped(groups, content, index, prefix):
    key = json.dumps(content, ensure_ascii=False, sort_keys=True)
    if key not in groups:
        groups[key] = {"evidence_id": prefix + str(len(groups) + 1), **content,
                       "count": 0, "source_indices": []}
    row = groups[key]
    row["count"] += 1
    row["source_indices"].append(index)
    return row


def build_static(path, app, gaps):
    if path is None:
        return {"available": False, "findings": [], "gaps": ["Static evidence not supplied."]}
    path = Path(path)
    raw = json.loads(path.read_text(encoding="utf-8"))
    identity = raw.get("apk") or {}
    if (not app.get("apk_sha256") or identity.get("sha256") != app["apk_sha256"]
            or identity.get("package") != app.get("package") or raw.get("available") is not True):
        raise ValueError("static evidence original APK SHA256/package identity mismatch or unavailable")
    findings = raw.get("findings")
    if not isinstance(findings, list) or not all(isinstance(f, dict) for f in findings):
        raise ValueError("static findings must be objects")
    groups = {}
    keys = ("rule_id", "title", "rule_type", "severity", "data_type_key", "evidence_kind",
            "finding_source", "matched_apis", "signals", "static_strength", "note")
    for index, finding in enumerate(findings):
        content = {key: finding[key] for key in keys if key in finding}
        content.update(conclusion_level="candidate", runtime_execution_proven=False,
                       personal_data_transfer_proven=False, source_artifact=path.name)
        grouped(groups, content, index, "ST")
    local_gaps = list(raw.get("gaps") or [])
    gaps.extend("[static] " + str(gap) for gap in local_gaps)
    return {"schema_version": 1, "available": True, "package": app["package"],
            "apk_sha256": app["apk_sha256"], "source_artifact": artifact(path),
            "findings": list(groups.values()), "source_finding_count": len(findings),
            "whole_dex_scanned": raw.get("whole_dex_scanned"),
            "rules_evaluated": raw.get("rules_evaluated"), "coverage": raw.get("coverage") or {},
            "decompile": raw.get("decompile"), "gaps": local_gaps,
            "scope": "Manifest/DEX references only; not runtime code locations, execution or leakage proof."}


def _endpoint(row):
    if row.get("ev") == "EGRESS_URL":
        try:
            url = urlsplit(row.get("url") or "")
            return {"host": url.hostname, "port": url.port, "scheme": url.scheme}
        except (ValueError, TypeError):
            return {"host": None, "port": None, "scheme": None}
    return {"host": row.get("target_host"), "ip": row.get("target_ip"), "port": row.get("target_port")}


def build_network(session, app, gaps):
    session = Path(session)
    groups, sources, excluded = {}, {}, Counter()
    path = session / "egress.jsonl"
    rows = []
    if path.is_file():
        sources[path.name] = artifact(path)
        for line, text in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if not text.strip():
                continue
            try:
                row = json.loads(text)
                if not isinstance(row, dict):
                    raise ValueError("object required")
                rows.append((line, row))
            except (ValueError, TypeError):
                excluded["malformed_egress_lines"] += 1
    starts = {(r.get("session_id"), r.get("pid")) for _, r in rows
              if r.get("ev") == "START" and r.get("src") == "egress"
              and r.get("package") == app.get("package")
              and isinstance(r.get("session_id"), str) and type(r.get("pid")) is int and r["pid"] > 0}
    for line, row in rows:
        if row.get("ev") not in {"EGRESS_URL", "EGRESS_CONNECT"}:
            continue
        if (row.get("src") != "egress" or row.get("package") != app.get("package")
                or len(starts) != 1 or (row.get("session_id"), row.get("pid")) not in starts):
            excluded["unbound_egress_events"] += 1
            continue
        content = {"kind": "process_egress_metadata", "event": row["ev"],
                   "endpoint": _endpoint(row), "outcome": row.get("outcome"),
                   "via": row.get("via"), "package": app["package"],
                   "pid": row["pid"], "session_id": row["session_id"],
                   "attribution": "target_process_hook", "source_artifact": path.name,
                   "payload_visibility": "not_captured", "plaintext_leak_proven": False,
                   "personal_data_transfer_proven": False}
        grouped(groups, content, line, "N")
    pcap, summary = session / "traffic.pcap", None
    if pcap.is_file():
        sources[pcap.name] = artifact(pcap)
        def packet(row):
            index = row.get("packet_index")
            if not index:
                excluded["pcap_tail_gaps"] += 1
                return
            keys = ("protocol", "src_ip", "dst_ip", "src_port", "dst_port", "tcp_flags", "gaps")
            content = {key: row.get(key) for key in keys}
            size = row.get("captured_transport_payload_bytes") or 0
            content.update(kind="packet_metadata", source_artifact=pcap.name,
                           attribution="unattributed_packet", app_uid_attribution="unavailable",
                           payload_visibility="opaque_not_inspected", has_transport_payload=bool(size),
                           plaintext_leak_proven=False, personal_data_transfer_proven=False)
            result = grouped(groups, content, index, "N")
            result["transport_payload_bytes"] = result.get("transport_payload_bytes", 0) + size
            result["captured_bytes"] = result.get("captured_bytes", 0) + row.get("available_bytes", 0)
        try:
            with pcap.open("rb") as source:
                summary = inventory(source, packet)
        except (OSError, ValueError) as exc:
            gaps.append("[network] PCAP inventory incomplete: " + str(exc))
    observations = list(groups.values())
    local_gaps = ["PCAP has no independent per-packet UID proof; DNS/sidecar/system traffic may be included.",
                  "URL construction/connect attempts and opaque packets do not establish request content, sensitive transfer, TLS decryption or leakage."]
    if not observations:
        local_gaps.append("No attributable process egress or packet metadata observed; network behavior remains unknown.")
    if excluded:
        local_gaps.append("Excluded unbound/malformed source records: " + json.dumps(dict(excluded), sort_keys=True))
    gaps.extend("[network] " + gap for gap in local_gaps)
    return {"schema_version": 1, "available": bool(sources), "observations": observations,
            "source_artifacts": sources, "pcap_summary": summary,
            "excluded_counts": dict(excluded), "gaps": local_gaps,
            "masking": "No URL path/query/userinfo, payload bytes, stack or response body included."}


def project_supplemental(bundle, *, network_limit=32, max_chars=60000):
    """Keep every ST; bound grouped N input with explicit IDs/counts omitted from AI."""
    static, network = bundle.get("static") or {}, (bundle.get("traffic") or {}).get("network_observations") or {}
    static_rows = []
    for row in static.get("findings") or []:
        selected = {k: v for k, v in row.items() if k not in ("source_indices", "matched_apis")}
        apis = row.get("matched_apis") or []
        selected.update(matched_apis=apis[:3], matched_api_count=len(apis),
                        matched_api_details_omitted=max(0, len(apis) - 3))
        static_rows.append(selected)
    rows = network.get("observations") or []
    ranked = sorted(rows, key=lambda r: (r.get("kind") != "process_egress_metadata",
                    -r.get("transport_payload_bytes", 0), -r.get("count", 0), r["evidence_id"]))
    chosen = ranked[:network_limit]
    kept = {r["evidence_id"] for r in chosen}
    result = {"static": {"available": static.get("available", False), "findings": static_rows,
                         "scope": static.get("scope"), "gaps": static.get("gaps", [])},
              "network": {"available": network.get("available", False),
                          "observations": [{k: v for k, v in r.items() if k != "source_indices"} for r in chosen],
                          "gaps": network.get("gaps", []), "pcap_summary": network.get("pcap_summary")},
              "projection": {"all_static_candidates_included": True, "network_groups_total": len(rows),
                             "network_groups_included": len(chosen),
                             "network_omitted_ids": [r["evidence_id"] for r in rows if r["evidence_id"] not in kept],
                             "network_omitted_source_records": sum(r["count"] for r in rows if r["evidence_id"] not in kept),
                             "source_indices": "Full grouped source indices are retained in the bundle; not sent to AI."}}
    if len(json.dumps(result, ensure_ascii=False)) > max_chars:
        raise ValueError("supplemental AI projection exceeds explicit budget; no silent truncation")
    return result
