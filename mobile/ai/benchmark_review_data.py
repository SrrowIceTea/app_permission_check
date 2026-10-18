"""Build label-blind benchmark evidence and map anonymous references back to source."""
from __future__ import annotations

import json
from pathlib import Path

OBSERVATIONS = {
    "probe_armed", "evidence_scope", "event_counts", "encryption_calls", "algorithms",
    "provider_default_mode_unresolved", "same_input_output_repeat_observed",
    "explicit_ecb_observed", "token_count", "token_repeat_observed", "iv_reuse_observed",
    "iv_fingerprint_groups", "disk_base64_matches_ciphertext", "disk_expected_base64_segments",
    "exact_crypto_write_relations", "disk_bytes", "resource_matches", "placement",
    "endpoint_payload_observed", "plaintext_packet_observed", "plaintext_stream_observed",
    "matched_packets", "matched_streams", "stream_marker_matches", "transport_plaintext_observed",
    "refusal_control_observed", "target_file_content_observed", "personal_information_proven",
    "response_seen", "handshake_rejected", "server_requests", "self_signed_certificate_accepted",
}
STATIC_FIELDS = ("state", "whole_dex_scanned", "candidate_count", "rules_evaluated",
                 "dex_count", "unhandled_rule_types", "gaps", "scan_scope", "scan_mode")
SDK_FIELDS = ("min_sdk", "target_sdk", "compile_sdk", "max_sdk")
MANIFEST_FLAGS = ("debuggable", "uses_cleartext_traffic", "allow_backup")


def sdk_value(value) -> bool:
    return value is None or type(value) is int or isinstance(value, str) and value.isdecimal()


def build_input(batch: dict) -> tuple[dict, dict]:
    """Never send author labels, sample names, variants, paths, or UI strings to the model."""
    samples, mapping, seen = [], {}, set()
    runtime_samples = 0
    for index, sample in enumerate(batch.get("samples") or [], 1):
        sample_id = sample.get("sample_id")
        if not isinstance(sample_id, str) or not sample_id or sample_id in seen:
            raise ValueError("Each sample needs a unique nonempty sample_id")
        seen.add(sample_id)
        anonymous = f"sample_{index:02d}"
        refs, evidence = {}, []

        def add(pointer: str, value) -> None:
            ref = f"{anonymous}:e{len(evidence) + 1:03d}"
            refs[ref] = {"sample_id": sample_id, "json_pointer": pointer,
                         "artifact": "batch.json"}
            evidence.append({"evidence_ref": ref, "field": "/".join(pointer.split("/")[3:]),
                             "value": value})

        prefix = f"/samples/{index - 1}"
        for key, value in (sample.get("observations") or {}).items():
            if key in OBSERVATIONS:
                add(f"{prefix}/observations/{key}", value)
        static = sample.get("static_summary") or {}
        for key in STATIC_FIELDS:
            if key in static:
                add(f"{prefix}/static_summary/{key}", static[key])
        for key in SDK_FIELDS:
            if key in sample and sdk_value(sample[key]):
                add(f"{prefix}/{key}", sample[key])
            elif key in (static.get("apk") or {}) and sdk_value(static["apk"][key]):
                add(f"{prefix}/static_summary/apk/{key}", static["apk"][key])
        flags = sample.get("manifest_flags")
        flag_prefix = f"{prefix}/manifest_flags"
        if not isinstance(flags, dict):
            flags = static.get("manifest_flags") or {}
            flag_prefix = f"{prefix}/static_summary/manifest_flags"
        for key in MANIFEST_FLAGS:
            if key in flags and (flags[key] is None or isinstance(flags[key], bool)):
                add(f"{flag_prefix}/{key}", flags[key])
        stages = sample.get("stages") or {}
        runtime = bool(sample.get("observations"))
        for key in ("install", "launch", "trigger", "observe"):
            state = (stages.get(key) or {}).get("state")
            if state:
                add(f"{prefix}/stages/{key}/state", state)
            runtime = runtime or key == "observe" and state == "done"
        runtime_samples += int(runtime)
        for number, finding in enumerate(sample.get("findings") or []):
            add(f"{prefix}/findings/{number}", {key: finding[key] for key in
                ("kind", "rule_id", "detail", "evidence_ids") if key in finding})
        # The deterministic risk module may supply a score, but the model cannot change it.
        risk = sample.get("risk_assessment") or {}
        for key in ("score", "level", "risk_score", "risk_level", "score_status",
                    "coverage", "confidence", "limitations", "unassessed_dimensions"):
            if key in risk:
                add(f"{prefix}/risk_assessment/{key}", risk[key])
        for number, finding in enumerate(risk.get("findings") or []):
            add(f"{prefix}/risk_assessment/findings/{number}", {key: finding[key] for key in
                ("title", "severity", "score", "dimension", "evidence_strength", "likelihood",
                 "impact", "rationale") if key in finding})
        mapping[anonymous] = {"sample_id": sample_id, "refs": refs}
        samples.append({"sample_id": anonymous, "policy_available": False, "evidence": evidence})
    if not samples:
        raise ValueError("Batch has no samples")
    scope = ("static technical evidence only; no runtime observation supplied"
             if not runtime_samples else "provided static and runtime evidence; not every domain or app behavior covered")
    return {"samples": samples, "regulations": [], "scope": scope + "; no policy or legal assessment"}, mapping


def map_output(parsed: dict, mapping: dict) -> dict:
    """Called only after validation, preserving exact references as JSON pointers."""
    output = json.loads(json.dumps(parsed, ensure_ascii=False))
    for sample in output["samples"]:
        item = mapping[sample["sample_id"]]
        sample["sample_id"] = item["sample_id"]
        all_refs = set(sample["summary_evidence_refs"])
        for key in ("concerns", "advice", "limitations"):
            for claim in sample[key]:
                all_refs.update(claim["evidence_refs"])
        sample["evidence_registry"] = {ref: item["refs"][ref] for ref in sorted(all_refs)}
    return output


def load_runtime_config(path: Path | None) -> dict:
    """Read only the user's named provider fields; never persist the source settings."""
    import llm_client
    if path is None:
        cfg = llm_client.load_config()
    else:
        source = json.loads(path.read_text(encoding="utf-8-sig"))
        if isinstance(source.get("ark"), dict):
            provider = source["ark"]
            cfg = {"base_url": provider.get("base_url"), "model": provider.get("text_model"),
                   "api_key": provider.get("api_key")}
        else:
            cfg = {key: source.get(key) for key in ("base_url", "model", "api_key")}
    if not all(isinstance(cfg.get(key), str) and cfg[key].strip()
               for key in ("base_url", "model", "api_key")):
        raise llm_client.ConfigError("Selected provider needs base_url, model, and api_key")
    if cfg["api_key"].strip() in llm_client.PLACEHOLDER_KEYS:
        raise llm_client.ConfigError("Selected provider API key is a placeholder")
    return {**cfg, "temperature": 0.1, "max_tokens": 24000, "timeout_s": 300,
            "max_retries": 0}
