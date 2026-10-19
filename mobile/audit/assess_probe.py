#!/usr/bin/env python3
"""仅用于授权测试：assess bounded authorized app observations, never assert a data leak.

All inputs may be synthetic. --canary is mandatory and must be a declared synthetic
marker, not real personal data. A negative result is not an absence/safety proof.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from cipher_storage import correlate_cipher_storage, explicit_symmetric_ecb

PACKAGE = "com.vscanner.privacydemo"
BASE_GAPS = [
    "Results concern storage API boundaries, not verified disk contents or exfiltration",
    "SharedPreferences.putString success does not prove commit/apply or persistence",
    "Only bounded prefixes are inspected; absence of a canary is inconclusive",
    "No Cipher.update, other doFinal overloads, native crypto/IO, SQLite or descriptor-only IO",
    "A known weak configuration is not proof of plaintext leakage",
    "Not matching a known weak configuration does not establish cryptographic safety",
    "Synthetic/offline fixture results do not demonstrate on-device execution",
]


def weak_reasons(algorithm: str) -> list[str]:
    """Explicit transformation only: bare AES is ambiguous, not assumed ECB."""
    parts = re.sub(r"\s+", "", algorithm).upper().split("/")
    base = parts[0].replace("-", "")
    reasons = []
    if base in {"DES", "DESEDE", "TRIPLEDES", "3DES", "TDEA"}:
        reasons.append("legacy_des_or_3des")
    if base in {"RC4", "ARC4", "ARCFOUR"}:
        reasons.append("legacy_rc4")
    if explicit_symmetric_ecb(algorithm):
        reasons.append("ecb_mode")
    return reasons


def text_contains(value: object, marker: str) -> bool:
    return isinstance(value, dict) and isinstance(value.get("text"), str) and marker in value["text"]


def bytes_contains(value: object, marker: bytes) -> bool:
    if not isinstance(value, dict) or not isinstance(value.get("hex"), str):
        return False
    try:
        return marker in bytes.fromhex(value["hex"])
    except ValueError:
        return False


def unwrap(value: dict) -> dict:
    """Accept driver's raw JSONL, direct send payload, or Frida send message."""
    if value.get("type") == "send" and isinstance(value.get("payload"), dict):
        value = value["payload"]
    if isinstance(value.get("line"), str):
        return json.loads(value["line"])
    return value


def assess(events: list[dict], canary: str, evidence_origin: str = "unverified",
           package: str = PACKAGE) -> dict:
    if not isinstance(package, str) or re.fullmatch(r"[A-Za-z]\w*(?:\.\w+)+", package, re.ASCII) is None:
        raise ValueError("package must be an exact valid Android package name")
    if not canary or len(canary.encode("utf-8")) > 256:
        raise ValueError("canary must be a nonempty synthetic marker of at most 256 UTF-8 bytes")
    raw_marker = canary.encode("utf-8")
    storage, crypto, gaps, counts = [], [], list(BASE_GAPS), {}
    indexed = []
    ready = False
    for line_no, raw in enumerate(events, 1):
        try:
            event = unwrap(raw)
        except (TypeError, ValueError):
            gaps.append(f"line {line_no}: malformed envelope ignored")
            continue
        if not isinstance(event, dict) or event.get("pkg") != package or event.get("src") != "storage_crypto":
            continue
        indexed.append((line_no, event))
        name = event.get("ev", "unknown")
        counts[name] = counts.get(name, 0) + 1
        ref = {"line": line_no, "evt_id": event.get("evt_id"), "ev": name}
        if name == "ARMED":
            ready = True
            gaps.extend(str(x) for x in event.get("coverage_gaps", []))
            gaps.extend("hook missing: " + str(x) for x in event.get("missing", []))
        if name in {"PROBE_ERROR", "OBSERVATION_ERROR", "HOOK_MISS", "NOT_READY"}:
            gaps.append(f"line {line_no}: {name}: {event.get('target', event.get('error', ''))}")
        if event.get("success") is not True:
            continue
        # CIPHER_FINAL alone proves neither storage nor leak; only exact paired writes below.
        if name == "PREF_PUT_STRING" and text_contains(event.get("value"), canary):
            storage.append({**ref, "observation_scope": "editor_staged", "disk_plaintext_proven": False,
                            "key": event.get("key")})
        if name == "FILE_WRITE" and bytes_contains(event.get("bytes"), raw_marker):
            storage.append({**ref, "observation_scope": "successful_stream_write", "disk_plaintext_proven": False,
                            "path": event.get("path"), "stream_id": event.get("stream_id")})
        if name == "CIPHER_INIT":
            algorithm = str(event.get("algorithm", ""))
            reasons = weak_reasons(algorithm)
            if reasons:
                crypto.append({**ref, "algorithm": algorithm, "opmode": event.get("opmode"),
                               "cipher_id": event.get("cipher_id"), "reasons": reasons,
                               "plaintext_leak_proven": False})
            if "/" not in algorithm and algorithm.upper() not in {"RC4", "ARC4", "ARCFOUR"}:
                gaps.append(f"line {line_no}: provider-default transformation/mode unresolved: {algorithm}")
    encrypted = correlate_cipher_storage(indexed, raw_marker, weak_reasons, package)
    gaps.extend(encrypted.pop("coverage_gaps"))
    if not ready:
        gaps.append("No ARMED event: hook coverage/liveness unverified; zero events are not a clean bill")
    for required in ("PREF_PUT_STRING", "FILE_WRITE", "CIPHER_INIT", "CIPHER_FINAL"):
        if not counts.get(required):
            gaps.append("No observed event for " + required)
    if evidence_origin != "device":
        gaps.append("evidence_origin=" + evidence_origin + "; no claim of real-device validation")
    return {"schema_version": 1, "package": package, "evidence_origin": evidence_origin,
            "canary_declared_synthetic": True, "storage_plaintext_observed": bool(storage),
            "weak_crypto_configuration": bool(crypto), "storage_evidence": storage,
            "weak_crypto_evidence": crypto, "disk_plaintext_proven": False,
            "plaintext_leak_proven": False, "crypto_safety_assessed": False,
            "event_counts": counts, **encrypted, "coverage_gaps": list(dict.fromkeys(gaps))}


def write_atomic(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        shutil.copy2(path, path.with_name(path.name + "." + stamp + ".bak"))
    temporary = None
    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", newline="\n", dir=path.parent,
                                         prefix=".assessment-", suffix=".tmp", delete=False) as out:
            temporary = Path(out.name)
            json.dump(value, out, ensure_ascii=False, indent=2)
            out.write("\n")
            out.flush()
            os.fsync(out.fileno())
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--events", type=Path, required=True)
    parser.add_argument("--package", default=PACKAGE, help="exact authorized package; default self-owned fixture")
    parser.add_argument("--canary", required=True, help="explicit synthetic marker; never personal data")
    parser.add_argument("--evidence-origin", choices=("synthetic", "device", "unverified"), default="unverified",
                        help="caller-declared provenance; choosing device is not independent attestation")
    parser.add_argument("--out", type=Path)
    args = parser.parse_args(argv)
    try:
        events = []
        for number, line in enumerate(args.events.read_text(encoding="utf-8").splitlines(), 1):
            if not line.strip():
                continue
            try:
                value = json.loads(line)
                if not isinstance(value, dict):
                    raise ValueError("record is not an object")
                events.append(value)
            except (ValueError, TypeError) as exc:
                raise ValueError(f"{args.events}:{number}: {exc}") from exc
        result = assess(events, args.canary, args.evidence_origin, args.package)
        if args.out:
            if args.out.resolve() == args.events.resolve():
                raise ValueError("--out must not overwrite input evidence")
            write_atomic(args.out, result)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    except (OSError, ValueError) as exc:
        parser.exit(2, str(exc) + "\n")


if __name__ == "__main__":
    raise SystemExit(main())
