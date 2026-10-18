"""仅用于授权测试：narrow exact-value crypto-to-write observation, not taint proof."""
from __future__ import annotations

import base64
import re

from collections.abc import Callable

WINDOW_MS = 5000
SYMMETRIC_BLOCK_CIPHERS = {
    "AES", "AES_128", "AES_192", "AES_256", "DES", "DESEDE", "TRIPLEDES", "3DES", "TDEA",
    "BLOWFISH", "RC2", "CAMELLIA", "SEED", "SM4", "TWOFISH", "SERPENT", "CAST5", "CAST6", "IDEA",
}
BASE_GAPS = [
    "Crypto-to-write exact or explicit-value-transform matching is API-boundary equality plus ordering, not taint causality",
    "Matching successful FileOutputStream writes do not independently prove disk persistence or exfiltration",
    "Only complete single-call exact-canary encryption and complete raw/Base64.DEFAULT equal writes within 5000ms are joined",
    "Split/concatenated/other-encoded ciphertext, truncated values and missing session/pid are not joined",
    "AES/GCM observed does not establish safe key management, nonce uniqueness, tag validation or overall safety",
]


def explicit_symmetric_ecb(algorithm: str) -> bool:
    """RSA/ECB is a provider transformation placeholder, not symmetric ECB mode.

    An unrecognized transformation remains unclassified, never a safety finding.
    """
    parts = re.sub(r"\s+", "", algorithm).upper().split("/")
    return (len(parts) > 1 and parts[1] == "ECB" and
            parts[0].replace("-", "") in SYMMETRIC_BLOCK_CIPHERS)


def complete_bytes(value: object) -> bytes | None:
    """Reject partial previews and contradictory metadata, including bool-as-int."""
    if not isinstance(value, dict) or value.get("truncated") is not False:
        return None
    length, captured, text = value.get("len"), value.get("captured"), value.get("hex")
    if type(length) is not int or type(captured) is not int or length < 0 or captured != length:
        return None
    if not isinstance(text, str) or len(text) != 2 * length:
        return None
    try:
        raw = bytes.fromhex(text)
    except ValueError:
        return None
    return raw if len(raw) == length else None


def identity(event: dict, package: str) -> tuple | None:
    session, pid = event.get("session_id"), event.get("pid")
    if event.get("pkg") != package or event.get("src") != "storage_crypto":
        return None
    if not isinstance(session, str) or not session.strip() or type(pid) is not int or pid <= 0:
        return None
    return package, session, pid


def reference(line: int, event: dict) -> dict:
    return {"line": line, "evt_id": event.get("evt_id"), "ev": event.get("ev")}


def configuration(algorithm: str, classify: Callable[[str], list[str]]) -> tuple[str, list[str]]:
    reasons = classify(algorithm)
    if reasons:
        return "weak_configuration", reasons
    if algorithm.upper().replace(" ", "") == "AES/GCM/NOPADDING":
        return "strong_algorithm_observed", []
    return "unclassified_configuration", []


def written_transform(ciphertext: bytes, written: bytes) -> str | None:
    """Exact re-encoding, never permissive decoding or whitespace removal.

    Android Base64.DEFAULT uses standard alphabet/padding, LF after each 76
    encoded characters and a final LF for nonempty input. encodebytes matches
    those bytes; misplaced whitespace, CRLF, missing padding and garbage fail.
    """
    if written == ciphertext:
        return "identity"
    if written == base64.encodebytes(ciphertext):
        return "android_base64_default"
    return None


def correlate_cipher_storage(indexed_events: list[tuple[int, dict]], canary: bytes,
                             classify: Callable[[str], list[str]], package: str) -> dict:
    """Require same declared session/process, exact complete bytes and forward <=5s."""
    candidates, writes, evidence, gaps = [], [], [], list(BASE_GAPS)
    for line, event in indexed_events:
        if event.get("success") is not True or event.get("ev") not in {"CIPHER_FINAL", "FILE_WRITE"}:
            continue
        owner = identity(event, package)
        if owner is None:
            if event.get("pkg") == package and event.get("src") == "storage_crypto":
                gaps.append("Crypto/storage event missing nonempty session_id or positive integer pid; not joined")
            continue
        timestamp = event.get("ts")
        if type(timestamp) is not int:
            gaps.append("Crypto/storage event lacks an integer device timestamp; not joined")
            continue
        if event["ev"] == "FILE_WRITE":
            raw = complete_bytes(event.get("bytes"))
            if raw is None:
                gaps.append("Truncated/incomplete FILE_WRITE bytes cannot be exactly correlated")
            elif raw:
                writes.append((line, event, owner, timestamp, raw))
            continue
        if type(event.get("opmode")) is not int or event["opmode"] != 1:
            continue  # Decrypt/unknown/wrap are never encryption candidates.
        if event.get("input_role") != "plaintext" or event.get("output_role") != "ciphertext":
            gaps.append("Encrypt CIPHER_FINAL missing confirmed plaintext/ciphertext direction; not joined")
            continue
        plain, cipher = complete_bytes(event.get("input")), complete_bytes(event.get("output"))
        if plain is None or cipher is None:
            gaps.append("Truncated/incomplete CIPHER_FINAL input/output cannot be exactly correlated")
        elif plain == canary and cipher:
            candidates.append((line, event, owner, timestamp, cipher))
    for cipher_line, cipher, owner, start, ciphertext in candidates:
        for write_line, write, write_owner, end, written in writes:
            if owner != write_owner or write_line <= cipher_line or not 0 <= end - start <= WINDOW_MS:
                continue
            transform = written_transform(ciphertext, written)
            if transform is None:
                continue
            algorithm = str(cipher.get("algorithm", ""))
            config, reasons = configuration(algorithm, classify)
            evidence.append({
                "relation": "value_exact" if transform == "identity" else "value_transform_exact",
                "value_transform": transform, "written_bytes": len(written), "configuration_class": config,
                "algorithm": algorithm, "weak_reasons": reasons,
                "pkg": owner[0], "session_id": owner[1], "pid": owner[2],
                "cipher_event": reference(cipher_line, cipher), "write_event": reference(write_line, write),
                "cipher_id": cipher.get("cipher_id"), "stream_id": write.get("stream_id"),
                "path": write.get("path"), "delta_ms": end - start, "window_ms": WINDOW_MS,
                "canary_match": "input_exact", "ciphertext_bytes": len(ciphertext),
                "observation_scope": "successful_stream_write", "disk_persistence_proven": False,
                "full_taint_causality_proven": False, "plaintext_leak_proven": False,
                "crypto_safety_assessed": False,
            })
    if not evidence:
        gaps.append("No eligible exact crypto-to-write pair; this is not proof of absent encrypted storage")
    return {"weak_ciphertext_storage_observed": any(
                row["configuration_class"] == "weak_configuration" for row in evidence),
            "encrypted_storage_evidence": evidence, "coverage_gaps": list(dict.fromkeys(gaps))}
