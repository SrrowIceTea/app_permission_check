"""Pinned public Ghera cases; 仅用于授权测试，不运行攻击 APK。"""
from __future__ import annotations
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
COMMIT = "ea1dbe234e4d3433161a3b85e96648913a36e83c"
PACKAGE = "edu.ksu.cs.benign"
GROUPS = (
    ("ecb", "Crypto", "BlockCipher-ECB-InformationExposure-Lean"),
    ("cbc", "Crypto", "BlockCipher-NonRandomIV-InformationExposure-Lean"),
    ("storage", "Storage", "ExternalStorage-InformationLeak-Lean"),
    ("socket", "Networking", "OpenSocket-InformationLeak-Lean"),
    ("tls", "Networking", "InvalidCertificateAuthority-MITM-Lean"),
)


def selected(corpus: Path, kinds: list[str] | None = None) -> list[dict]:
    corpus = corpus.resolve()
    manifest = json.loads((corpus / "manifest.json").read_text(encoding="utf-8"))
    if manifest.get("commit") != COMMIT:
        raise ValueError("Ghera commit does not match the evaluated corpus")
    artifacts = {row["repository_path"]: row for row in manifest["artifacts"]}
    result = []
    for kind, category, case in GROUPS:
        if kinds is not None and kind not in kinds:
            continue
        for variant in ("Benign", "Secure"):
            relative = f"{category}/{case}/{variant}/{case}-{variant.lower()}.apk"
            apk = corpus / "source" / relative
            expected = artifacts[relative]["sha256"]
            digest = hashlib.sha256(apk.read_bytes()).hexdigest()
            if digest != expected:
                raise ValueError("APK changed since corpus inventory: " + relative)
            namespace = "secure" if kind in {"cbc", "socket"} and variant == "Secure" else "benign"
            activity = ("edu.ksu.cs.benign.ResetPasswordActivity" if kind == "ecb"
                        else f"edu.ksu.cs.{namespace}.MainActivity")
            marker = "VSCAN_TEST_ROOT_20261017"
            result.append({"sample_id": f"ghera-{kind}-{variant.lower()}", "dataset": "Ghera",
                           "case_id": case, "kind": kind, "variant": variant, "package": PACKAGE,
                           "activity": activity, "apk": str(apk), "apk_sha256": digest,
                           "source_commit": COMMIT, "source_url": artifacts[relative]["source_url"],
                           "original_truth": "author_vulnerable" if variant == "Benign" else "author_corrected",
                           "canary": marker + "@example.test" if kind == "ecb" else marker,
                           "canary_exact": (marker + " , C" if kind == "cbc" else
                                            marker + "@example.test" if kind == "ecb" else marker)})
    if not result:
        raise ValueError("no supported cases selected")
    return result
