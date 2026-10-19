"""SDK signature-scoped observation; rules DB is never rewritten. 仅用于授权测试。"""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import re
from mobile.hooks.gen_targets import load, load_consent, render
from mobile.rules.extract_android_apis import extract, find_javap
from mobile.lab.root_runtime import save

ROOT = Path(__file__).resolve().parents[2]


def key(row):
    return row["cls"], row["method"], row["desc"]


def select(entries, facts):
    present = {(f["class_name"], f["method_name"], f["jvm_descriptor"]) for f in facts}
    return ([r for r in entries if key(r) in present],
            [r for r in entries if key(r) not in present])


def prepare(jar: Path, api: str, out: Path):
    """Generate the same seed's javap facts, then intersect existing targets exactly."""
    jar = Path(jar).resolve()
    properties = jar.with_name("source.properties").read_text(encoding="utf-8")
    match = re.search(r"^AndroidVersion.ApiLevel=(\d+)\s*$", properties, re.M)
    if not match or match[1] != str(api):
        raise ValueError("android.jar API does not match selected device API")
    facts_by_kind = {}
    for kind, filename in (("privacy", "api_targets.json"), ("consent", "consent_targets.json")):
        seed_path = ROOT / "mobile/rules/seed" / filename
        seed = json.loads(seed_path.read_text(encoding="utf-8"))
        facts, missing = extract(jar, find_javap(None), seed)
        if missing:
            raise ValueError("SDK seed extraction incomplete; refusing to exempt unknown targets: " + repr(missing))
        facts_by_kind[kind] = facts
        (out / (kind + "-sdk-facts.jsonl")).write_text(
            "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in facts), encoding="utf-8")
    original, types, meta = load(ROOT / "mobile/rules/rules_mobile.db")
    original_consent = load_consent(ROOT / "mobile/rules/build/consent_facts.jsonl")
    watch, unsupported = select(original, facts_by_kind["privacy"])
    consent, consent_unsupported = select(original_consent, facts_by_kind["consent"])
    if not watch or not consent:
        raise ValueError("SDK intersection has no usable privacy/consent targets")
    scope = {"device_android_api": str(api), "signature_android_api": match[1],
        "android_jar": str(jar), "android_jar_sha256": hashlib.sha256(jar.read_bytes()).hexdigest(),
        "rules_android_version": meta["android_version"], "rules_sha256": meta["rules_sha256"],
        "scope": "Only exact original target signatures present in this SDK's same-seed javap facts; not a new compliance rules DB.",
        "privacy": {"original": len(original), "selected": len(watch), "unsupported": unsupported},
        "consent": {"original": len(original_consent), "selected": len(consent), "unsupported": consent_unsupported}}
    save(out / "sdk-hook-scope.json", scope)
    scoped_meta = dict(meta, rules_android_version=meta["android_version"], android_version=str(api),
                       signature_android_jar_sha256=scope["android_jar_sha256"])
    return render(watch, types, scoped_meta, consent), scope
