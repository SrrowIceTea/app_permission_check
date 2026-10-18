"""Bind AI legal references to the existing, offline, versioned source excerpts."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path

REGULATIONS = Path(__file__).resolve().parents[1] / "rules" / "regulations"


def _excerpt(doc: dict, clause: str):
    if doc["id"] == "yrd-method-2019":
        for category in doc.get("categories", []):
            for item in category["items"]:
                if clause == f"{category['key']}.{item['no']}":
                    return item["text"]
    if doc["id"] == "pipl-2021":
        return next((a["text"] for a in doc["articles"] if str(a["no"]) == clause), None)
    if doc["id"] == "gbt35273-2020" and clause == "3.2":
        return doc["definition_3_2"]["text"]
    if doc["id"] == "necessary-info-2021" and clause == "5":
        # Source is explicitly a structured transcription, not an invented full article.
        return json.dumps(doc["categories"], ensure_ascii=False)
    return None


def bind_regulations(refs: list[dict], directory: Path = REGULATIONS) -> tuple[list, dict]:
    documents = {}
    for path in sorted(directory.glob("*.json")):
        raw = path.read_bytes()
        document = json.loads(raw)
        documents[document["id"]] = (path.name, document, hashlib.sha256(raw).hexdigest())
    bound = []
    for ref in refs:
        item = dict(ref)
        source = documents.get(item["doc"])
        text = _excerpt(source[1], str(item["clause"])) if source else None
        item.update({"text": text, "text_available": bool(text)})
        if source:
            name, document, sha = source
            item.update({"source_file": name, "source_sha256": sha,
                         "source_urls": document.get("urls", []),
                         "source_verification": document.get("verification", {})})
        bound.append(item)
    scope = {"mode": "offline_local_excerpts", "complete_legal_corpus": False,
             "documents": [{"id": doc, "file": source[0], "sha256": source[2],
                             "verification": source[1].get("verification", {})}
                            for doc, source in documents.items()],
             "missing_references": [f"{r['doc']}:{r['clause']}" for r in bound
                                    if not r["text_available"]]}
    return bound, scope


def load_bound_policy(store: Path | None, app: dict, rules_db: Path, version: str,
                      *, allow_legacy: bool = False) -> dict:
    from mobile.policy.policy_library import load_policy
    from mobile.policy import policy_lint
    policy = load_policy(store, package=app["package"], version_code=app.get("version_code"),
                         apk_sha256=app.get("apk_sha256"), allow_legacy=allow_legacy)
    if policy.get("available"):
        text = policy["text"]
        policy["lint"] = policy_lint.lint(text, policy_lint.load_requirements(rules_db, version),
                                           policy.get("cjk_ratio") or 0.0)
        policy["disclosure_scan"] = policy_lint.disclosure_scan(text, policy_lint.load_keywords())
    return policy
