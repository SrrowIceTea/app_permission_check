"""Read APK-bound linked notices offline; never replace an application's main policy."""
from __future__ import annotations
from datetime import date
import hashlib
import json
from pathlib import Path
import re

SUPPLEMENTARY_SCOPE = (
    "Independent linked notices apply only to their described function/platform. "
    "They do not establish runtime SDK use, data collection, permission grant or user consent. "
    "They do not replace the main policy or establish a complete policy corpus."
)


def _inside(store: Path, value) -> Path:
    path = (store / value).resolve()
    path.relative_to(store.resolve())
    return path


def load_supporting_documents(store: Path, *, package: str, version_code: str | None,
                              apk_sha256: str | None, primary: dict) -> tuple[list, list]:
    """Return separately cited, digest-checked documents and acquisition/coverage gaps."""
    documents, gaps = [], []
    index = store / "supplements.json"
    if not index.is_file():
        return documents, gaps
    if not version_code or not re.fullmatch(r"[0-9a-f]{64}", apk_sha256 or ""):
        return [], ["Linked notices require exact package, versionCode and complete APK SHA-256 binding"]
    if primary.get("status") == "not_effective":
        return [], ["Linked notices excluded while their primary policy is not yet effective"]
    try:
        rows = json.loads(index.read_text(encoding="utf-8"))["results"]
        if not isinstance(rows, list):
            raise ValueError("results must be a list")
    except (OSError, ValueError, KeyError, TypeError) as error:
        return [], ["Linked-notice catalog invalid: " + str(error)]
    for row in rows:
        if not isinstance(row, dict) or row.get("package") != package:
            continue
        if str(row.get("version_code")) != str(version_code) or row.get("apk_sha256") != apk_sha256:
            gaps.append("Linked notice excluded: versionCode or APK SHA-256 mismatch")
            continue
        if row.get("status") != "ok":
            gaps.append("Linked notice unavailable: " + str(row.get("status")))
            continue
        try:
            meta_file = _inside(store, row["meta_file"])
            meta = json.loads(meta_file.read_text(encoding="utf-8"))
            if not isinstance(meta, dict):
                raise ValueError("linked-notice metadata must be an object")
            for key in ("package", "version_code", "apk_sha256", "source", "raw_sha256", "text_sha256"):
                if str(meta.get(key)) != str(row.get(key)):
                    raise ValueError("catalog/metadata mismatch: " + key)
            if (meta.get("status") != "ok" or meta.get("document_kind") != "linked_app_notice"
                    or meta.get("scope_review_required") is not True or not meta.get("scope")):
                raise ValueError("not an independently scoped extracted app notice")
            if meta.get("effective_date") and date.fromisoformat(meta["effective_date"]) > date.today():
                raise ValueError("linked notice not yet effective")
            if (primary.get("text_sha256") and
                    meta.get("primary_text_sha256") != primary["text_sha256"]):
                raise ValueError("linked primary policy revision differs")
            raw = _inside(store, str(meta_file.parent / "document.raw")).read_bytes()
            text_bytes = _inside(store, str(meta_file.parent / "document.txt")).read_bytes()
            text = text_bytes.decode("utf-8")
            if (hashlib.sha256(raw).hexdigest() != meta["raw_sha256"] or
                    hashlib.sha256(text_bytes).hexdigest() != meta["text_sha256"] or
                    len(text) != meta.get("chars") or not text.strip()):
                raise ValueError("linked-notice content digest or length mismatch")
            source = meta["source"]
            if not isinstance(source, str) or not source:
                raise ValueError("source URL is missing")
            document_id = "SUP-" + hashlib.sha256(source.encode()).hexdigest()[:16]
            if any(d["document_id"] == document_id for d in documents):
                raise ValueError("duplicate linked-notice source")
            keys = ("package", "version_code", "apk_sha256", "source", "discovered_from",
                    "primary_text_sha256", "raw_sha256", "text_sha256", "retrieved_at",
                    "effective_date", "title", "scope", "scope_review_required", "document_kind")
            documents.append({**{key: meta.get(key) for key in keys}, "document_id": document_id,
                              "available": True, "status": "ok", "text": text,
                              "chars": len(text), "association_verified": True,
                              "supplementary_scope": "document_scope_only"})
        except (OSError, ValueError, KeyError, TypeError) as error:
            gaps.append("Linked notice excluded: " + str(error))
    return documents, list(dict.fromkeys(gaps))
