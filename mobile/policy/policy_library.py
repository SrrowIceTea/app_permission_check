"""Local-first, package-bound policy snapshots. No network access in resolution."""
from __future__ import annotations

import hashlib
import json
import re
from datetime import date, datetime, timezone
from pathlib import Path

try:
    from . import policy_extract
except ImportError:
    import policy_extract

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_STORE = ROOT / "output" / "local-policy-library-20261018"


def _digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _write(path: Path, raw: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_bytes(raw)
    temporary.replace(path)


def _json(path: Path, obj: dict) -> None:
    _write(path, (json.dumps(obj, ensure_ascii=False, indent=2) + "\n").encode("utf-8"))


def _inside(store: Path, value: str) -> Path:
    path = (store / value).resolve()
    path.relative_to(store.resolve())
    return path


def register_policy(store: Path, *, raw: bytes, package: str, version_code: str,
                    apk_sha256: str, source: str, source_kind: str,
                    content_type: str = "text/plain", source_version: str | None = None,
                    applicability: str = "current_official_snapshot",
                    document_kind: str = "app_policy", notes: list[str] | None = None,
                    effective_date: str | None = None, retrieval_url: str | None = None) -> dict:
    """Explicitly register a confirmed app policy, not arbitrary keyword candidates.

    The association records the APK under test; only release_tag/apk_asset confirms
    source-version correspondence. Online current snapshots keep that limitation.
    """
    if not re.fullmatch(r"[A-Za-z0-9_.]+", package) or not version_code:
        raise ValueError("A package and version_code are required")
    if not re.fullmatch(r"[0-9a-f]{64}", apk_sha256):
        raise ValueError("A complete APK sha256 is required")
    if document_kind != "app_policy":
        raise ValueError("Only confirmed app policies belong in this library")
    if effective_date:
        date.fromisoformat(effective_date)
    ex = policy_extract.extract(raw, content_type=content_type, source=source)
    if ex["status"] != "ok":
        raise ValueError(f"Policy extraction is not usable: {ex['status']}")
    stamp = datetime.now(timezone.utc).isoformat()
    identifier = f"{package}-{version_code}-{apk_sha256[:12]}-{_digest(raw)[:16]}"
    folder = store / identifier
    raw_file = "policy-local.raw"
    text_file = "policy-local.txt"
    record = {"package": package, "version_code": str(version_code),
              "apk_sha256": apk_sha256, "source": source, "source_kind": source_kind,
              "document_kind": document_kind, "applicability": applicability,
              "source_version": source_version, "retrieved_at": stamp, "saved_at": stamp,
              "raw_sha256": _digest(raw), "text_sha256": _digest(ex["text"].encode("utf-8")),
              "extract_status": ex["status"], "extract_path": ex["path"],
              "text_chars": ex["chars"], "cjk_ratio": ex["cjk_ratio"],
              "title": ex["title"], "raw_file": raw_file, "text_file": text_file,
              "notes": notes or [], "effective_date": effective_date,
              "retrieval_url": retrieval_url or source}
    _write(folder / raw_file, raw)
    _write(folder / text_file, ex["text"].encode("utf-8"))
    _json(folder / "policy-local.meta.json", record)
    catalog_path = store / "catalog.json"
    catalog = json.loads(catalog_path.read_text(encoding="utf-8")) if catalog_path.exists() else {
        "schema_version": 1, "document_kind": "app_policy_library", "entries": []}
    relative = (folder / "policy-local.meta.json").relative_to(store).as_posix()
    catalog["entries"] = [e for e in catalog["entries"] if e.get("meta_file") != relative]
    catalog["entries"].append({"package": package, "version_code": str(version_code),
                               "apk_sha256": apk_sha256, "meta_file": relative})
    catalog["updated_at"] = stamp
    _json(catalog_path, catalog)
    return record


def _read_record(store: Path, meta_path: Path, *, package: str,
                 version_code: str | None, apk_sha256: str | None,
                 allow_legacy: bool) -> dict:
    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    legacy = not meta.get("package")
    if legacy and not allow_legacy:
        raise ValueError("metadata has no package binding")
    if not legacy and meta.get("package") != package:
        raise ValueError("package mismatch")
    if not legacy and meta.get("document_kind") != "app_policy":
        raise ValueError("not an application privacy policy")
    if not legacy:
        same_apk = bool(apk_sha256 and meta.get("apk_sha256") == apk_sha256)
        same_version = bool(version_code and str(meta.get("version_code")) == str(version_code))
        if version_code and meta.get("version_code") and not same_version:
            raise ValueError("version_code mismatch")
        if apk_sha256 and meta.get("apk_sha256") and not same_apk:
            raise ValueError("APK hash mismatch")
        if not same_apk and not same_version:
            raise ValueError("version association missing or mismatched")
    if meta.get("extract_status") != "ok":
        raise ValueError("unusable policy extraction")
    local = meta_path.parent
    raw_path = _inside(local, meta["raw_file"])
    text_path = _inside(local, meta["text_file"])
    raw, text_bytes = raw_path.read_bytes(), text_path.read_bytes()
    if _digest(raw) != meta.get("raw_sha256") or _digest(text_bytes) != meta.get("text_sha256"):
        raise ValueError("policy snapshot digest mismatch")
    text = text_bytes.decode("utf-8")
    if len(text) < policy_extract.MIN_USEFUL_CHARS:
        raise ValueError("policy text is too short")
    if meta.get("effective_date") and date.fromisoformat(meta["effective_date"]) > date.today():
        return {**meta, "available": False, "status": "not_effective",
                "chars": len(text), "meta_file": str(meta_path), "store": str(store),
                "gaps": [f"Official policy is published but not effective until {meta['effective_date']}"]}
    gaps = []
    if legacy:
        gaps.append("Legacy explicitly supplied policy: package/version association not verified")
    elif meta.get("applicability") not in ("release_tag", "apk_asset"):
        gaps.append("Current official policy snapshot; correspondence to the APK release date is unverified")
    return {**meta, "available": True, "status": "ok", "text": text,
            "chars": len(text), "meta_file": str(meta_path), "store": str(store),
            "association_verified": not legacy, "gaps": gaps}


def _load_primary_policy(store: Path | None = None, *, package: str,
                version_code: str | None = None, apk_sha256: str | None = None,
                allow_legacy: bool = False) -> dict:
    """Resolve without network or filename-last-wins; a bad match never becomes empty text."""
    store = Path(store or DEFAULT_STORE).resolve()
    missing = {"available": False, "status": "not_found", "gaps": []}
    if not store.is_dir():
        return {**missing, "gaps": ["No local application policy library supplied or present"]}
    errors, candidates = [], []
    catalog_path = store / "catalog.json"
    try:
        if catalog_path.exists():
            catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
            entries = [e for e in catalog["entries"] if e.get("package") == package]
            entries.sort(key=lambda e: e.get("apk_sha256") == apk_sha256, reverse=True)
            paths = [_inside(store, e["meta_file"]) for e in entries]
        else:
            paths = sorted(store.glob("policy-*.meta.json"))
        for path in paths:
            try:
                candidates.append(_read_record(store, path, package=package,
                    version_code=version_code, apk_sha256=apk_sha256, allow_legacy=allow_legacy))
            except (OSError, ValueError, KeyError, TypeError) as exc:
                errors.append(f"{path.name}: {exc}")
    except (OSError, ValueError, KeyError, TypeError) as exc:
        errors.append(f"Invalid local policy catalog: {exc}")
    if not candidates:
        return {**missing, "status": "invalid" if errors else "not_found", "gaps": errors or [
            f"No matching local policy for {package} / version {version_code}"]}
    # Ambiguous revisions require explicit snapshot selection, never an arbitrary last file.
    active = [c for c in candidates if c["available"]]
    if not active:
        return candidates[0]
    if len({c["text_sha256"] for c in active}) > 1:
        return {**missing, "status": "ambiguous", "gaps": ["Multiple matching policy revisions"]}
    return active[0]


def load_policy(store: Path | None = None, *, package: str,
                version_code: str | None = None, apk_sha256: str | None = None,
                allow_legacy: bool = False) -> dict:
    """Keep the primary snapshot intact and attach independently scoped local notices."""
    try:
        from .policy_supplements import load_supporting_documents, SUPPLEMENTARY_SCOPE
    except ImportError:
        from policy_supplements import load_supporting_documents, SUPPLEMENTARY_SCOPE
    store = Path(store or DEFAULT_STORE).resolve()
    policy = _load_primary_policy(store, package=package, version_code=version_code,
                                  apk_sha256=apk_sha256, allow_legacy=allow_legacy)
    documents, gaps = load_supporting_documents(store, package=package, version_code=version_code,
                                               apk_sha256=apk_sha256, primary=policy)
    return {**policy, "supporting_documents": documents, "supplementary_scope": SUPPLEMENTARY_SCOPE,
            "gaps": list(dict.fromkeys([*(policy.get("gaps") or []), *gaps]))}
