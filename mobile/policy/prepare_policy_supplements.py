"""Archive reviewed one-hop app notices locally, separately from the main policy."""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

try:
    from .policy_fetch import fetch_url
    from .policy_extract import extract
except ImportError:
    from policy_fetch import fetch_url
    from policy_extract import extract

HERE = Path(__file__).resolve().parent


def save(path: Path, value: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_bytes(value)
    temporary.replace(path)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--manifest", type=Path, required=True)
    ap.add_argument("--sources", type=Path, default=HERE / "official_policy_supplements.json")
    ap.add_argument("--store", type=Path, required=True)
    args = ap.parse_args()
    rows = json.loads(args.manifest.read_text(encoding="utf-8"))
    apps = {r["sample_id"]: r for r in rows if r.get("download_status") == "downloaded"}
    sources = json.loads(args.sources.read_text(encoding="utf-8"))["sources"]

    def archive(source: dict) -> dict:
        row = apps[source["sample_id"]]
        digest = hashlib.sha256(source["source"].encode()).hexdigest()[:16]
        folder = args.store / "supplements" / source["sample_id"] / digest
        path = folder / "document.meta.json"
        if path.exists():
            cached = json.loads(path.read_text(encoding="utf-8"))
            if cached.get("status") == "ok":
                raw = (folder / "document.raw").read_bytes()
                text = (folder / "document.txt").read_bytes()
                if (hashlib.sha256(raw).hexdigest() == cached["raw_sha256"] and
                        hashlib.sha256(text).hexdigest() == cached["text_sha256"]):
                    return {**cached, "cache_hit": True}
        fetched = fetch_url(source.get("retrieval_url", source["source"]))
        raw = fetched.pop("bytes", b"")
        result = {**source, "package": row["package"], "version_code": row["version_code"],
            "apk_sha256": row["sha256"], "retrieved_at": datetime.now(timezone.utc).isoformat(),
            "http": fetched, "document_kind": "linked_app_notice",
            "scope_review_required": True, "status": "fetch_failed"}
        if fetched["ok"] and not fetched["truncated"]:
            extracted = extract(raw, content_type=source.get("content_type", "text/html"),
                                source=source["source"])
            text = extracted["text"].encode("utf-8")
            result.update(status=extracted["status"], title=extracted["title"],
                chars=extracted["chars"], raw_sha256=hashlib.sha256(raw).hexdigest(),
                text_sha256=hashlib.sha256(text).hexdigest())
            save(folder / "document.raw", raw)
            save(folder / "document.txt", text)
        result["meta_file"] = str(path.resolve())
        save(path, (json.dumps(result, ensure_ascii=False, indent=2) + "\n").encode())
        return result

    with ThreadPoolExecutor(max_workers=4) as executor:
        results = list(executor.map(archive, sources))
    summary = {"requested": len(results), "extracted": sum(r["status"] == "ok" for r in results),
        "note": "Separate linked notices, not verified complete primary policies or runtime consent evidence.",
        "results": results}
    save(args.store / "supplements.json", (json.dumps(summary, ensure_ascii=False, indent=2) + "\n").encode())
    print(json.dumps({"requested": summary["requested"], "extracted": summary["extracted"]}))
    return 0 if summary["extracted"] == len(results) else 2


if __name__ == "__main__":
    raise SystemExit(main())
