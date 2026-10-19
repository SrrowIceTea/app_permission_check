"""Collect explicitly reviewed official policies once; detector then reads local files."""
from __future__ import annotations
import argparse
import json
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from policy_fetch import fetch_url
from policy_library import register_policy, load_policy

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--manifest", type=Path, required=True)
    ap.add_argument("--sources", type=Path, default=HERE / "official_policy_sources.json")
    ap.add_argument("--store", type=Path, required=True)
    args = ap.parse_args()
    rows = json.loads(args.manifest.read_text(encoding="utf-8"))
    by_id = {r["sample_id"]: r for r in rows if r.get("download_status") == "downloaded"}
    source_config = json.loads(args.sources.read_text(encoding="utf-8"))
    sources = source_config["sources"]
    results = []
    for source in sources:
        row = by_id.get(source["sample_id"])
        if not row:
            continue
        result = {"sample_id": row["sample_id"], "package": row["package"],
                  "version_code": row["version_code"], "source": source["source"]}
        try:
            want_agreement = source.get("document_kind", "app_policy") == "app_agreement"
            cached = load_policy(args.store, package=row["package"],
                version_code=str(row["version_code"]), apk_sha256=row["sha256"])
            # 协议的"已存在"要看 app_agreements：主政策可用不代表这份协议已经收过。
            if want_agreement:
                already = any(a.get("source") == source["source"]
                              for a in cached.get("app_agreements") or [])
            else:
                already = cached["available"] or cached["status"] == "not_effective"
            if already:
                result.update(status="ok" if want_agreement else cached["status"],
                    cache_hit=True,
                    text_chars=(cached.get("chars") if not want_agreement
                                else len(cached["app_agreements"][0]["text"])),
                    text_sha256=(cached.get("text_sha256") if not want_agreement else
                                 next(a["text_sha256"] for a in cached["app_agreements"]
                                      if a.get("source") == source["source"])),
                    gaps=cached["gaps"])
                results.append(result)
                print(json.dumps(result, ensure_ascii=False), flush=True)
                continue
            if source.get("apk_entry"):
                with zipfile.ZipFile(row["apk_path"]) as apk:
                    raw = apk.read(source["apk_entry"])
                kind = "apk_asset"
            else:
                fetched = fetch_url(source.get("retrieval_url", source["source"]))
                if not fetched["ok"] or fetched["truncated"]:
                    raise ValueError(f"Fetch failed/truncated: {fetched['error']}")
                raw = fetched["bytes"]
                kind = "official_url"
            meta = register_policy(args.store, raw=raw, package=row["package"],
                version_code=str(row["version_code"]), apk_sha256=row["sha256"],
                source=source["source"], source_kind=kind,
                content_type=source.get("content_type", "text/plain"),
                source_version=source.get("source_version"),
                applicability=source.get("applicability", "current_official_snapshot"),
                # app_agreement：用户协议/服务协议，独立引用，不替代主政策（默认 app_policy）
                document_kind=source.get("document_kind", "app_policy"),
                notes=source.get("notes"), effective_date=source.get("effective_date"),
                retrieval_url=source.get("retrieval_url"))
            loaded = load_policy(args.store, package=row["package"],
                version_code=str(row["version_code"]), apk_sha256=row["sha256"])
            status = loaded["status"]
            if want_agreement:
                # 协议登记成功与否只看 app_agreements，不能拿主政策状态冒充。
                status = ("ok" if any(a.get("text_sha256") == meta["text_sha256"]
                                      for a in loaded.get("app_agreements") or [])
                          else "agreement_not_registered")
            result.update(status=status, text_chars=meta["text_chars"],
                          text_sha256=meta["text_sha256"], gaps=loaded["gaps"])
        except (OSError, ValueError, KeyError, zipfile.BadZipFile) as exc:
            result.update(status="failed", error=str(exc))
        results.append(result)
        print(json.dumps(result, ensure_ascii=False), flush=True)
    summary = {"retrieved_at": datetime.now(timezone.utc).isoformat(),
               "manifest": str(args.manifest.resolve()), "results": results,
               "available": sum(r["status"] == "ok" for r in results),
               "requested": len(sources)}
    args.store.mkdir(parents=True, exist_ok=True)
    target = args.store / "preparation.json"
    temporary = target.with_suffix(".tmp")
    temporary.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temporary.replace(target)
    unavailable = {r["sample_id"]: r for r in source_config.get("unavailable_sources", [])}
    coverage_rows = []
    for row in by_id.values():
        policy = load_policy(args.store, package=row["package"],
            version_code=str(row["version_code"]), apk_sha256=row["sha256"])
        coverage_rows.append({"sample_id": row["sample_id"], "package": row["package"],
            "version_code": row["version_code"], "policy_status": policy["status"],
            "available": policy["available"], "applicability": policy.get("applicability"),
            "source": policy.get("source"), "chars": policy.get("chars"),
            "effective_date": policy.get("effective_date"), "gaps": policy["gaps"],
            "notes": policy.get("notes"), "acquisition_check": unavailable.get(row["sample_id"])})
    coverage = {"apps": len(coverage_rows), "available": sum(r["available"] for r in coverage_rows),
        "missing": sum(not r["available"] for r in coverage_rows),
        "not_effective": sum(r["policy_status"] == "not_effective" for r in coverage_rows),
        "not_found": sum(r["policy_status"] == "not_found" for r in coverage_rows),
        "checked_at": datetime.now(timezone.utc).isoformat(), "results": coverage_rows}
    target = args.store / "coverage.json"
    temporary = target.with_suffix(".tmp")
    temporary.write_text(json.dumps(coverage, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temporary.replace(target)
    return 0 if results and all(r["status"] == "ok" for r in results) else 2


if __name__ == "__main__":
    raise SystemExit(main())
