"""Build an inactive draft rules database from explicitly supplied local sources."""
import argparse
import hashlib
import json
import sqlite3
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

from parse_sources import packed, parse_permissions, parse_properties


def insert_rows(db, table, rows):
    if table not in ("permissions", "vhal_properties"):
        raise ValueError("Unsupported destination table")
    for row in rows:
        names = list(row)
        db.execute(f"INSERT INTO {table} ({','.join(names)}) VALUES "
                   f"({','.join('?' for _ in names)})", [row[n] for n in names])


def build(manifest, properties, android_version, revision, output, schema=None):
    if not android_version.strip() or not revision.strip():
        raise ValueError("Android version and source revision must be explicit")
    permissions = parse_permissions(manifest, android_version, revision)
    vhal, diagnostics = parse_properties(properties, android_version, revision)
    output = Path(output)
    summary_path = output.with_suffix(output.suffix + ".summary.json")
    if output.exists() or summary_path.exists():
        raise FileExistsError("Refusing to overwrite an existing database or summary")
    output.parent.mkdir(parents=True, exist_ok=True)
    schema = Path(schema) if schema else Path(__file__).resolve().parents[1] / "schema.sql"
    # Reserve the path exclusively so parallel runs cannot silently replace a database.
    with output.open("xb"):
        pass
    summary_owned = False
    try:
        with sqlite3.connect(output) as db:
            db.executescript(schema.read_text(encoding="utf-8"))
            insert_rows(db, "permissions", permissions)
            insert_rows(db, "vhal_properties", vhal)
            for table in ("permissions", "vhal_properties"):
                for (refs,) in db.execute(f"SELECT source_refs_json FROM {table}"):
                    if not json.loads(refs):
                        raise ValueError("Missing extraction provenance")
            if db.execute("PRAGMA foreign_key_check").fetchall():
                raise ValueError("Foreign key validation failed")
            if db.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                raise ValueError("Database integrity validation failed")
            db.commit()
        db.close()
        summary = {
            "status": "draft_not_for_audit", "android_version": android_version,
            "source_revision_asserted_by_caller": revision,
            "schema_version": 1,
            "counts": {"permissions": len(permissions), "vhal_properties": len(vhal),
                       "dangerous_apis": 0, "risk_rules": 0},
            "unresolved_properties": diagnostics,
            "database_sha256": hashlib.sha256(output.read_bytes()).hexdigest(),
            "limitations": ["No API signatures or risk rules generated",
                            "No device support inferred from source declarations",
                            "Revision label is caller supplied; source hashes are computed"],
        }
        with summary_path.open("x", encoding="utf-8") as handle:
            summary_owned = True
            handle.write(json.dumps(summary, ensure_ascii=False, indent=2) + "\n")
        return summary
    except Exception:
        # Close before cleanup on Windows. Only remove the file reserved by this run.
        if "db" in locals():
            db.close()
        output.unlink(missing_ok=True)
        if summary_owned:
            summary_path.unlink(missing_ok=True)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--properties", type=Path, required=True)
    parser.add_argument("--android-version", required=True)
    parser.add_argument("--source-revision", required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = build(args.manifest, args.properties, args.android_version,
                       args.source_revision, args.out)
        print(packed(result))
    except (ValueError, OSError, sqlite3.Error, SyntaxError, ET.ParseError) as exc:
        print(packed({"status": "failed", "error_type": type(exc).__name__,
                      "message": str(exc)}), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
