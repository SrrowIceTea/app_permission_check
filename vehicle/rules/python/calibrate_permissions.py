"""Compare saved pm output to a draft database. Never invoke adb or modify rules.db."""
import argparse
import hashlib
import json
import re
import sqlite3
import sys
from pathlib import Path


def compare(database, pm_output, android_version, coverage):
    text = Path(pm_output).read_text(encoding="utf-8-sig")
    observed = set(re.findall(r"^\s*permission:\s*(android\.car\.[\w.]+)\s*$",
                              text, flags=re.M))
    if not observed:
        raise ValueError("No car permission names parsed; verify saved output format")
    if coverage not in ("full", "filtered"):
        raise ValueError("Coverage must be full or filtered")
    uri = Path(database).resolve().as_uri() + "?mode=ro"
    db = sqlite3.connect(uri, uri=True)
    try:
        declared = {row[0] for row in db.execute(
            "SELECT permission_name FROM permissions WHERE android_version = ?",
            (android_version,))}
    finally:
        db.close()
    if not declared:
        raise ValueError("No source permissions for the requested Android version")
    return {
        "status": "comparison_only", "android_version": android_version,
        "coverage": coverage,
        "database_sha256": hashlib.sha256(Path(database).read_bytes()).hexdigest(),
        "pm_output_sha256": hashlib.sha256(Path(pm_output).read_bytes()).hexdigest(),
        "observed_and_declared": sorted(observed & declared),
        "observed_only": sorted(observed - declared),
        "source_only_not_observed": sorted(declared - observed),
        "interpretation": "Not observed is not proof of absence. Filtered output cannot "
                          "establish completeness. No protection levels inferred.",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", type=Path, required=True)
    parser.add_argument("--pm-output", type=Path, required=True)
    parser.add_argument("--android-version", required=True)
    parser.add_argument("--coverage", choices=("full", "filtered"), required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = compare(args.db, args.pm_output, args.android_version, args.coverage)
        args.out.parent.mkdir(parents=True, exist_ok=True)
        with args.out.open("x", encoding="utf-8") as handle:
            handle.write(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
        print(json.dumps(result, ensure_ascii=False))
    except (ValueError, OSError, sqlite3.Error) as exc:
        print(json.dumps({"status": "failed", "error_type": type(exc).__name__,
                          "message": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
