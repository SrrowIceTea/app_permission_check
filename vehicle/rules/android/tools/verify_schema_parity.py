#!/usr/bin/env python3
"""Compare the three descriptions of the rule-library schema.

1. schema.sql            - the hand-written contract
2. baseline rules.db     - what actually ships in assets/
3. Room's exported 1.json - what Room expects to find when it opens that file

Room validates (2) against (3) at runtime, but it compares only columns,
indices and foreign keys. CHECK constraints, index *names* and primary-key
ordering are invisible to it, yet the project's integrity claims rest on them —
this script is what covers those.  Usage: --json-only skips the schema.sql pass;
exit code is non-zero when any comparison fails.
"""
from __future__ import annotations

import argparse
import json
import re
import sqlite3
import sys
from pathlib import Path

ANDROID_DIR = Path(__file__).resolve().parents[1]
PHASE1_DIR = ANDROID_DIR.parent
SCHEMA_SQL = PHASE1_DIR / "schema.sql"
# The database the app actually ships, not the android-14 baseline it was built from.
# Those are different files now: the shipped one also carries the android-15 rows.
RULES_DB = ANDROID_DIR / "app" / "src" / "main" / "assets" / "rules.db"
ROOM_JSON = ANDROID_DIR / "app" / "schemas" / "com.vscanner.rules.RulesDatabase" / "1.json"

# Room's createSql never carries CHECK clauses; SQLite's sqlite_master does.
CHECK_RE = re.compile(r",?\s*CHECK\s*\([^)]*\)", re.IGNORECASE | re.DOTALL)
WS_RE = re.compile(r"\s+")


def normalize_sql(sql: str) -> str:
    """Whitespace-collapsed, case-folded, CHECK-free, semicolon-free, IF NOT EXISTS-free."""
    if sql is None:
        return ""
    out = CHECK_RE.sub("", sql)
    out = re.sub(r"\bIF\s+NOT\s+EXISTS\b", "", out, flags=re.IGNORECASE)
    out = WS_RE.sub(" ", out).strip().rstrip(";").strip()
    out = out.replace(" (", "(").replace("( ", "(").replace(" )", ")")
    return out.lower()


def affinity(declared: str) -> str:
    """SQLite type affinity, per the documented substring rules."""
    t = (declared or "").upper()
    if "INT" in t:
        return "INTEGER"
    if "CHAR" in t or "CLOB" in t or "TEXT" in t:
        return "TEXT"
    if "BLOB" in t or not t:
        return "BLOB"
    if "REAL" in t or "FLOA" in t or "DOUB" in t:
        return "REAL"
    return "NUMERIC"


def snapshot(conn: sqlite3.Connection) -> dict:
    """Everything about a database that the contract cares about."""
    conn.row_factory = sqlite3.Row
    snap: dict = {"tables": {}, "indices": {}, "user_version": conn.execute("PRAGMA user_version").fetchone()[0]}

    for row in conn.execute(
        "SELECT type, name, tbl_name, sql FROM sqlite_master "
        "WHERE type IN ('table','index') AND name NOT LIKE 'sqlite_%' ORDER BY name"
    ):
        entry = {"sql": normalize_sql(row["sql"]), "tbl_name": row["tbl_name"]}
        (snap["tables"] if row["type"] == "table" else snap["indices"])[row["name"]] = entry

    for table in snap["tables"]:
        snap["tables"][table]["columns"] = [
            {
                "name": r["name"],
                "type": r["type"],
                "affinity": affinity(r["type"]),
                "notnull": bool(r["notnull"]),
                "dflt_value": r["dflt_value"],
                "pk": r["pk"],
            }
            for r in conn.execute(f'PRAGMA table_info("{table}")')
        ]
        snap["tables"][table]["foreign_keys"] = [
            {
                "id": r["id"],
                # seq orders the columns *within* one composite foreign key.
                "seq": r["seq"],
                "table": r["table"],
                "from": r["from"],
                "to": r["to"],
                "on_delete": r["on_delete"],
                "on_update": r["on_update"],
            }
            for r in conn.execute(f'PRAGMA foreign_key_list("{table}")')
        ]
        pk_columns = sorted(
            (c for c in snap["tables"][table]["columns"] if c["pk"] > 0),
            key=lambda c: c["pk"],
        )
        snap["tables"][table]["primary_key"] = tuple(c["name"] for c in pk_columns)

    for index in snap["indices"]:
        # cid is the *table* column ordinal and is NOT in index order. seqno is.
        snap["indices"][index]["columns"] = [
            r["name"]
            for r in sorted(
                conn.execute(f'PRAGMA index_xinfo("{index}")'),
                key=lambda r: r["seqno"],
            )
            if r["cid"] >= 0 and r["name"] is not None
        ]
        snap["indices"][index]["unique"] = bool(
            conn.execute(
                "SELECT \"unique\" FROM pragma_index_list(?) WHERE name = ?", (snap["indices"][index]["tbl_name"], index)
            ).fetchone()[0]
        )
    return snap


class Diff:
    def __init__(self) -> None:
        self.problems: list[str] = []

    def check(self, ok: bool, message: str) -> None:
        if not ok:
            self.problems.append(message)


def compare_databases(diff: Diff, expected: dict, actual: dict) -> None:
    diff.check(
        expected["user_version"] == actual["user_version"],
        f"user_version: schema.sql={expected['user_version']} rules.db={actual['user_version']}",
    )
    for kind in ("tables", "indices"):
        missing = set(expected[kind]) - set(actual[kind])
        extra = set(actual[kind]) - set(expected[kind])
        diff.check(not missing, f"{kind} present in schema.sql but not in rules.db: {sorted(missing)}")
        diff.check(not extra, f"{kind} present in rules.db but not in schema.sql: {sorted(extra)}")
        for name in sorted(set(expected[kind]) & set(actual[kind])):
            diff.check(
                expected[kind][name]["sql"] == actual[kind][name]["sql"],
                f"{kind[:-1]} DDL differs: {name}\n    schema.sql: {expected[kind][name]['sql']}\n    rules.db  : {actual[kind][name]['sql']}",
            )
            for key in ("columns", "foreign_keys", "unique", "primary_key"):
                if key in expected[kind][name] or key in actual[kind][name]:
                    diff.check(
                        expected[kind][name].get(key) == actual[kind][name].get(key),
                        f"{kind[:-1]} {name} {key} differs:\n    schema.sql: {expected[kind][name].get(key)}\n    rules.db  : {actual[kind][name].get(key)}",
                    )


def compare_room_json(diff: Diff, db: dict, room: dict) -> None:
    """Room's expectations vs what the packaged file actually contains."""
    if "database" not in room or "entities" not in room["database"]:
        raise KeyError(
            "Room schema JSON has an unexpected shape. Top-level keys: "
            f"{sorted(room)}; database keys: {sorted(room.get('database', {}))}"
        )
    entities = room["database"]["entities"]
    db_tables = set(db["tables"])
    json_tables = {e.get("tableName") for e in entities}
    diff.check(json_tables == db_tables, f"table sets differ: room={sorted(json_tables)} db={sorted(db_tables)}")

    for entity in entities:
        table = entity.get("tableName")
        if table not in db_tables:
            continue
        for key in ("fields", "createSql"):
            if key not in entity:
                raise KeyError(f"entity {table} is missing '{key}'. Keys found: {sorted(entity)}")

        actual_cols = {c["name"]: c for c in db["tables"][table]["columns"]}
        for field in entity["fields"]:
            column = field.get("columnName")
            if column not in actual_cols:
                diff.check(False, f"{table}.{column}: expected by Room but absent from rules.db")
                continue
            got = actual_cols[column]
            diff.check(
                bool(field.get("notNull", False)) == got["notnull"],
                f"{table}.{column} notNull: room={field.get('notNull')} db={got['notnull']}",
            )
            want_aff = (field.get("affinity") or "TEXT").upper()
            diff.check(
                want_aff == got["affinity"],
                f"{table}.{column} affinity: room={want_aff} db={got['affinity']} (declared {got['type']!r})",
            )
            # Room writes "undefined" for "no default"; SQLite writes NULL.
            want_default = field.get("defaultValue")
            want_default = None if want_default in (None, "undefined") else want_default
            diff.check(
                normalize_sql(str(want_default)) == normalize_sql(str(got["dflt_value"])),
                f"{table}.{column} default: room={want_default!r} db={got['dflt_value']!r}",
            )
        # Composite primary key ORDER. Room's runtime check reduces a primary key
        # to a set of booleans per column and cannot see the ordering at all, so a
        # reordered primaryKeys = [...] in an entity would slip past it. Here it
        # cannot: the exported columnNames list is ordered.
        if "primaryKey" in entity:
            room_pk = tuple(entity["primaryKey"].get("columnNames", []))
            diff.check(
                room_pk == db["tables"][table]["primary_key"],
                f"{table} primary key order: room={room_pk} db={db['tables'][table]['primary_key']}",
            )

        for index in entity.get("indices", []):
            name = index.get("name")
            if name not in db["indices"]:
                diff.check(False, f"{table}: index {name} expected by Room but absent from rules.db")
                continue
            got_index = db["indices"][name]
            diff.check(
                bool(index.get("unique", False)) == got_index["unique"],
                f"index {name} unique: room={index.get('unique')} db={got_index['unique']}",
            )
            diff.check(
                list(index.get("columnNames", [])) == got_index["columns"],
                f"index {name} columns: room={index.get('columnNames')} db={got_index['columns']}",
            )

        room_fks = set()
        for fk in entity.get("foreignKeys", []):
            for key in ("table", "columns", "referencedColumns"):
                if key not in fk:
                    raise KeyError(f"{table} foreignKey is missing '{key}'. Keys found: {sorted(fk)}")
            room_fks.add((
                fk["table"],
                tuple(fk["columns"]),
                tuple(fk["referencedColumns"]),
                fk.get("onDelete", "NO ACTION"),
                fk.get("onUpdate", "NO ACTION"),
            ))

        grouped: dict = {}
        for row in db["tables"][table]["foreign_keys"]:
            grouped.setdefault(row["id"], []).append(row)
        db_fks = set()
        for rows in grouped.values():
            rows = sorted(rows, key=lambda r: r["seq"])
            db_fks.add((
                rows[0]["table"],
                tuple(r["from"] for r in rows),
                tuple(r["to"] for r in rows),
                rows[0]["on_delete"],
                rows[0]["on_update"],
            ))

        diff.check(room_fks == db_fks, f"{table} foreign keys differ:\n    room: {sorted(room_fks)}\n    db  : {sorted(db_fks)}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json-only", action="store_true", help="skip the schema.sql vs rules.db pass")
    args = parser.parse_args()

    for required in (SCHEMA_SQL, RULES_DB):
        if not required.exists():
            print(f"MISSING required input: {required}", file=sys.stderr)
            return 2

    diff = Diff()

    expected_conn = sqlite3.connect(":memory:")
    expected_conn.executescript(SCHEMA_SQL.read_text(encoding="utf-8"))
    expected = snapshot(expected_conn)
    expected_conn.close()

    actual_conn = sqlite3.connect(f"file:{RULES_DB.as_posix()}?mode=ro", uri=True)
    actual = snapshot(actual_conn)
    actual_conn.close()

    if not args.json_only:
        compare_databases(diff, expected, actual)
        print(f"schema.sql vs rules.db : {len(expected['tables'])} tables, {len(expected['indices'])} indices compared")

    if ROOM_JSON.exists():
        compare_room_json(diff, actual, json.loads(ROOM_JSON.read_text(encoding="utf-8")))
        print(f"Room 1.json vs rules.db: {ROOM_JSON.relative_to(PHASE1_DIR)} compared")
    else:
        print(f"Room schema JSON not built yet ({ROOM_JSON.relative_to(PHASE1_DIR)}).\n"
              "Run ./gradlew :app:kspDebugKotlin (or assembleDebug) first, then re-run.",
              file=sys.stderr)

    if diff.problems:
        print(f"\nFAILED: {len(diff.problems)} difference(s)", file=sys.stderr)
        for problem in diff.problems:
            print(f"  - {problem}", file=sys.stderr)
        return 1

    print("\nPASS: no differences")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
