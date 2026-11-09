#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Insert an extra source-verified baseline (android-13 / android-16) into the library.

The rows come from `baseline_androidXX/`, produced by `extract_seed.py` and sealed
by `sources.lock.json`. `build_seed.load_records` re-verifies the lock digests,
every source reference and the evidence locators before anything is inserted, so a
tampered or stale seed directory fails closed instead of entering the library.

Order matters: risk_rules carries foreign keys into the three tables above.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path

from build_seed import load_records

TABLE_ORDER = ("permissions", "vhal_properties", "dangerous_apis", "risk_rules")


def insert_source_rows(dst: sqlite3.Connection, seed_dir: Path) -> dict:
    """Insert one source baseline; return per-table row counts."""
    records = load_records(seed_dir)
    version = records[0]["row"]["android_version"]
    counts = {}
    for table in TABLE_ORDER:
        rows = [record["row"] for record in records if record["table"] == table]
        if any(row["android_version"] != version for row in rows):
            raise ValueError("Mixed source baseline versions")
        schema_columns = {r[1] for r in dst.execute(f"PRAGMA table_info({table})")}
        extra = set().union(*(set(row) for row in rows)) - schema_columns
        if extra:
            raise ValueError("Unknown columns in " + table + ": " + ", ".join(sorted(extra)))
        for row in rows:
            # Insert only the columns the seed row carries, exactly like build_seed:
            # omitted NOT NULL columns then take their schema default ('[]' / NULL).
            names = list(row)
            dst.execute(
                f"INSERT INTO {table} ({','.join(names)}) VALUES ({','.join('?' * len(names))})",
                [row[name] for name in names],
            )
        counts[table] = len(rows)
    return counts
