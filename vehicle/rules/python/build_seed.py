"""Offline reproducible seed database builder/verifier. All audit rules stay disabled."""
import argparse
import hashlib
import json
import sqlite3
import sys
from pathlib import Path
from seed_policy import draft_rules

TABLES = ('permissions', 'vhal_properties', 'dangerous_apis', 'risk_rules')


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def load_records(directory):
    directory = Path(directory)
    lock = json.loads((directory / 'sources.lock.json').read_text(encoding='utf-8'))
    for name, digest in lock['artifacts'].items():
        if sha(directory / name) != digest:
            raise ValueError('Packaged artifact digest mismatch: ' + name)
    facts = [json.loads(line) for line in (directory / 'seed_facts.jsonl').read_text(encoding='utf-8').splitlines()]
    records = facts + draft_rules(facts, directory / 'POLICY.md')
    evidence = {r['evidence_id']: r for r in map(json.loads,
        (directory / 'seed_evidence.jsonl').read_text(encoding='utf-8').splitlines())}
    sources = {entry['id']: entry for entry in lock['files']}
    for record in records:
        if record['table'] not in TABLES:
            raise ValueError('Unknown table')
        row = record['row']
        if row['android_version'] != lock['android_version']:
            raise ValueError('Mixed source baseline versions')
        refs = json.loads(row['source_refs_json'])
        if not refs:
            raise ValueError('Missing source references')
        for ref in refs:
            entry = sources[ref['id']]
            for key in ('path', 'commit', 'url', 'sha256', 'git_blob_sha1'):
                if ref[key] != entry[key]:
                    raise ValueError('Source lock mismatch: ' + key)
            excerpt = evidence[ref['evidence_id']]
            if (excerpt['source_id'], excerpt['line'], excerpt['end_line']) != (
                    ref['id'], ref['line'], ref['end_line']):
                raise ValueError('Evidence locator mismatch')
        for key, value in row.items():
            if key.endswith('_json') and value is not None:
                json.loads(value)
    permissions = {r['row']['permission_name'] for r in records if r['table'] == 'permissions'}
    for record in facts:
        row = record['row']
        if record['table'] == 'vhal_properties':
            if json.loads(row['read_permission_expr_json'])['name'] not in permissions:
                raise ValueError('Unresolved permission reference')
    if any(r['row']['enabled'] != 0 for r in records if r['table'] == 'risk_rules'):
        raise ValueError('Draft seed rules cannot be enabled')
    return records


def inspect(database, expected=None):
    db = sqlite3.connect(Path(database).resolve().as_uri() + '?mode=ro', uri=True)
    try:
        if db.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
            raise ValueError('Integrity check failed')
        if db.execute('PRAGMA foreign_key_check').fetchall():
            raise ValueError('Foreign key check failed')
        if db.execute('PRAGMA user_version').fetchone()[0] != 1:
            raise ValueError('Schema version mismatch')
        counts = {table: db.execute(f'SELECT COUNT(*) FROM {table}').fetchone()[0] for table in TABLES}
        active = db.execute('SELECT COUNT(*) FROM risk_rules WHERE enabled <> 0').fetchone()[0]
        if active:
            raise ValueError('Unexpected enabled rule')
        if expected is not None:
            reference = sqlite3.connect(':memory:')
            reference.row_factory = sqlite3.Row
            reference.executescript((Path(__file__).resolve().parents[1] / 'schema.sql').read_text(encoding='utf-8'))
            for record in expected:
                names, row = list(record['row']), record['row']
                reference.execute(f"INSERT INTO {record['table']} ({','.join(names)}) VALUES ({','.join('?' for _ in names)})",
                                  [row[name] for name in names])
            for table in TABLES:
                wanted = [dict(r) for r in reference.execute(f'SELECT * FROM {table}')]
                if counts[table] != len(wanted):
                    raise ValueError('Unexpected row count: ' + table)
                db.row_factory = sqlite3.Row
                actual = [dict(r) for r in db.execute(f'SELECT * FROM {table}')]
                for row in wanted:
                    if row not in actual:
                        raise ValueError('Seed content mismatch in ' + table)
            reference.close()
        return {'status': 'reference_baseline_only', 'counts': counts, 'total_records': sum(counts.values()),
                'enabled_rules': active, 'device_verified': False, 'database_sha256': sha(database)}
    finally:
        if 'reference' in locals():
            reference.close()
        db.close()


def build(directory, output):
    records = load_records(directory)
    output = Path(output)
    summary = output.with_suffix(output.suffix + '.summary.json')
    if output.exists() or summary.exists():
        raise FileExistsError('Refusing to overwrite database or summary')
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open('xb'):
        pass
    summary_owned = False
    try:
        db = sqlite3.connect(output)
        with db:
            schema = Path(__file__).resolve().parents[1] / 'schema.sql'
            db.executescript(schema.read_text(encoding='utf-8'))
            for record in records:
                table, row = record['table'], record['row']
                names = list(row)
                db.execute(f"INSERT INTO {table} ({','.join(names)}) VALUES ({','.join('?' for _ in names)})",
                           [row[name] for name in names])
        db.close()
        result = inspect(output, records)
        with summary.open('x', encoding='utf-8', newline='\n') as handle:
            summary_owned = True
            handle.write(json.dumps(result, ensure_ascii=False, indent=2) + '\n')
        return result
    except Exception:
        if 'db' in locals():
            db.close()
        output.unlink(missing_ok=True)
        if summary_owned:
            summary.unlink(missing_ok=True)
        raise


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--seed-dir', type=Path, default=Path(__file__).resolve().parents[1] / 'baseline_android14')
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--out', type=Path)
    mode.add_argument('--verify', type=Path)
    args = parser.parse_args()
    try:
        result = inspect(args.verify, load_records(args.seed_dir)) if args.verify else build(args.seed_dir, args.out)
        print(json.dumps(result, ensure_ascii=False, indent=2))
    except (ValueError, KeyError, OSError, sqlite3.Error) as exc:
        print(json.dumps({'status': 'failed', 'error_type': type(exc).__name__, 'message': str(exc)},
                         ensure_ascii=False), file=sys.stderr)
        raise SystemExit(1)
