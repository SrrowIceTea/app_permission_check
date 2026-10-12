"""SQLite 单机会话时序事件库；仅用于授权测试。JSONL 保留为原始证据。

按 session、collector、包名及主机时间索引，支持范围查询和固定时间桶聚合。
不是 InfluxDB/TimescaleDB，也不声称分布式时序引擎能力。
"""
import argparse
import hashlib
import json
import sqlite3
import time
from pathlib import Path

SCHEMA = '''
    CREATE TABLE IF NOT EXISTS events (
        session TEXT NOT NULL, collector TEXT NOT NULL, digest TEXT NOT NULL,
        ts INTEGER, device_ts INTEGER, package TEXT, kind TEXT, payload TEXT NOT NULL,
        PRIMARY KEY(session, collector, digest));
    CREATE INDEX IF NOT EXISTS event_time ON events(session, ts);
    CREATE INDEX IF NOT EXISTS package_time ON events(session, package, ts);
'''
# 换句柄重试的上限；下面三类 SQLite 错误在本模块里都是**可换句柄恢复**的瞬时故障。
REOPEN_ATTEMPTS = 40
TRANSIENT_DB = ('locked', 'busy', 'readonly')


def _transient(exc):
    msg = str(exc).lower()
    return any(key in msg for key in TRANSIENT_DB)


class EventStore:
    """单文件事件库。**同一进程内多线程并发首建同一个库**是明确支持的用法，见 `_connect`。"""

    def __init__(self, path):
        self.path = str(path)
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.db = None
        self._connect()

    def _connect(self):
        """建连接 + 切 WAL + 建表；碰到瞬时错误就**换一个新句柄**重来。

        为什么不能原地重试（实测，不是理论）：Windows 上 SQLite 的 VFS 维护一份进程级
        的打开文件表，同进程内多线程并发首次打开同一个库时，后到者会拿到
        `attempt to write a readonly database`，而该状态**粘在句柄上不会自愈**——
        原地重试 40 次仍是全失败，关掉重开则 4 线程 10/10、8 线程 6/6 全部成功。
        换成多进程并发完全正常（0/6 失败），只有同进程多线程会踩。
        所以修复点是"换句柄"，不是"多等一会"。
        """
        if self.db is not None:
            # 换句柄前必须先把旧的关掉。直接覆盖 `self.db` 会让旧连接泄漏成孤儿句柄，
            # 表现为临时目录清理时报 WinError 32（"另一个程序正在使用此文件"，实测踩过）。
            self.close()
        self.db = sqlite3.connect(self.path, timeout=15, check_same_thread=False)
        for attempt in range(REOPEN_ATTEMPTS):
            try:
                self.db.execute('PRAGMA journal_mode=WAL')
                self.db.executescript(SCHEMA)
                return
            except sqlite3.OperationalError as exc:
                if attempt == REOPEN_ATTEMPTS - 1 or not _transient(exc):
                    self.close()
                    raise
                self.close()
                time.sleep(.05 * (attempt + 1))
                self.db = sqlite3.connect(self.path, timeout=15, check_same_thread=False)

    def append(self, session, collector, record):
        if not session or not collector:
            raise ValueError('session 和 collector 不得为空')
        payload = json.dumps(record, ensure_ascii=False, sort_keys=True)
        ts = record.get('host_received_ts')
        if ts is None and record.get('src') == 'proxy':
            ts = record.get('ts')
        row = (session, collector, hashlib.sha256(payload.encode()).hexdigest(), ts,
               record.get('ts'), record.get('pkg') or record.get('package'),
               record.get('ev') or 'PROXY_FLOW', payload)
        # 与 _connect 同理：句柄一旦进入 readonly 就没救了，写失败也要换句柄重来。
        for attempt in range(REOPEN_ATTEMPTS):
            try:
                with self.db:
                    self.db.execute('INSERT OR IGNORE INTO events VALUES (?,?,?,?,?,?,?,?)', row)
                return
            except sqlite3.OperationalError as exc:
                if attempt == REOPEN_ATTEMPTS - 1 or not _transient(exc):
                    raise
                self._connect()
                time.sleep(.05 * (attempt + 1))

    def query(self, session, start, end, package=None):
        sql = 'SELECT payload FROM events WHERE session=? AND ts>=? AND ts<?'
        params = [session, start, end]
        if package:
            sql += ' AND package=?'
            params.append(package)
        return [json.loads(r[0]) for r in self.db.execute(sql + ' ORDER BY ts, collector, digest', params)]

    def buckets(self, session, width_ms=1000):
        if width_ms <= 0:
            raise ValueError('时间桶宽度必须为正数')
        return [dict(zip(('ts', 'package', 'kind', 'count'), r)) for r in self.db.execute(
            'SELECT (ts / ?) * ?, package, kind, COUNT(*) FROM events '
            'WHERE session=? AND ts IS NOT NULL GROUP BY 1,2,3 ORDER BY 1',
            (width_ms, width_ms, session))]

    def close(self):
        if self.db is not None:
            self.db.close()
            self.db = None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--db', type=Path, required=True)
    parser.add_argument('--session', required=True)
    parser.add_argument('--import-jsonl', type=Path, action='append', default=[])
    parser.add_argument('--bucket-ms', type=int, default=1000)
    parser.add_argument('--start-ms', type=int)
    parser.add_argument('--end-ms', type=int)
    parser.add_argument('--package')
    parser.add_argument('--export-jsonl', type=Path)
    args = parser.parse_args()
    store = EventStore(args.db)
    try:
        for path in args.import_jsonl:
            with path.open(encoding='utf-8') as handle:
                for number, line in enumerate(handle, 1):
                    if line.strip():
                        try:
                            store.append(args.session, str(path.resolve()), json.loads(line))
                        except (ValueError, TypeError) as exc:
                            raise ValueError(f'{path}:{number}: {exc}') from exc
        if args.start_ms is not None or args.end_ms is not None:
            if args.start_ms is None or args.end_ms is None or args.end_ms <= args.start_ms:
                parser.error('范围查询需要 start-ms < end-ms')
            rows = store.query(args.session, args.start_ms, args.end_ms, args.package)
            if args.export_jsonl:
                args.export_jsonl.parent.mkdir(parents=True, exist_ok=True)
                with args.export_jsonl.open('x', encoding='utf-8') as handle:
                    for row in rows:
                        handle.write(json.dumps(row, ensure_ascii=False) + '\n')
            print(json.dumps(rows, ensure_ascii=False))
        else:
            print(json.dumps(store.buckets(args.session, args.bucket_ms), ensure_ascii=False))
    finally:
        store.close()


if __name__ == '__main__':
    main()
