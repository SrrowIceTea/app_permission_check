#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""EventStore 的存储不变量：并发初始化、会话隔离、时间范围、未知时钟分桶。

**为什么搬到这里**：这三条测的是 `core/event_store.py` 的行为，此前却错位在仓库根的
`test_completion.py` 里——那个文件按"新增功能验收"命名，改 `core` 的人不会去翻它
（§8.2 B-5）。搬到被测模块旁边，并让它进 core 组的回归。

**为什么这三条必须留**：它们覆盖的都是**静默**失败——

* 并发初始化失败的表现是丢事件（两个 Collector 同时 `CREATE TABLE` 时一方失败），
  而"少了几百条"在几十万行 JSONL 里根本看不出来；
* 会话隔离写错会把两个应用的读取混进同一个桶，直接产出错误的归因结论；
* 未知时钟（`host_received_ts` 缺失）若能分桶，时间窗就成了一个假的确定值。
"""
from __future__ import annotations

import sys
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.event_store import EventStore  # noqa: E402


def record(pkg: str = 'app.a', ts: int = 1000) -> dict:
    """一条最小可入库事件。`host_received_ts` 是 EventStore 分桶用的时钟。"""
    return dict(pkg=pkg, ts=999999, host_received_ts=ts, evt_id=1, ev='VHAL_READ',
                outcome='ok', prop_id=289408000, prop_name='GEAR_SELECTION')


class StorageTests(unittest.TestCase):
    def test_concurrent_collectors_initialise_and_write(self):
        with tempfile.TemporaryDirectory() as tmp:
            barrier = threading.Barrier(4)

            def collect(index):
                barrier.wait()
                store = EventStore(Path(tmp) / 'events.db')
                try:
                    store.append('one', str(index), record())
                finally:
                    store.close()

            with ThreadPoolExecutor(max_workers=4) as pool:
                list(pool.map(collect, range(4)))
            store = EventStore(Path(tmp) / 'events.db')
            self.assertEqual(4, len(store.query('one', 0, 2000)))
            store.close()

    def test_session_isolation_replay_and_range(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = EventStore(Path(tmp) / 'events.db')
            for session in ('one', 'two'):
                for _ in range(2):
                    store.append(session, 'reads', record())
            self.assertEqual(1, len(store.query('one', 1000, 1001, 'app.a')))
            self.assertEqual([], store.query('one', 0, 1000))
            self.assertEqual(1, store.buckets('one')[0]['count'])
            store.close()

    def test_unknown_clock_not_bucketed(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = EventStore(Path(tmp) / 'events.db')
            store.append('one', 'reads', dict(ts=1000, pkg='app.a'))
            self.assertEqual([], store.buckets('one'))
            store.close()


if __name__ == '__main__':
    unittest.main()
