#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""离线回归：缓存、LRU 淘汰、后台任务。不需要设备、不需要 jadx。"""
from __future__ import annotations

import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import jobs  # noqa: E402


def make_room(root: Path, digest: str, megabytes: int) -> Path:
    room = root / digest
    room.mkdir(parents=True, exist_ok=True)
    (room / "payload.bin").write_bytes(b"x" * (megabytes * 1024 * 1024))
    return room


class CacheTest(unittest.TestCase):
    def test_complete_marker_gates_the_cache(self) -> None:
        """只有打了 `.complete` 才算可用——半成品目录**不能**当缓存命中。

        否则取消/崩溃留下的半个反编译产物会被当成完整结果复用，
        表现为"源码树缺一大半但没人知道"。
        """
        with tempfile.TemporaryDirectory() as tmp:
            cache = jobs.Cache(Path(tmp), limit_bytes=1 << 30)
            make_room(Path(tmp), "aaa", 1)
            self.assertFalse(cache.has("aaa"))
            cache.mark_complete("aaa")
            self.assertTrue(cache.has("aaa"))

    def test_evicts_until_under_the_limit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cache = jobs.Cache(Path(tmp), limit_bytes=3 * 1024 * 1024)
            for name in ("aaa", "bbb", "ccc", "ddd"):
                make_room(Path(tmp), name, 1)
                time.sleep(0.01)          # 拉开 mtime，保证淘汰顺序确定
            removed = cache.evict()
            self.assertTrue(removed, "超限时必须真的淘汰")
            self.assertLessEqual(cache.usage(), cache.limit_bytes)

    def test_evict_never_removes_the_protected_room(self) -> None:
        """正在跑的任务目录删不得：删了之后任务会写进一个已被清空的目录，
        表现为"反编译成功了但文件树是空的"。"""
        with tempfile.TemporaryDirectory() as tmp:
            cache = jobs.Cache(Path(tmp), limit_bytes=1 * 1024 * 1024)
            make_room(Path(tmp), "running", 2)
            make_room(Path(tmp), "old", 2)
            removed = cache.evict(protect="running")
            self.assertNotIn("running", removed)
            self.assertTrue((Path(tmp) / "running").is_dir())

    def test_evict_is_a_noop_under_the_limit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cache = jobs.Cache(Path(tmp), limit_bytes=100 * 1024 * 1024)
            make_room(Path(tmp), "aaa", 1)
            self.assertEqual([], cache.evict())


class RegistryTest(unittest.TestCase):
    def test_job_runs_and_reports_progress(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            registry = jobs.Registry(jobs.Cache(Path(tmp)))
            def work(job, out):
                job.total = 10
                job.done = 7
                return {"ok": True}
            job = registry.submit("digest1", "a.apk", work)
            for _ in range(100):
                if registry.get(job.id).state in ("done", "failed"):
                    break
                time.sleep(0.05)
            final = registry.get(job.id)
            self.assertEqual("done", final.state, final.error)
            self.assertEqual({"ok": True}, final.result)
            self.assertEqual(70, final.as_dict()["percent"])   # 7 / 10

    def test_failure_is_recorded_with_the_exception(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            registry = jobs.Registry(jobs.Cache(Path(tmp)))
            def boom(job, out):
                raise RuntimeError("jadx 炸了")
            job = registry.submit("digest2", "b.apk", boom)
            for _ in range(100):
                if registry.get(job.id).state in ("done", "failed"):
                    break
                time.sleep(0.05)
            final = registry.get(job.id)
            self.assertEqual("failed", final.state)
            self.assertIn("jadx 炸了", final.error)

    def test_a_failed_run_does_not_mark_the_cache_complete(self) -> None:
        """失败**不能**留下 `.complete`——否则下次拖同一个 APK 会直接命中半个产物。"""
        with tempfile.TemporaryDirectory() as tmp:
            cache = jobs.Cache(Path(tmp))
            registry = jobs.Registry(cache)
            def boom(job, out):
                raise RuntimeError("x")
            job = registry.submit("digest3", "c.apk", boom)
            for _ in range(100):
                if registry.get(job.id).state in ("done", "failed"):
                    break
                time.sleep(0.05)
            self.assertFalse(cache.has("digest3"))

    def test_cancel_nonexistent_is_false(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            registry = jobs.Registry(jobs.Cache(Path(tmp)))
            self.assertFalse(registry.cancel("nope"))


class PathSafetyTest(unittest.TestCase):
    def test_read_source_refuses_to_escape_the_sources_dir(self) -> None:
        """`../` 能读到整个磁盘——服务端必须挡住，这是安全边界不是便利问题。"""
        import jadx
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "sources").mkdir()
            (root / "secret.txt").write_text("secret", encoding="utf-8")
            with self.assertRaises(ValueError):
                jadx.read_source(root, "../secret.txt")

    def test_read_source_reads_a_normal_file(self) -> None:
        import jadx
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "sources" / "com").mkdir(parents=True)
            (root / "sources" / "com" / "A.java").write_text("class A {}", encoding="utf-8")
            self.assertEqual("class A {}", jadx.read_source(root, "com/A.java")["text"])


if __name__ == "__main__":
    unittest.main()
