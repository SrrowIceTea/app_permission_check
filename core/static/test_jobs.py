#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""离线回归：缓存、LRU 淘汰、后台任务。不需要设备、不需要 jadx。"""
from __future__ import annotations

import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import jobs  # noqa: E402
import winpath  # noqa: E402


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


_DEEP_FILE_NAME = "A" * 60 + ".java"


def make_deep_file(root: Path, content: bytes = b"", minimum: int = 262) -> Path:
    """在 `root/sources/` 下造一条**超过 Windows MAX_PATH(260)** 的路径并落一个文件。

    这类超长路径不是臆想的：jadx 源码树的深度由被测 APK 的包名与类名决定，
    `android/view/accessibility/AccessibilityManager$...Listener.java` 单是 `sources/`
    之后就有 90+ 字符，本项目实测最长绝对路径 **262**（2026-10-12）。临时目录本身很短，
    所以要自己堆目录把长度顶上去。

    注意**每一级都必须用扩展长度形式创建**：普通 `mkdir` 自己就先撞上 260（WinError 206），
    连夹具都建不出来。
    """
    root.mkdir(parents=True, exist_ok=True)
    # 用**少而长**的目录名把总长度顶过 260：Windows 上删除目录很贵（本机实测单次
    # 长路径递归删除要 15s 量级），层数从十几个降到三个，测试才跑得动。
    # 触发这个 bug 的只是**路径总长**，与分段数无关，所以这样仍然测得到东西。
    parts: list[str] = []
    while len(winpath.extended(root.joinpath("sources", *parts, _DEEP_FILE_NAME))) <= minimum:
        parts.append(f"{len(parts):02d}".ljust(67, "x"))
    current = root
    for segment in ("sources", *parts):
        current = current / segment
        try:
            os.mkdir(winpath.extended(current))
        except FileExistsError:
            pass
    deep = current / _DEEP_FILE_NAME
    with open(winpath.extended(deep), "wb") as handle:
        handle.write(content)
    return deep


class LongPathTest(unittest.TestCase):
    """Windows MAX_PATH 回归：超过 260 的路径必须照样能列、能读、能统计、能删。

    症状之所以难查，是因为它**不是崩在列目录**上：`rglob` 用父目录、照样成功，
    于是"文件树看着是对的"；只有对那个文件 `stat()`/`open()` 才抛 WinError 3。
    2026-10-12 拆分把 `phase7/` 改名成 `vehicle/workbench/` 后路径越过 260，
    整条分析直接判 failed——所以这条必须钉住。

    四件事合成一条用例：Windows 上创建/删除目录很贵，一棵深树跑下来要秒级，
    拆成四条会把这个基本断言的成本翻好几倍（实测 3 条要 24s，1 条 8s）。
    断言各自带说明，失败时照样看得到是哪一段。
    """

    def test_deep_paths_still_list_read_size_and_delete(self) -> None:
        import jadx
        # 不用 TemporaryDirectory：它的收尾也是 shutil.rmtree，会被同一个坑绊倒
        # （超长路径 + 混分隔符 → WinError 145），于是断言全过、却报 error。
        root = Path(tempfile.mkdtemp(prefix="vscan-longpath-"))
        self.addCleanup(winpath.rmtree, root)

        room = root / "aaa"
        payload = b"class Deep {}"
        deep = make_deep_file(room, payload)
        self.assertGreater(len(str(deep)), 260, "夹具必须真的超过 MAX_PATH，否则测不到东西")
        relative = deep.relative_to(room / "sources").as_posix()

        # 1) 列树：这正是"拖入 APK 显示分析失败"崩掉的那一步
        entries = {entry["path"]: entry["size"] for entry in jadx.source_tree(room)}
        self.assertEqual(len(payload), entries[relative])

        # 2) 读单个源文件（界面上点开源码走这里）
        self.assertEqual(payload.decode(), jadx.read_source(room, relative)["text"])

        # 3) 统计容量：usage() 在**成功路径**上被 mark_complete -> evict 调用，
        #    一炸就把一次成功分析记成 failed
        cache = jobs.Cache(root, limit_bytes=1 << 30)
        self.assertEqual(len(payload), cache.usage())

        # 4) 淘汰要真的把它删掉——普通 shutil.rmtree 在这种路径上会静默失败（目录还在）
        cache = jobs.Cache(root, limit_bytes=1)
        self.assertEqual(["aaa"], cache.evict())
        self.assertFalse(room.exists())


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
