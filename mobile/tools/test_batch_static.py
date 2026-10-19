#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""`batch_static` / `batch_plan` 的离线守卫。

为什么钉住这三个点：
  ① **目录/键的唯一性**——静态产物目录同时是 `--static-dir` 复用判据和 Windows
     短路径的落点，拼错一次就是"复用永不命中"或"两个样本互相覆盖"，两者都静默；
  ② **并发真的发生了**，且**单条失败不拖垮整批**——批处理最怕"看起来跑了 60 个、
     其实只有第一个成功"；
  ③ **完成标记的语义**——只看目录存在会把半途被杀的那一轮当成已完成（老坑）。

全部离线：不碰设备、不跑 jadx（用假脚本替代），可在 `run_mobile_checks` 里跑。
"""
from __future__ import annotations

import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import batch_plan as bp  # noqa: E402
import batch_static as bs  # noqa: E402

FAKE_SCAN = '''\
import sys, time, pathlib
args = sys.argv[1:]
apk = pathlib.Path(args[args.index("--apk") + 1])
out = pathlib.Path(args[args.index("--out") + 1])
out.mkdir(parents=True, exist_ok=True)
(out / "start").write_text(str(time.time()), encoding="utf-8")
time.sleep(0.35)
(out / "end").write_text(str(time.time()), encoding="utf-8")
sys.exit(7 if "bad" in apk.name else 0)
'''


def _max_overlap(starts: list[float], ends: list[float]) -> int:
    events = sorted([(t, 1) for t in starts] + [(t, -1) for t in ends])
    current = peak = 0
    for _, delta in events:
        current += delta
        peak = max(peak, current)
    return peak


class NamingTest(unittest.TestCase):
    def test_key_has_index_and_short_slug(self):
        key = bs.key_for(7, "com.example.app")
        self.assertTrue(key.startswith("07-"), key)
        self.assertNotIn("com.", key)          # 前缀被剥掉，避免深层路径
        self.assertEqual(key, bs.key_for(7, "com.example.app"))

    def test_static_dir_is_outside_sample_dir(self):
        batch = Path("D:/batch")
        out = bs.dir_for(batch, 2, "com.example.app")
        log = bs.log_for(batch, 2, "com.example.app")
        self.assertEqual(out.parent.name, "_static")
        self.assertEqual(log.parent.name, "_logs")
        # 源目录绝不能落在样本自己的 --out 里（device_run 会 rmtree 后拷，自己删自己）
        self.assertNotIn("02-", out.parts)


class ManifestTest(unittest.TestCase):
    def test_manifest_is_completion_marker(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            self.assertFalse(bs.manifest_done(directory))
            (directory / "dexfacts.json").write_text("{}", encoding="utf-8")
            self.assertFalse(bs.manifest_done(directory), "半成品不该被当成已完成")
            (directory / "static-manifest.json").write_text("{}", encoding="utf-8")
            self.assertTrue(bs.manifest_done(directory))

    def test_reuse_hit_by_package(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "com.example.app").mkdir()
            self.assertIsNone(bs.reuse_hit(root, "com.example.app"))
            (root / "com.example.app" / "static-manifest.json").write_text("{}")
            self.assertEqual(bs.reuse_hit(root, "com.example.app"),
                             root / "com.example.app")
            self.assertIsNone(bs.reuse_hit(None, "com.example.app"))


class ThreadsTest(unittest.TestCase):
    def test_threads_shrink_with_workers(self):
        cpu = os.cpu_count() or 4
        for workers in (1, 2, 3, 8, 32):
            got = bs.threads_for(workers)
            # 向上取整：8 核 3 worker 应给 3 而不是 2（2 会白扔两个核）
            self.assertEqual(got, max(1, min(4, -(-cpu // workers))), f"workers={workers}")
            self.assertLessEqual(got, 4)

    def test_cap_is_honoured(self):
        got = bs.threads_for(1)
        self.assertEqual(got, max(1, min(4, os.cpu_count() or 4)))


class RunJobsTest(unittest.TestCase):
    def test_parallel_and_failure_isolated(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            script = root / "fake_scan.py"
            script.write_text(FAKE_SCAN, encoding="utf-8")
            jobs = []
            for idx, name in enumerate(["one.apk", "two.apk", "bad.apk"], 1):
                jobs.append(bs.Job(key=f"{idx:02d}-{name}", apk=root / name,
                                   package=name, out=root / f"out{idx}",
                                   log=root / "logs" / f"{idx}.log"))
            rcs = bs.run_jobs(jobs, script=script, python=sys.executable, cwd=root,
                              workers=3, timeout=60)

            self.assertEqual(len(rcs), 3)
            self.assertEqual(rcs["03-bad.apk"], 7, "失败样本要如实带回返回码")
            self.assertEqual(rcs["01-one.apk"], 0)
            self.assertEqual(rcs["02-two.apk"], 0)

            starts = [float((root / f"out{i}" / "start").read_text()) for i in (1, 2, 3)]
            ends = [float((root / f"out{i}" / "end").read_text()) for i in (1, 2, 3)]
            # 用事件重叠而不是墙钟时间做判据：Windows 进程启动抖动大，墙钟断言会假红，
            # 而"三个时间段真的叠在一起"是并发的直接证据。
            self.assertEqual(_max_overlap(starts, ends), 3, "3 个 worker 应真的并发")

    def test_empty_jobs(self):
        self.assertEqual(bs.run_jobs([], script=Path("x"), python=sys.executable,
                                     cwd=Path("."), workers=3), {})


class ApplyStaticTest(unittest.TestCase):
    def _item(self, status=None):
        return {"idx": 1, "apk": Path("a.apk"), "pkg": "com.example.app",
                "rec": {"status": status, "steps": {}, "dir": "D:/batch/01-example-app"},
                "reuse": None, "static_dir": None,
                "job": bs.Job(key="01-example-app", apk=Path("a.apk"),
                              package="com.example.app", out=Path("D:/batch/_static/x"),
                              log=Path("D:/batch/_static/_logs/x.log"))}

    def test_success_sets_dir(self):
        item = self._item()
        bp.apply_static(item, {"01-example-app": 0})
        self.assertIsNone(item["rec"]["status"])
        self.assertEqual(item["static_dir"], Path("D:/batch/_static/x"))
        self.assertEqual(item["rec"]["steps"]["static"], 0)

    def test_failure_marks_only_that_sample(self):
        item = self._item()
        bp.apply_static(item, {"01-example-app": 3})
        self.assertEqual(item["rec"]["status"], "static_failed")
        self.assertTrue(item["rec"]["static_log"].endswith("x.log"))
        self.assertIsNone(item["static_dir"], "静态失败不该把半成品当 --static-dir 传下去")

    def test_reuse_skips_and_records_source(self):
        item = self._item()
        item["reuse"] = Path("D:/static-ds/com.example.app")
        bp.apply_static(item, {})
        self.assertEqual(item["static_dir"], Path("D:/static-ds/com.example.app"))
        self.assertEqual(item["rec"]["steps"]["static"], 0)
        self.assertIn("static_reused_from", item["rec"])

    def test_unreadable_is_left_alone(self):
        item = self._item(status="unreadable_apk")
        bp.apply_static(item, {"01-example-app": 1})
        self.assertEqual(item["rec"]["status"], "unreadable_apk")


if __name__ == "__main__":
    unittest.main()
