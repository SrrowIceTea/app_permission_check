"""日志分卷的离线契约：超阈值分卷、旧卷不覆盖、分卷失败不打断写入。

仅用于授权测试（自有设备与已授权的公开第三方样本）。
"""
from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase, main
from unittest.mock import patch

from core import log_rotation as lr


class RotateTests(TestCase):
    def test_below_threshold_keeps_appending(self):
        with TemporaryDirectory() as tmp:
            log = Path(tmp) / "run.log"
            log.write_text("a" * 100, encoding="utf-8")
            with lr.open_capped(log, max_bytes=1024) as fh:
                fh.write("b" * 10)
            self.assertEqual(log.stat().st_size, 110)
            self.assertEqual([p.name for p in Path(tmp).iterdir()], ["run.log"])

    def test_over_threshold_rolls_and_starts_clean(self):
        with TemporaryDirectory() as tmp:
            log = Path(tmp) / "run.log"
            log.write_text("x" * 2048, encoding="utf-8")
            with lr.open_capped(log, max_bytes=1024) as fh:
                fh.write("new\n")
            volumes = sorted(p.name for p in Path(tmp).iterdir() if p.name != "run.log")
            self.assertEqual(len(volumes), 1)
            self.assertTrue(volumes[0].startswith("run.log."))
            self.assertEqual((Path(tmp) / volumes[0]).read_text(encoding="utf-8"),
                             "x" * 2048)                       # 旧卷内容一字不改
            fresh = log.read_text(encoding="utf-8")
            self.assertTrue(fresh.startswith("# 续卷自 " + volumes[0]), fresh)
            self.assertTrue(fresh.endswith("new\n"))

    def test_same_second_never_overwrites_volume(self):
        with TemporaryDirectory() as tmp:
            log = Path(tmp) / "run.log"
            for _ in range(3):
                log.write_text("y" * 64, encoding="utf-8")
                lr.rotate_if_needed(log, max_bytes=32, stamp="20261111-232900")
            names = sorted(p.name for p in Path(tmp).iterdir())
            self.assertEqual(names, ["run.log.20261111-232900",
                                     "run.log.20261111-232900-2",
                                     "run.log.20261111-232900-3"])

    def test_existing_volume_with_content_is_never_replaced(self):
        """同名卷已存在（并发进程/历史残留）→ 换 -2，已存在的那份内容必须原样保留。"""
        with TemporaryDirectory() as tmp:
            log = Path(tmp) / "run.log"
            taken = Path(tmp) / "run.log.s"
            taken.write_text("precious", encoding="utf-8")
            log.write_text("v" * 32, encoding="utf-8")
            volume = lr.rotate_if_needed(log, max_bytes=16, stamp="s")
            self.assertEqual(volume.name, "run.log.s-2")
            self.assertEqual(taken.read_text(encoding="utf-8"), "precious")

    def test_locked_file_does_not_break_logging(self):
        """Windows 上分卷改名会失败；失败必须退化成继续追加，而不是抛给跑批。"""
        with TemporaryDirectory() as tmp:
            log = Path(tmp) / "run.log"
            log.write_text("z" * 100, encoding="utf-8")
            with patch.object(lr.os, "replace", side_effect=PermissionError("locked")):
                with lr.open_capped(log, max_bytes=10) as fh:
                    fh.write("tail")
            self.assertEqual(log.read_text(encoding="utf-8"), "z" * 100 + "tail")
            self.assertEqual(len(list(Path(tmp).iterdir())), 1)

    def test_missing_parent_is_created(self):
        with TemporaryDirectory() as tmp:
            log = Path(tmp) / "a" / "b" / "run.log"
            with lr.open_capped(log) as fh:
                fh.write("x")
            self.assertTrue(log.is_file())

    def test_default_threshold_is_bounded(self):
        self.assertEqual(lr.DEFAULT_MAX_BYTES, 20 * 1024 * 1024)
        self.assertLess(lr.DEFAULT_MAX_BYTES, 64 * 1024 * 1024)

    def test_zero_threshold_still_rotates_once(self):
        """max_bytes<=0 时不能变成"每次打开都分卷"的死循环，但仍要分卷一次。"""
        with TemporaryDirectory() as tmp:
            log = Path(tmp) / "run.log"
            log.write_text("v", encoding="utf-8")
            self.assertIsNotNone(lr.rotate_if_needed(log, max_bytes=0, stamp="s"))
            self.assertIsNone(lr.rotate_if_needed(log, max_bytes=0, stamp="s"))


class WiringTests(TestCase):
    """跑批日志必须真的走这一层，否则模块再对也没有上限。"""

    def test_batch_logs_use_capped_open(self):
        root = Path(__file__).resolve().parents[1]
        batch_dynamic = (root / "mobile/tools/batch_dynamic.py").read_text(encoding="utf-8")
        supervise = (root / "mobile/tools/supervise_batch.py").read_text(encoding="utf-8")
        for label, text in (("batch_dynamic", batch_dynamic), ("supervise_batch", supervise)):
            self.assertIn("open_capped", text, f"{label} 未接 log_rotation.open_capped")
            self.assertNotIn('open("a", encoding="utf-8")', text,
                             f"{label} 仍有裸追加句柄（无上限）")

    def test_output_dirs_are_ignored_by_git(self):
        """只断言 .gitignore 口径；不假设 output/ 存在（干净检出没有它，回归会自建）。"""
        root = Path(__file__).resolve().parents[1]
        ignored = (root / ".gitignore").read_text(encoding="utf-8")
        self.assertIn("output/", ignored)


if __name__ == "__main__":
    main()
