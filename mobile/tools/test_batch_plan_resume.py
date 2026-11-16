"""`--resume` 的完成判据：目录存在 ≠ 样本已完成（`batch_plan._finished`）。

仅用于授权测试（自有设备与已授权的公开第三方样本）。

为什么单列：`batch_plan.py:27-40` 是「断点续跑」唯一的分母来源，也是
`supervise_batch.batch_progress` 判断"这批跑完没有"的同款口径。它的反例很隐蔽——
上次半途死掉的样本目录里同样有 `run.log`、`static/`、`out/`，长得和成功产物一模一样，
所以判据必须是 **verification.json 的 passed 为 true 且报告在**，不能是 `app_dir.exists()`。
另外 `out/verification.json` 是动态段的判据文件，passed=false（有缺口）不能当成已完成。

全部离线：`badging`（要 aapt2 + 真 APK）被替换；不碰设备、不跑 jadx。
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase, main
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))

import batch_plan as bp

PKG_A = "com.example.alpha"
PKG_B = "com.example.bravo"


def sample(batch: Path, key: str, *, verification=None, report=True) -> Path:
    """造一个"看起来跑过"的样本目录。verification=None 表示不写该文件。"""
    app_dir = batch / key
    (app_dir / "out").mkdir(parents=True)
    (app_dir / "run.log").write_text("样本: x.apk\n", encoding="utf-8")
    (app_dir / "static").mkdir()
    if report:
        (app_dir / "out" / "mobile-report.pdf").write_bytes(b"%PDF-unit-only")
    if verification is not None:
        text = verification if isinstance(verification, str) else json.dumps(verification)
        (app_dir / "verification.json").write_text(text, encoding="utf-8")
    return app_dir


class FinishedCriterionTests(TestCase):
    def test_completed_retry_leaves_original_failure_intact(self):
        with TemporaryDirectory() as tmp:
            app = sample(Path(tmp), "01-alpha", verification={"passed": False})
            attempt = sample(app, "try-second", verification={"passed": True})
            self.assertEqual(attempt, bp.completed_attempt(app))
            self.assertFalse(bp._finished(app))

    def test_passed_false_is_not_finished(self):
        """核心反例：目录齐全、报告在，但判据未通过 → 必须重跑。"""
        with TemporaryDirectory() as tmp:
            app = sample(Path(tmp), "01-alpha", verification={"passed": False})
            self.assertFalse(bp._finished(app))

    def test_missing_passed_key_is_not_finished(self):
        with TemporaryDirectory() as tmp:
            app = sample(Path(tmp), "01-alpha", verification={"failed": ["network_up"]})
            self.assertFalse(bp._finished(app))

    def test_passed_true_without_report_is_not_finished(self):
        with TemporaryDirectory() as tmp:
            app = sample(Path(tmp), "01-alpha", verification={"passed": True}, report=False)
            self.assertFalse(bp._finished(app))

    def test_missing_or_broken_verification_is_not_finished(self):
        with TemporaryDirectory() as tmp:
            self.assertFalse(bp._finished(sample(Path(tmp), "01-alpha", verification=None)))
            self.assertFalse(bp._finished(sample(Path(tmp), "02-bravo", verification="{not json")))
            # 半截 JSON（上次被杀时的现场）同样不能算完成
            self.assertFalse(bp._finished(sample(Path(tmp), "03-charlie", verification='{"passed": tr')))

    def test_passed_true_with_report_is_finished(self):
        with TemporaryDirectory() as tmp:
            app = sample(Path(tmp), "01-alpha", verification={"passed": True})
            self.assertTrue(bp._finished(app))

    def test_empty_directory_is_not_finished(self):
        with TemporaryDirectory() as tmp:
            empty = Path(tmp) / "09-empty"
            empty.mkdir()
            self.assertFalse(bp._finished(empty))
            self.assertFalse(bp._finished(Path(tmp) / "does-not-exist"))


class CollectResumeTests(TestCase):
    """`collect(resume=True)` 必须把上面的判据真正用起来，而不是按目录名跳过。"""

    def _collect(self, batch: Path, apks: list[Path]) -> list[dict]:
        def fake_badging(apk, _build_tools):
            return {"package": PKG_A if apk.stem.startswith("a") else PKG_B,
                    "app_label": "x", "version_name": "1", "version_code": "1"}

        with patch.object(bp, "badging", side_effect=fake_badging):
            return bp.collect(apks, batch, build_tools="unused", resume=True)

    def test_failed_verification_is_replanned_not_resumed(self):
        with TemporaryDirectory() as tmp:
            batch = Path(tmp)
            sample(batch, "01-example-alpha", verification={"passed": False})
            apk = batch / "alpha.apk"
            apk.write_bytes(b"PK")
            # run.log 先删掉：否则 sample() 自己写的那份会让"collect 有没有写头"看不出来
            (batch / "01-example-alpha" / "run.log").unlink()
            plan = self._collect(batch, [apk])

            rec = plan[0]["rec"]
            self.assertIsNone(rec["status"], "passed=false 的样本不能标成 resumed")
            self.assertNotIn("report", rec)
            log = plan[0]["app_dir"] / "run.log"
            self.assertTrue(log.is_file(), "重跑必须重建可读现场")
            self.assertIn(PKG_A, log.read_text(encoding="utf-8"))
            self.assertIn("job", plan[0], "重跑样本必须重新建静态任务")

    def test_replan_appends_instead_of_truncating(self):
        """同一目录再跑一次不能抹掉上一轮现场（失败运行同样保留产物）。"""
        with TemporaryDirectory() as tmp:
            batch = Path(tmp)
            app = sample(batch, "01-example-alpha", verification={"passed": False})
            (app / "run.log").write_text("上一轮 device_run 的输出\n", encoding="utf-8")
            apk = batch / "alpha.apk"
            apk.write_bytes(b"PK")
            self._collect(batch, [apk])
            text = (app / "run.log").read_text(encoding="utf-8")
            self.assertIn("上一轮 device_run 的输出", text, "旧现场被截断了")
            self.assertIn("重新排入本样本", text)
            self.assertIn(PKG_A, text)

    def test_passed_sample_is_resumed(self):
        with TemporaryDirectory() as tmp:
            batch = Path(tmp)
            app = sample(batch, "01-example-alpha", verification={"passed": True})
            (app / "out" / "summary.json").write_text(
                json.dumps({"findings_total": 3, "findings_by_rule_type": {"x": 3}}),
                encoding="utf-8")
            apk = batch / "alpha.apk"
            apk.write_bytes(b"PK")
            plan = self._collect(batch, [apk])

            rec = plan[0]["rec"]
            self.assertEqual(rec["status"], "resumed")
            self.assertEqual(rec["report"], str(app / "out" / "mobile-report.pdf"))
            self.assertEqual(rec["findings_total"], 3)
            self.assertNotIn("job", plan[0], "已完成的样本不该再排静态任务")

    def test_resume_off_never_skips(self):
        with TemporaryDirectory() as tmp:
            batch = Path(tmp)
            sample(batch, "01-example-alpha", verification={"passed": True})
            apk = batch / "alpha.apk"
            apk.write_bytes(b"PK")
            with patch.object(bp, "badging",
                              return_value={"package": PKG_A, "app_label": "x",
                                            "version_name": "1", "version_code": "1"}):
                plan = bp.collect([apk], batch, build_tools="unused", resume=False)
            self.assertIsNone(plan[0]["rec"]["status"])
            self.assertIn("job", plan[0])


if __name__ == "__main__":
    main()
