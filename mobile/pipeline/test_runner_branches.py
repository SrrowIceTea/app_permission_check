"""runner 的三条失败分支：静态失败 / 设备不可用 / 动态 rc≠0 但报告已出。

仅用于授权测试（自有设备与已授权的公开第三方样本）。

为什么单独成文件：`runner.py:99-218` 的终态判定是「报告生成即算完成」，但它同时
也是「静态失败必须整单失败」「设备不可用必须降级 static_only 而不是假装跑过」这两条
口径的唯一实现。此前 `mobile/pipeline/` 的 group 只有 formal_runner / history 共 5 个
用例（2026-11-11 评估 §1.5），这三条分支一旦被改错，前端只会看到"done"，没人会红。

全部离线：不连设备（`device_boot` 的 ensure_device 被替换）、不跑 jadx/aapt2
（`_run` 与 `apk_meta.badging` 被替换）、不发网络。产物只写临时目录。
"""
from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase, main
from unittest.mock import patch

from mobile.pipeline import runner, stages
from mobile.pipeline.runner import PipelineJob, run_pipeline

IDENT = {"package": "com.example.demo", "app_label": "Demo", "version_name": "1.0",
         "version_code": "1"}

# 期望值**硬编码**：不能用 stages.DYNAMIC_STAGES 同时当期望与实参（那样把集合改空也全绿）。
# 改动阶段划分时，这条与 stages.py 一起改——这正是"17→16 阶段漂移"该响的地方。
DYNAMIC_EXPECTED = [
    "frida_server", "network", "install", "launch", "conn_probe", "mitm", "hooks",
    "explore", "death_probe", "correlate", "bundle", "ai_review", "report",
]
NON_DEVICE_EXPECTED = ["prepare", "boot", "static", "surface"]


def make_job(root) -> PipelineJob:
    apk = root / "demo.apk"
    apk.write_bytes(b"PK\x03\x04unit-fixture")
    out = root / "job"
    out.mkdir()
    return PipelineJob(apk, out)


def event_status(events_file, stage: str) -> list[str]:
    events, _ = stages.read_events(events_file)
    return [e["status"] for e in events if e["stage"] == stage]


def fake_surface(job, events) -> None:
    """敏感面统计的桩：真实实现只读 APK、设备不可用时也照样出数，这里只留一条事件。"""
    stages.emit_events(events, "surface", "done", "stub：敏感面统计完成")


class StaticFailureTests(TestCase):
    """静态段失败 → failed，且不得继续走设备与动态段。"""

    def test_static_rc_nonzero_fails_whole_job(self):
        with TemporaryDirectory() as tmp:
            job = make_job(Path(tmp))
            with patch.object(runner, "_run", return_value=7) as run, \
                    patch.object(runner, "finalize") as finish:
                run_pipeline(job)
            self.assertEqual(finish.call_args.args[1], "failed")
            self.assertIn("rc=7", finish.call_args.args[2])
            # 只跑了静态那一次，设备/动态一次都没起
            self.assertEqual(run.call_count, 1)
            self.assertEqual(event_status(job.events, "static"), ["running", "failed"])
            self.assertEqual(event_status(job.events, "boot"), [])

    def test_missing_apk_fails_before_any_stage(self):
        with TemporaryDirectory() as tmp:
            job = make_job(Path(tmp))
            job.apk.unlink()
            with patch.object(runner, "_run") as run, \
                    patch.object(runner, "finalize") as finish:
                run_pipeline(job)
            self.assertEqual(finish.call_args.args[1], "failed")
            self.assertIn("样本不存在", finish.call_args.args[2])
            run.assert_not_called()


class StageSplitTests(TestCase):
    """阶段划分本身：`DYNAMIC_STAGES` 必须正好是 13 个设备侧阶段。

    `stages.py:47-51` 把「surface 不得被算进设备阶段」写成硬口径；只用常量互相验证
    抓不到"把 surface 划进设备段"或"集合被清空"这类改动，所以这里写死名单。
    """

    def test_dynamic_and_non_device_stages_are_pinned(self):
        self.assertEqual(list(stages.DYNAMIC_STAGES), DYNAMIC_EXPECTED)
        self.assertEqual(list(stages.NON_DEVICE_STAGES), NON_DEVICE_EXPECTED)
        self.assertEqual(len(stages.STAGES), 17)
        self.assertIn("surface", stages.NON_DEVICE_STAGES)


class DeviceUnavailableTests(TestCase):
    """设备不可用 → static_only，动态阶段逐条 skipped（不得写成 done/没跑不说）。"""

    def test_no_device_degrades_to_static_only(self):
        with TemporaryDirectory() as tmp:
            job = make_job(Path(tmp))
            reason = "adb devices 为空：没有可用设备"
            with patch.object(runner, "_run", return_value=0), \
                    patch.object(runner, "badging", return_value=dict(IDENT)), \
                    patch("mobile.pipeline.surface_stage.run", side_effect=fake_surface), \
                    patch.object(runner.dboot, "needs_cold_start", return_value=False), \
                    patch.object(runner.dboot, "ensure_device", return_value=(False, reason)):
                run_pipeline(job)

            self.assertEqual(job.state, "static_only")
            self.assertEqual(job.error, reason)
            self.assertEqual(job.result["device_unavailable"], reason)
            # 静态结论仍然出得来（不是整单失败）
            self.assertEqual(job.result["static"]["package"], "com.example.demo")
            for sid in DYNAMIC_EXPECTED:
                self.assertEqual(event_status(job.events, sid), ["skipped"], sid)
            # surface 只读 APK，设备挂了也照样出数——绝不能被标成 skipped
            self.assertEqual(event_status(job.events, "surface"), ["done"])
            self.assertNotIn("skipped", event_status(job.events, "surface"))
            self.assertEqual(event_status(job.events, "boot"), ["running", "failed"])
            # 终态落盘，供前端/批处理读
            saved = json.loads((job.out / "pipeline.json").read_text(encoding="utf-8"))
            self.assertEqual(saved["state"], "static_only")


class DynamicReportTests(TestCase):
    """动态 rc≠0 但报告已产出 → done（报告如实记录缺口，不把可用检测整单判失败）。"""

    def _run_with(self, root, rc: int, report: bool, verification: dict | None):
        job = make_job(root)
        if report:
            (job.out / "out").mkdir()
            (job.out / "out" / "mobile-report.pdf").write_bytes(b"%PDF-unit-only")
        if verification is not None:
            (job.out / "verification.json").write_text(
                json.dumps(verification), encoding="utf-8")
        calls: list[str] = []

        def fake_run(cmd, log, timeout):
            calls.append(str(cmd[1]))
            return 0 if "static_scan_thirdparty.py" in str(cmd[1]) else rc

        with patch.object(runner, "_run", side_effect=fake_run), \
                patch.object(runner, "badging", return_value=dict(IDENT)), \
                patch.object(runner, "launchable_activity",
                             return_value=("com.example.demo/.Main", "launcher")), \
                patch("mobile.pipeline.surface_stage.run", side_effect=fake_surface), \
                patch.object(runner.dboot, "needs_cold_start", return_value=False), \
                patch.object(runner.dboot, "early_mitm_started", return_value=False), \
                patch.object(runner.dboot, "ensure_device", return_value=(True, "emulator-5554")):
            run_pipeline(job)
        return job, calls

    def test_report_present_overrides_failing_rc(self):
        with TemporaryDirectory() as tmp:
            job, calls = self._run_with(Path(tmp), rc=1, report=True,
                                        verification={"passed": False,
                                                      "failed": ["zero_runtime_events"]})
            self.assertEqual(job.state, "done")
            self.assertIsNone(job.error)
            self.assertEqual(len(calls), 2)          # 静态 + 动态各一次
            self.assertTrue(job.result["report"])
            self.assertEqual(job.result["verification"]["failed"], ["zero_runtime_events"])
            self.assertEqual(event_status(job.events, "static"), ["running", "done"])
            saved = json.loads((job.out / "pipeline.json").read_text(encoding="utf-8"))
            self.assertEqual(saved["state"], "done")

    def test_zero_rc_without_report_is_failed(self):
        """rc=0 但没报告 → failed。

        没有这条时，把终态判据写成 `if report.exists() or rc == 0` 会全绿——那等于把
        "报告生成即算完成"悄悄换成"退出码即完成"，前端会看到 done 但 result.report=null。
        """
        with TemporaryDirectory() as tmp:
            job, _ = self._run_with(Path(tmp), rc=0, report=False, verification=None)
            self.assertEqual(job.state, "failed")
            self.assertIn("rc=0", job.error)
            self.assertIsNone(job.result["report"])

    def test_no_report_and_failing_rc_is_failed(self):
        with TemporaryDirectory() as tmp:
            job, _ = self._run_with(Path(tmp), rc=1, report=False, verification=None)
            self.assertEqual(job.state, "failed")
            self.assertIn("rc=1", job.error)
            self.assertIsNone(job.result["report"])


class RunningStateTests(TestCase):
    """执行期必须真的进入 `running`。

    此前 `state` 只在 finalize 时落盘，整条流水线（实测 5–15 分钟）里
    `/api/pipeline/<id>` 一直回 `queued`，前端刷新看到「仍在排队」，
    无法区分"没开始"与"正在跑第 12 个阶段"。
    """

    def test_state_is_running_while_pipeline_executes(self):
        with TemporaryDirectory() as tmp:
            job = make_job(Path(tmp))
            seen = {}

            def fake_finalize(target, state, error=None):
                seen["at_finalize"] = target.state

            with patch.object(runner, "_run", return_value=7), \
                    patch.object(runner, "finalize", side_effect=fake_finalize):
                run_pipeline(job)
            self.assertEqual(seen["at_finalize"], "running",
                             "进入 finalize 时 state 应已是 running，不能还是 queued")

    def test_running_state_is_persisted_for_api_reads(self):
        """持久化后才能被 `/api/pipeline/<id>` 与 history.lookup 读到。"""
        with TemporaryDirectory() as tmp:
            job = make_job(Path(tmp))
            with patch.object(runner, "_run", return_value=7), \
                    patch.object(runner, "finalize"):
                run_pipeline(job)
            saved = json.loads((job.out / "pipeline.json").read_text(encoding="utf-8"))
            self.assertEqual(saved["state"], "running")
            self.assertEqual(saved["id"], job.id)


if __name__ == "__main__":
    main()
