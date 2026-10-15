#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""APEX 信任库挂载的离线回归（不需要设备）。

跑法：python -m unittest test_apex_ca   （在 mobile/traffic 目录下）

这一层的失败全都**不报错**，只是"没生效"，所以纯设备测试靠不住——设备上跑一遍
绿色、应用照样 `certificate unknown` 是常态。这里钉住的是命令序列的**形状**：

  * 每个 zygote 都必须有自己的 `nsenter -t <pid> -m -- mount --bind`
    （只挂 shell 命名空间 = 没挂，而 shell 里 `ls` 一切正常）
  * 不能 `rm -rf` 一个正被别人当证书库读的目录（那会让它瞬间看到空信任库）
  * 准备阶段必须**先**拷现有 APEX 证书、**再**补我们那张（少拷就丢了系统根证书）
  * `perm` 里目录必须留 x 位（`chmod -R 644` 会把目录也锁死）
  * SELinux 上下文必须是 system_security_cacerts_file
  * 找不到 zygote 时必须**报错**，不能报成功
"""
from __future__ import annotations

import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import apex_ca  # noqa: E402

APEX = apex_ca.APEX_CA_DIR
FNAME = "c8750f0d.0"
SRC = f"/sdcard/{FNAME}"
STAGE = "/data/local/tmp/cacerts-vscan-1014-120000"
PIDS = {"zygote64": "476", "webview_zygote": "1145"}


def fake_adb(apex_present: bool = True, zygotes: dict | None = None,
             invisible: tuple = (), fail_on: str | None = None,
             state: str = "device"):
    """替身：只关心命令**长什么样**，不关心设备。返回 (可调用, 调用记录)。"""
    zygotes = PIDS if zygotes is None else zygotes
    calls: list[str] = []

    def _run(*args, timeout=120):
        cmd = " ".join(args)
        calls.append(cmd)
        rc, out, err = 0, "", ""
        if cmd == "get-state":
            if state == "device":
                out = "device\n"
            else:
                rc = 1
                err = ("error: no devices/emulators found\n" if not state
                       else f"error: device {state}\n")
        elif cmd.startswith("shell ls -d "):
            rc = 0 if apex_present else 1
        elif "pidof" in cmd:
            name = cmd.rsplit("pidof ", 1)[1].strip()
            if name in zygotes:
                out = zygotes[name] + "\n"
            else:
                rc = 1
        elif "nsenter" in cmd and " ls " in cmd:
            pid = cmd.split("-t ", 1)[1].split()[0]
            rc = 0 if pid not in invisible else 1
        if fail_on and fail_on in cmd:
            rc = 1
        return subprocess.CompletedProcess(args=list(args), returncode=rc,
                                           stdout=out, stderr=err)

    return _run, calls


class ZygoteNamespaceTest(unittest.TestCase):
    def test_every_zygote_gets_its_own_mount(self):
        """**这一层的全部意义就在这里**：应用进程有自己的 mount namespace，
        只挂 shell 那份，应用一点都拿不到。漏掉任何一个 zygote，它 fork 出来的
        应用就 `certificate unknown`——而 shell 里 `ls` 数得出一张张证书，看不出问题。"""
        text = [cmd for _, cmd in apex_ca.mount_plan(FNAME, STAGE, SRC, PIDS)]
        for pid in PIDS.values():
            self.assertTrue(
                any(f"nsenter -t {pid} -m -- mount --bind" in c for c in text),
                f"zygote {pid} 没有自己的挂载命令")
        self.assertEqual(sum("nsenter" in c and "mount --bind" in c for c in text),
                         len(PIDS))
        # shell 命名空间那份不服务应用，但它是人排障时唯一看得见的东西。
        self.assertTrue(any(c.startswith("mount --bind ") for c in text))

    def test_never_removes_a_live_cert_dir(self):
        """`rm -rf` 一个正被某个命名空间当证书库读的目录，会让那个命名空间瞬间
        看到**空**信任库——比不装更糟，而且不报错。所以只新建、不删除。"""
        plan = apex_ca.mount_plan(FNAME, STAGE, SRC, PIDS)
        for _, cmd in plan:
            self.assertNotIn("rm -rf", cmd)

    def test_stage_dir_is_fresh_per_run(self):
        """固定复用一个 stage 路径，才会引出"先删再建"的需求；每轮换新目录就不必删。"""
        d = apex_ca.stage_dir()
        self.assertTrue(d.startswith(apex_ca.CA_STAGE_PREFIX + "-"))
        self.assertNotEqual(d, apex_ca.CA_STAGE_PREFIX)


class PrepareOrderTest(unittest.TestCase):
    def _plan(self) -> dict:
        return dict(apex_ca.mount_plan(FNAME, STAGE, SRC, PIDS))

    def test_apex_certs_copied_before_ours(self):
        """少拷这一步，挂上去等于把系统 120 张根证书全弄丢。"""
        prep = self._plan()["prepare"]
        self.assertIn(f"cp -a {APEX}/. {STAGE}/", prep)
        self.assertLess(prep.index("cp -a"), prep.index(f"cp {SRC}"))

    def test_perm_keeps_dir_traversable(self):
        """`chmod -R 644` 会把目录自己的 x 位也抹掉，root 都进不去——
        然后挂载"成功"、证书却读不到。"""
        perm = self._plan()["perm"]
        self.assertNotIn("chmod -R 644", perm)
        self.assertIn(f"chmod 755 {STAGE}", perm)
        self.assertIn(f"chmod 644 {STAGE}/*", perm)

    def test_selinux_context_pinned(self):
        """上下文写错会被 SELinux 挡在读之前，且错误不会回到我们这一层。"""
        self.assertIn(apex_ca.SELINUX_CTX, self._plan()["perm"])

    def test_prepare_before_mounts(self):
        labels = [label for label, _ in apex_ca.mount_plan(FNAME, STAGE, SRC, PIDS)]
        self.assertLess(labels.index("prepare"), labels.index("mount_shell"))
        self.assertLess(labels.index("perm"), labels.index("mount_shell"))


class InstallBehaviorTest(unittest.TestCase):
    def _install(self, **kw):
        run, calls = fake_adb(**kw)
        with mock.patch.object(apex_ca, "adb", run):
            return apex_ca.install(FNAME, SRC), calls

    def test_success_requires_zygote_namespace_visibility(self):
        res, _ = self._install()
        self.assertTrue(res["mounted"])
        self.assertIsNone(res["error"])
        self.assertEqual(res["zygote_visible"], {"zygote64": True,
                                                 "webview_zygote": True})

    def test_shell_success_but_zygote_invisible_is_failure(self):
        """**实机上踩过的正是这个假象**：挂载命令全部返回成功、shell 里数得出证书，
        zygote 命名空间里却没有——应用依然 `certificate unknown`。
        判定必须以 zygote 命名空间为准，不能以命令退出码为准。"""
        res, _ = self._install(invisible=("476",))
        self.assertFalse(res["mounted"])
        self.assertFalse(res["zygote_visible"]["zygote64"])
        self.assertIsNotNone(res["error"])

    def test_refuses_to_report_success_without_zygote(self):
        """一个 zygote 都找不到时，只挂 shell 命名空间等于没挂。
        这时报成功，会把整条抓包链路变成一个查不出的假象。"""
        res, _ = self._install(zygotes={})
        self.assertFalse(res["mounted"])
        self.assertIn("zygote", res["error"])

    def test_not_needed_on_old_android_is_not_a_failure(self):
        """Android < 14 没有这个 APEX——是**不适用**，不是失败。"""
        res, _ = self._install(apex_present=False)
        self.assertFalse(res["needed"])
        self.assertTrue(res["mounted"])
        self.assertIsNone(res["error"])

    def test_failed_step_names_itself(self):
        """半途失败必须指出是哪一步：只报"失败"的话，重跑也不知道从哪接。"""
        res, _ = self._install(fail_on="chcon")
        self.assertFalse(res["mounted"])
        self.assertIn("perm", res["error"])


class DeviceReachabilityTest(unittest.TestCase):
    """实测踩过（2026-10-15）：无设备时 `adb shell` 同样返回非 0，被读成
    "Android < 14 无需这一步"并**报成功**——把"没测到"落成"不用测"，
    正是三态红线禁止的那类假结论。"""

    def _install(self, **kw):
        run, calls = fake_adb(**kw)
        with mock.patch.object(apex_ca, "adb", run):
            return apex_ca.install(FNAME, SRC), calls

    def test_unreachable_device_is_failure_not_not_needed(self):
        """adbd 都够不着时：既不能当"不适用"报成功，也不能静默过去。"""
        res, _ = self._install(state="")
        self.assertFalse(res["needed"])
        self.assertFalse(res["mounted"])
        self.assertIsNotNone(res["error"])

    def test_offline_device_is_failure(self):
        """设备 offline 时 `adb shell` 全挂——同样必须失败，不是"没有 APEX"。"""
        res, _ = self._install(state="offline")
        self.assertFalse(res["mounted"])
        self.assertIn("设备不可用", res["error"])

    def test_status_without_device_does_not_claim_absent_apex(self):
        """status 在无设备时不得给出 apex_present=false——那是"没测到"。"""
        run, _ = fake_adb(state="offline")
        with mock.patch.object(apex_ca, "adb", run):
            out = apex_ca.status(FNAME)
        self.assertIn("offline", out.get("device_state", ""))
        self.assertNotIn("apex_present", out)


class ModuleDocTest(unittest.TestCase):
    def test_keeps_the_silent_failure_explained(self):
        """这两条结论是实测推理出来的、且违反直觉（shell 里看得见≠应用看得见；
        删目录比不装更糟），删掉注释下一个人会重新踩一遍。"""
        doc = (HERE / "apex_ca.py").read_text(encoding="utf-8")
        self.assertIn("nsenter", doc)
        self.assertIn("certificate unknown", doc)
        self.assertIn("空", doc)


if __name__ == "__main__":
    unittest.main(verbosity=2)
