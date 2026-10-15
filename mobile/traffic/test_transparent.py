#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""强制抓包链路的离线回归（不需要设备）。

跑法：python -m unittest test_transparent   （在 mobile/traffic 目录下）

这里钉住的是**会静默失败的**那几处：
  * 系统 CA 的文件名算法（名字错了系统直接忽略，表现是"装了但 HTTPS 照样失败"）
  * 启动参数必须真的带上 `-http-proxy`（漏了就是"应用绕过了代理"，而报告只会说没有 flows）
  * iptables 规则必须按 uid 限定（不限就把系统流量一起劫走）+ 必须带前置条件说明
"""
from __future__ import annotations

import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import transparent as tp  # noqa: E402


def make_cert(tmp: Path):
    """生成一张自签证书，用来验证命名算法（不依赖用户机器上的任何文件）。"""
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
    except ImportError:  # pragma: no cover
        return None
    import datetime
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "vscan-test-ca")])
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow() - datetime.timedelta(days=1))
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=30))
            .sign(key, hashes.SHA256()))
    p = tmp / "test-ca.pem"
    p.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return p


class CaNamingTest(unittest.TestCase):
    def test_name_is_subject_hash_old_with_dot_zero_suffix(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            pem = make_cert(Path(td))
            if pem is None:
                self.skipTest("cryptography 未安装")
            hash_hex, fname = tp.android_ca_name(pem)
            self.assertRegex(hash_hex, r"^[0-9a-f]{8}$")
            self.assertEqual(fname, hash_hex + ".0")

    def test_name_is_deterministic(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            pem = make_cert(Path(td))
            if pem is None:
                self.skipTest("cryptography 未安装")
            self.assertEqual(tp.android_ca_name(pem)[1], tp.android_ca_name(pem)[1])

    def test_matches_known_android_convention(self):
        """**已用真实设备反验**：拿 3 张设备系统证书算，文件名 3/3 一致。
        这里用同样的算法口径做一次自检，防止将来改成新式 SHA-1 哈希
        （Android 用的是 old=MD5 那套，换了名字系统会静默忽略证书）。"""
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            pem = make_cert(Path(td))
            if pem is None:
                self.skipTest("cryptography 未安装")
            from cryptography import x509
            import hashlib
            cert = x509.load_pem_x509_certificate(pem.read_bytes())
            expected = f"{int.from_bytes(hashlib.md5(cert.subject.public_bytes()).digest()[:4], 'little'):08x}.0"
            self.assertEqual(tp.android_ca_name(pem)[1], expected)


class EmulatorArgsTest(unittest.TestCase):
    def test_capture_args_include_http_proxy(self):
        args = tp.emulator_capture_args(port=8888, host="10.0.2.2")
        self.assertIn("-http-proxy", args)
        self.assertIn("http://10.0.2.2:8888", args)

    def test_writable_system_flag_present_by_default(self):
        """没有 -writable-system 就 remount 不了，系统 CA 装不进去——
        而失败发生在设备侧，看起来像"CA 装了但没生效"。"""
        self.assertIn("-writable-system", tp.emulator_capture_args())

    def test_can_skip_writable_system(self):
        self.assertNotIn("-writable-system",
                         tp.emulator_capture_args(writable_system=False))

    def test_no_snapshot_load_for_first_run_state(self):
        """抓包要的是**首次运行**行为；带快照恢复会把上一次的数据状态带进来。"""
        self.assertIn("-no-snapshot-load", tp.emulator_capture_args())


class IptablesRuleTest(unittest.TestCase):
    def test_rules_scoped_to_uid(self):
        """**必须按 uid 限定**：不限就把系统流量一起劫走，整台设备的网络都断。"""
        r = tp.iptables_rules(10234)
        for key in ("check", "add", "del"):
            self.assertIn("--uid-owner", r[key])
            self.assertIn("10234", r[key])
            self.assertIn("REDIRECT", r[key])

    def test_add_and_del_are_symmetric(self):
        r = tp.iptables_rules(10234)
        self.assertEqual(r["add"][:2], ["iptables", "-t"])
        self.assertIn("-A", r["add"])
        self.assertIn("-D", r["del"])
        # 除 -A/-D 外必须逐字一致，否则删不掉自己加的规则
        self.assertEqual([x for x in r["add"] if x != "-A"],
                         [x for x in r["del"] if x != "-D"])

    def test_carries_precondition_warning(self):
        """规则本身**在宿主机代理布局下无效**，必须随规则一起说明，
        否则有人会照抄然后困惑"为什么流量还是没进来"。"""
        r = tp.iptables_rules(10234)
        self.assertIn("设备本机", r["precondition"])
        self.assertIn("SO_ORIGINAL_DST", r["precondition"])


class ApexWiringTest(unittest.TestCase):
    """Android 14+ 上最容易出的一种假象：`/system/etc/security/cacerts` 写好了、
    `ls` 也有那张证书，但应用只读 APEX 那份，所以照样 `certificate unknown`。
    这里钉住：APEX 那一层没挂上时，install_system_ca() 必须报**失败**。"""

    def _install_with(self, apex_result: dict, tmp: Path) -> dict:
        pem = make_cert(tmp)
        if pem is None:
            self.skipTest("cryptography 未安装")
        ok0 = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
        with mock.patch.object(tp, "adb", lambda *a, **k: ok0), \
                mock.patch.object(tp, "ca_installed", lambda *a, **k: (True, "x.0")), \
                mock.patch.object(tp.apex_ca, "install", lambda *a, **k: apex_result):
            return tp.install_system_ca(pem)

    def test_apex_not_mounted_marks_install_failed(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            res = self._install_with({"mounted": False, "error": "半成品"}, Path(td))
        self.assertFalse(res["installed"])
        self.assertIn("APEX", res["error"])
        self.assertIn("apex", res)

    def test_apex_mounted_keeps_install_ok(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            res = self._install_with({"mounted": True, "error": None}, Path(td))
        self.assertTrue(res["installed"])
        self.assertIsNone(res["error"])


class ModuleDocTest(unittest.TestCase):
    def test_module_explains_why_not_iptables(self):
        """这条结论是实测推理出来的，写在模块开头；删掉它就只剩一个"为什么不用 iptables"
        的空白，下一个人会重新踩一遍。"""
        doc = (HERE / "transparent.py").read_text(encoding="utf-8")
        self.assertIn("SO_ORIGINAL_DST", doc)
        self.assertIn("-http-proxy", doc)
        # Android 14+ 那一层：应用只读 APEX 那份信任库，往 /system 写等于白写。
        self.assertIn("/apex/com.android.conscrypt/cacerts", doc)
        self.assertIn("nsenter", doc)


if __name__ == "__main__":
    unittest.main(verbosity=2)
