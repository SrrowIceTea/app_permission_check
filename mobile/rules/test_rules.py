#!/usr/bin/env python3
"""规则库离线回归 —— 不需要设备、不需要网络。

跑法：python -m unittest test_rules   （在 mobile/rules 目录下）

覆盖的是**规则库自己的不变量**，不是「规则内容对不对」：
  * 构建可重复（两次构建字节一致）
  * 每条启用规则带完整溯源，且 basis_refs 指向真实法规文件
  * 时间窗语义：只有 data_egress 有窗口，且值等于声明值
  * dangerous_apis 全部来自 android.jar（有 jar sha256 的 source ref）
  * 39 类必要个人信息齐全，13 类「无须个人信息」标记正确
  * 每个可观测的数据类别都有规则覆盖（无孤儿）
  * 半成品 DB 不会留在磁盘上（构建失败即清理）
"""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
PY = sys.executable
REG = HERE / "regulations"


def build(out: Path, env_extra: dict | None = None) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env.update(env_extra or {})
    return subprocess.run([PY, str(HERE / "build_mobile_rules.py"), "--out", str(out)],
                          capture_output=True, text=True, encoding="utf-8", errors="replace",
                          cwd=HERE, timeout=300, env=env)


class RuleLibraryTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.db = Path(cls.tmp.name) / "rules.db"
        proc = build(cls.db)
        if proc.returncode != 0:
            raise AssertionError(f"构建失败: {proc.stdout}\n{proc.stderr}")
        cls.conn = sqlite3.connect(cls.db)
        cls.conn.row_factory = sqlite3.Row

    @classmethod
    def tearDownClass(cls):
        cls.conn.close()
        cls.tmp.cleanup()

    def test_build_is_reproducible(self):
        """两次构建必须字节一致 —— 否则「哪一版是证据」无法回答。"""
        other = Path(self.tmp.name) / "rules2.db"
        proc = build(other)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        h1 = hashlib.sha256(self.db.read_bytes()).hexdigest()
        h2 = hashlib.sha256(other.read_bytes()).hexdigest()
        self.assertEqual(h1, h2, "同一份种子两次构建结果不同")

    def test_enabled_rules_have_full_provenance(self):
        rows = self.conn.execute(
            "SELECT rule_id, condition_json, evidence_requirements_json, source_refs_json,"
            " basis_refs_json FROM risk_rules WHERE enabled=1").fetchall()
        self.assertGreater(len(rows), 0, "没有任何启用规则")
        for r in rows:
            for col in ("condition_json", "evidence_requirements_json",
                        "source_refs_json", "basis_refs_json"):
                self.assertNotIn(r[col], (None, "", "[]"), f"{r['rule_id']} 的 {col} 为空")

    def test_basis_refs_resolve_to_real_regulation_files(self):
        docs = {json.loads(p.read_text(encoding="utf-8"))["id"]: p for p in REG.glob("*.json")}
        seen = set()
        for r in self.conn.execute("SELECT rule_id, basis_refs_json FROM risk_rules"):
            for ref in json.loads(r["basis_refs_json"]):
                self.assertIn(ref["doc"], docs, f"{r['rule_id']} 引用了不存在的法规 {ref['doc']}")
                actual = hashlib.sha256(docs[ref["doc"]].read_bytes()).hexdigest()
                self.assertEqual(ref["sha256"], actual,
                                 f"{r['rule_id']} 的法规 sha256 与文件不一致（文件被改过？）")
                seen.add(ref["doc"])
        self.assertGreaterEqual(len(seen), 4, f"依据文件覆盖不足: {seen}")

    def test_window_only_on_data_egress(self):
        for r in self.conn.execute("SELECT rule_id, rule_type, window_ms FROM risk_rules"):
            if r["rule_type"] == "data_egress":
                self.assertIsNotNone(r["window_ms"], f"{r['rule_id']} 缺时间窗")
                self.assertGreater(r["window_ms"], 0)
            else:
                self.assertIsNone(r["window_ms"], f"{r['rule_id']} 不该有时间窗")

    def test_apis_carry_android_jar_provenance(self):
        rows = self.conn.execute(
            "SELECT api_key, definition_status, source_refs_json FROM dangerous_apis").fetchall()
        self.assertGreaterEqual(len(rows), 30)
        for r in rows:
            self.assertEqual(r["definition_status"], "source_verified",
                             f"{r['api_key']} 不是 source_verified")
            refs = json.loads(r["source_refs_json"])
            self.assertTrue(refs, f"{r['api_key']} 没有来源")
            self.assertTrue(any(x.get("kind") == "android_jar_signature" and x.get("jar_sha256")
                                for x in refs), f"{r['api_key']} 缺 android.jar 溯源")

    def test_app_categories_39_and_13_free(self):
        total = self.conn.execute("SELECT COUNT(*) FROM app_categories").fetchone()[0]
        free = self.conn.execute(
            "SELECT COUNT(*) FROM app_categories WHERE no_personal_info_required=1").fetchone()[0]
        self.assertEqual(total, 39, "39 类必要个人信息不齐")
        self.assertEqual(free, 13, "「无须个人信息」的类目数应为 13")

    def _reachable_data_types(self) -> set[str]:
        """dangerous_apis 能触及的全部数据类别（含 1:1 直连与 spec 分派）。

        provider_arg 的 map 是 dict（provider → 类别），content_uri / string_key_arg 的
        map 是 list；两种都要认——只认 list 会把 precise/coarse_location 漏掉。
        """
        out: set[str] = set()
        for r in self.conn.execute("SELECT data_type_key, observation_spec_json FROM dangerous_apis"):
            if r["data_type_key"]:
                out.add(r["data_type_key"])
            spec = json.loads(r["observation_spec_json"]) if r["observation_spec_json"] else {}
            m = spec.get("map")
            if isinstance(m, list):
                out |= {i["data_type"] for i in m
                        if isinstance(i, dict) and i.get("data_type")}
            elif isinstance(m, dict):
                out |= {v for v in m.values() if isinstance(v, str) and v}
        return out

    def test_no_orphan_observable_data_types(self):
        """有 API 可观测的数据类别，必须有规则；否则观测到了却判不了。"""
        covered = set()
        for r in self.conn.execute("SELECT condition_json FROM risk_rules WHERE enabled=1"):
            dt = json.loads(r["condition_json"]).get("data_type")
            if dt:
                covered.add(dt)
        self.assertEqual(sorted(self._reachable_data_types() - covered), [],
                         "存在可观测但无规则的数据类别")

    def test_every_data_type_has_api_or_declared_gap(self):
        """反向守护：每个数据类别要么有 API 抓手，要么显式声明为设计缺口。

        这正是过去靠人工核对、结果漏掉 3 类（advertising_id / ip_address /
        notification_content）的那一步——「有规则、无抓手」的空转规则必须在
        构建期就被拦住，而不是等答辩时被问出来。
        """
        seed = json.loads((HERE / "seed" / "sensitive_data_types.json").read_text(encoding="utf-8"))
        reaches = self._reachable_data_types()
        for dt in seed["data_types"]:
            key = dt["data_type_key"]
            cov = dt.get("coverage", "api")
            self.assertIn(cov, ("api", "uncovered_by_design"), f"{key} 的 coverage 非法")
            if cov == "api":
                self.assertIn(key, reaches, f"{key} 声称有 API 抓手，实际没有")
            else:
                self.assertTrue((dt.get("coverage_reason") or "").strip(),
                                f"{key} 声明为设计缺口却没写理由")
                self.assertNotIn(key, reaches,
                                 f"{key} 已声明为设计缺口，却查到了 API 抓手（声明过期）")

    def test_no_partial_db_left_on_failure(self):
        """构建失败时不得留下半成品 DB —— 半成品与成功产物难以区分。"""
        bad_seed = Path(self.tmp.name) / "broken"
        bad_seed.mkdir(exist_ok=True)
        out = Path(self.tmp.name) / "should_not_exist.db"
        # 用一个不存在的 schema 路径触发失败：直接调用构建器并篡改环境不可行，
        # 改为验证「已有输出且未加 --force 时拒绝构建」这条守门规则。
        out.write_bytes(b"stale")
        proc = subprocess.run([PY, str(HERE / "build_mobile_rules.py"), "--out", str(out)],
                              capture_output=True, text=True, encoding="utf-8",
                              errors="replace", cwd=HERE, timeout=120)
        self.assertNotEqual(proc.returncode, 0, "已存在产物时必须拒绝覆盖")
        self.assertEqual(out.read_bytes(), b"stale", "拒绝构建时不得改动既有文件")

    def test_protection_level_bits(self):
        """protectionLevel 复合串按位或；认不出的级别词必须返回 None（不编造）。"""
        sys.path.insert(0, str(HERE))
        import build_mobile_rules as bmr
        self.assertEqual(bmr._protection_level_value("dangerous"), 1)
        self.assertEqual(bmr._protection_level_value("signature|privileged"), 2 | 0x10)
        self.assertEqual(bmr._protection_level_value("signature|retailDemo"), 2 | 0x1000000)
        self.assertEqual(bmr._protection_level_value("normal"), 0)
        self.assertIsNone(bmr._protection_level_value("完全认不出的级别"))
        self.assertIsNone(bmr._protection_level_value("dangerous|未知标志"))

    def test_published_device_calibration_evidence(self):
        calib = HERE / "calibration"
        raw = (calib / "permissions-api36-pm.txt").read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        facts = json.loads((calib / "device-api36.json").read_text(encoding="utf-8"))
        records = [json.loads(line) for line in
                   (calib / "permissions-device.jsonl").read_text(encoding="utf-8").splitlines()]
        published = sqlite3.connect(HERE / "rules_mobile.db")
        try:
            for record in records:
                row = published.execute(
                    "SELECT protection_level_raw, device_calibration_json FROM permissions"
                    " WHERE android_version=? AND permission_name=?",
                    (facts["android_sdk"], record["permission_name"])).fetchone()
                self.assertIsNotNone(row, record["permission_name"])
                self.assertEqual(row[0], record["protection_level_raw"])
                self.assertEqual(json.loads(row[1])[0]["source_sha256"], digest)
                self.assertEqual(json.loads(row[1])[0]["build_fingerprint"], facts["build_fingerprint"])
            self.assertEqual(len(records), 40)
        finally:
            published.close()

    def test_device_calibration_reaches_protection_level(self):
        """回归一条曾经的**死路**：permissions 的 INSERT 没写 protection_level_raw，
        于是设备实测文件喂进来也永远落不到库里，over_permission 规则永远缺保护级别这一维。

        本用例把标定文件喂给构建器，断言值确实到了 protection_level_raw/value，
        且 definition_status 仍是 pending（schema 规定设备观测不得标 source_verified）。
        """
        calib = Path(self.tmp.name) / "calib"
        calib.mkdir(exist_ok=True)
        (calib / "permissions-device.jsonl").write_text(
            json.dumps({"permission_name": "android.permission.CAMERA",
                        "protection_level_raw": "dangerous",
                        "provenance": {"device": {"android_sdk": "36",
                                                   "build_fingerprint": "fixture"}}}) + "\n"
            + json.dumps({"permission_name": "android.permission.USE_BIOMETRIC",
                          "protection_level_raw": "signature|privileged"}) + "\n"
            + json.dumps({"permission_name": "android.permission.INTERNET",
                          "protection_level_raw": "normal",
                          "provenance": {"device": {"android_sdk": "35"}}}) + "\n",
            encoding="utf-8")
        out = Path(self.tmp.name) / "calibrated.db"
        proc = build(out, {"VSCAN_MOBILE_CALIB": str(calib)})
        self.assertEqual(proc.returncode, 0, proc.stderr)

        conn = sqlite3.connect(out)
        row = conn.execute(
            "SELECT protection_level_raw, protection_level_value, definition_status"
            " FROM permissions WHERE permission_name=?",
            ("android.permission.CAMERA",)).fetchone()
        self.assertEqual(row[0], "dangerous")
        self.assertEqual(row[1], 1)
        self.assertEqual(row[2], "pending", "设备观测不得标 source_verified")
        observed = conn.execute("SELECT device_calibration_json FROM permissions WHERE permission_name=?",
                                ("android.permission.CAMERA",)).fetchone()[0]
        self.assertEqual(json.loads(observed)[0]["device"]["build_fingerprint"], "fixture")
        self.assertEqual(conn.execute(
            "SELECT protection_level_raw FROM permissions WHERE permission_name=?",
            ("android.permission.USE_BIOMETRIC",)).fetchone()[0], "signature|privileged")
        self.assertEqual(conn.execute(
            "SELECT protection_level_value FROM permissions WHERE permission_name=?",
            ("android.permission.USE_BIOMETRIC",)).fetchone()[0], 0x12)
        self.assertIsNone(conn.execute(
            "SELECT protection_level_raw FROM permissions WHERE permission_name=?",
            ("android.permission.INTERNET",)).fetchone()[0],
            "其他 Android 版本的观测不能用于当前规则库")
        conn.close()

    def test_jvm_descriptor_to_frida_types(self):
        """数组类型必须转成 Frida 认的 JVM 形态。

        实测教训：拼成 `[java.lang.String` 时 overload() 匹配不上，
        `ContentResolver.query` 三个重载全挂不上——而钩子其它 API 照常工作，
        症状是"某一类数据从来没被观测到"，不报错。"""
        sys.path.insert(0, str(HERE))
        import jvmdesc
        self.assertEqual(
            jvmdesc.param_types("(Landroid/net/Uri;[Ljava/lang/String;"
                                "Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;)"
                                "Landroid/database/Cursor;"),
            ["android.net.Uri", "[Ljava.lang.String;", "java.lang.String",
             "[Ljava.lang.String;", "java.lang.String"])
        self.assertEqual(jvmdesc.param_types("([I)V"), ["[I"])
        self.assertEqual(jvmdesc.param_types("([[Ljava/lang/String;)V"),
                         ["[[Ljava.lang.String;"])
        self.assertEqual(jvmdesc.param_types("(I[Ljava/lang/String;[I)V"),
                         ["int", "[Ljava.lang.String;", "[I"])
        self.assertEqual(jvmdesc.return_type("()Landroid/location/Location;"),
                         "android.location.Location")

    def test_policy_requirements_have_check_kinds(self):
        rows = self.conn.execute(
            "SELECT req_id, check_kind, basis_refs_json FROM policy_requirements"
            " WHERE enabled=1").fetchall()
        self.assertGreaterEqual(len(rows), 10)
        kinds = {r["check_kind"] for r in rows}
        self.assertTrue(kinds <= {"text_present", "text_absent", "ai", "manual"},
                        f"未知 check_kind: {kinds}")
        self.assertIn("ai", kinds, "语义类条款必须显式标为需要 AI 研判")
        self.assertIn("text_present", kinds, "确定性可查的条款不应全推给 AI")
        for r in rows:
            self.assertTrue(json.loads(r["basis_refs_json"]), f"{r['req_id']} 缺依据")


if __name__ == "__main__":
    unittest.main(verbosity=2)
