#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""离线回归：**结论引用的到底是哪条事件**。

从 `test_codeloc.py` 拆出来（2026-09-28，原文超过 300 行上限）。这些用例测的不是
"怎么把栈解析成代码位置"，而是 `attach` 之前那一步——按编号/按时间挑事件。它自己
藏着两类静默出错：撞号覆盖（钩子与代理的编号都从 1 重来）与候选漂移
（Phase 4 排除失败连接、codeloc 没有）。两者都会让结论挂到别的事件上，
而 dex 核对照样通过。

需要设备/Frida 吗？不需要——全部用实测栈的文本副本驱动。
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from core.evidence import codeloc  # noqa: E402

A = "com.vscanner.targetapp"

# 实测栈（phase3/logs/cap_vhal.jsonl，GEAR_SELECTION 那次读取）。
VHAL_STACK = "\n".join([
    "dalvik.system.VMStack.getThreadStackTrace(Native Method)",
    "java.lang.Thread.getStackTrace(Thread.java:1946)",
    "android.car.hardware.property.CarPropertyManager.getProperty(Native Method)",
    f"{A}.VhalReader.readOne(VhalReader.kt:128)",
    f"{A}.VhalReader.readAll(VhalReader.kt:105)",
    f"{A}.MainActivity.doRead$lambda$9(MainActivity.kt:118)",
    f"{A}.MainActivity.$r8$lambda$QaUb4dwx378mAQV5JYf1oDfmltE(Unknown Source:0)",
    f"{A}.MainActivity$$ExternalSyntheticLambda6.invoke(D8$$SyntheticClass:0)",
    "kotlin.concurrent.ThreadsKt$thread$thread$1.run(Thread.kt:30)",
])

# 实测栈（hook_egress.js 修好截断之后的目标形状：应用帧单列）。
EGRESS_APP_FRAMES = [
    f"{A}.EgressSender.send(EgressSender.kt:64)",
    f"{A}.MainActivity.doEgress$lambda$12(MainActivity.kt:141)",
]


def egress(evt_id: int, ts: int, line: int, **extra) -> dict:
    """一条出站连接事件，`app_frames` 指向 `line` 行。"""
    return {"ev": "EGRESS_CONNECT", "evt_id": evt_id, "package": A,
            "host_received_ts": ts, "app_frames": [f"{A}.Egress.send(Egress.kt:{line})"],
            **extra}


def pair_finding(read_id=9, flow_id=1) -> dict:
    return {"rule_id": "VSC-E003", "evidence_kind": "read_then_egress",
            "pairs": [{"read_event_id": read_id, "flow_event_id": flow_id}]}


class DuplicateEventIdTest(unittest.TestCase):
    """同一 evt_id 对应多条事件时**必须记缺口，不能挑一条**。

    钩子与代理的编号都从 1 重新开始，重挂钩子、或两次追加进同一个 JSONL 就会撞号。
    旧实现用 `{evt_id: record}` 字典推导，后一条**静默覆盖**前一条，结论于是挂到
    另一个事件的栈上——而 dex 核对照样通过，报告上完全看不出来。
    实测 `phase4/evidence/egress-multi-A.jsonl` 里 evt_id 1/2/3 各出现两次，
    且 `src` 与 `session_id` 都相同，所以复合键消解不了，只能报出来。
    """

    def test_duplicate_event_id_is_a_gap_not_a_guess(self) -> None:
        reads = [{"evt_id": 5, "src": "hook", "stack": VHAL_STACK},
                 {"evt_id": 5, "src": "hook", "stack": [f"{A}.Other.send(Other.kt:7)"]}]
        findings = [{"rule_id": "VSC-R003", "evidence_kind": "read_event", "event_ids": [5]}]
        out = codeloc.attach(findings, reads, [], [], A)
        self.assertEqual([], out[0]["code_locs"])              # 不挑、不猜
        gaps = out[0]["code_loc_gaps"]
        self.assertEqual(1, len(gaps))
        self.assertIn("evt_id=5", gaps[0]["reason"])
        self.assertIn("2 条记录", gaps[0]["reason"])
        self.assertIn("src=hook", gaps[0]["reason"])           # 能看出是钩子侧撞号
        # 不能说"事件里没有应用侧栈帧"——事件有栈，只是不知道该用哪一条
        self.assertNotIn("没有应用侧栈帧", out[0]["code_loc_note"])
        self.assertIn("歧义", out[0]["code_loc_note"])

    def test_unique_event_id_still_resolves(self) -> None:
        """撞号检测不能把正常情况也变成缺口。"""
        reads = [{"evt_id": 5, "src": "hook", "stack": VHAL_STACK},
                 {"evt_id": 6, "src": "hook", "stack": VHAL_STACK}]
        findings = [{"rule_id": "VSC-R003", "evidence_kind": "read_event", "event_ids": [6]}]
        out = codeloc.attach(findings, reads, [], [], A)
        self.assertEqual(out[0]["code_locs"][0]["line"], 128)
        self.assertNotIn("code_loc_gaps", out[0])

    def test_src_ref_resolves_the_collision(self) -> None:
        """带 `src` 的引用能唯一定位——这是撞号的**正路**，不是猜。

        实测形态：reads.jsonl 里 privacy 与 native_ssl 各自从 1 编号，evt_id=13 有两条。
        只给编号只能报歧义；给 `{src: privacy, evt_id: 13}` 就能取到确定的那一条。
        """
        reads = [{"evt_id": 13, "src": "native_ssl", "stack": "SSL_read(Native Method)"},
                 {"evt_id": 13, "src": "privacy", "stack": VHAL_STACK}]
        findings = [{"rule_id": "MOB-R006", "evidence_kind": "read_event", "event_ids": [13],
                     "event_refs": [{"src": "privacy", "evt_id": 13}]}]
        out = codeloc.attach(findings, reads, [], [], A)
        self.assertEqual(out[0]["code_locs"][0]["line"], 128)
        self.assertNotIn("code_loc_gaps", out[0])

    def test_ref_to_missing_src_is_not_guessed(self) -> None:
        """引用说 src=privacy，但记录里没有这个 src → 报缺口，绝不借用别人的栈。"""
        reads = [{"evt_id": 13, "src": "native_ssl", "stack": VHAL_STACK}]
        findings = [{"rule_id": "MOB-R006", "evidence_kind": "read_event", "event_ids": [13],
                     "event_refs": [{"src": "privacy", "evt_id": 13}]}]
        out = codeloc.attach(findings, reads, [], [], A)
        self.assertEqual([], out[0]["code_locs"])
        self.assertIn("native_ssl", out[0]["code_loc_gaps"][0]["reason"])


class FailedConnectionTest(unittest.TestCase):
    """失败连接不能拿来定位外发代码位置——即使它在时间上离流更近。

    实测漂移：Phase 4 的归因排除 `outcome=error`（D408），codeloc 只比包名 + 时间。
    于是"流量归属正确、报告里的代码位置却来自一次失败连接"，而 dex 核对照样通过。
    """

    def test_failed_connection_is_not_used_for_code_location(self) -> None:
        flows = [{"evt_id": 1, "ts": 1_000_000}]
        out = codeloc.attach([pair_finding()], [], flows,
                             [egress(4, 1_000_050, 999, outcome="error"),
                              egress(3, 1_001_500, 64, outcome="ok")], A)
        locs = out[0]["code_locs"]
        self.assertEqual(1, len(locs))
        self.assertEqual(64, locs[0]["line"])     # 成功那条，不是更近的失败那条
        self.assertEqual(3, locs[0]["event_id"])
        self.assertNotIn("999", str(locs[0]))     # 绝不是失败连接的栈

    def test_only_failed_connections_says_so(self) -> None:
        """范围内只有失败连接时，理由必须与"根本没有连接"不同——否则是假话。"""
        out = codeloc.attach([pair_finding()], [], [{"evt_id": 1, "ts": 1_000_000}],
                             [egress(4, 1_000_050, 999, outcome="error")], A)
        self.assertEqual([], out[0]["code_locs"])
        reasons = [g["reason"] for g in out[0]["code_loc_gaps"]]
        self.assertTrue(any("失败" in r and "D408" in r for r in reasons), reasons)
        self.assertFalse(any("没有本包的出站事件" in r for r in reasons), reasons)

    def test_missing_outcome_field_is_still_eligible(self) -> None:
        """缺 `outcome` 字段的记录仍合格——历史证据和多数夹具都长这样。

        判定必须是否定式（只有 error 才排除）。改成"必须 == ok"会静默丢弃全部旧事件。
        """
        out = codeloc.attach([pair_finding()], [], [{"evt_id": 1, "ts": 1_000_000}],
                             [egress(3, 1_000_100, 64)], A)
        self.assertEqual(64, out[0]["code_locs"][0]["line"])


if __name__ == "__main__":
    unittest.main()
