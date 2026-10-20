#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""`explore()` 的**跨分段状态**守卫（2026-10-20）。

仅用于授权测试（自有设备 / 已授权的公开第三方样本）。

为什么必须钉住：`device_run_thirdparty` 是按 `--segment-chunk`（默认 10 秒）
**多次**调用 `explore()` 的——分段是为了每 10 秒判一次应用是否还活着，不是重开探索。
原实现把 `tapped` / `stale` / `scrolls` 都放在 `explore()` 的局部变量里，每次调用
清零，于是同一两个按钮被反复点。`ds60-sup-1019` 前 40 个样本的实测：

    326 次点击 / 平均 3.0 个不同目标
    40-timer-other      Next→Add / START STEP→More timer settings 各连点 5 轮
    35-kerballone       Settings→Screening 连点 5 轮

**这类错误不会让任何检查项变红**：taps 照样统计、`ui_taps_made` 照样通过、
报告里"交互了 N 次"也照样印出来——只是探索原地打转，应用永远走不到联网界面。
所以只能靠离线断言把它钉死。

第二个守卫是**轮次号必须全局**：每次调用从 0 开始时 `ui-00-before.xml` 会被下一段
覆盖（实测 38-paroj-dsub2000 点了 5 次只留下 1 组 XML），证据链断在文件名上。
"""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT))

import thirdparty_ui_flow as flow  # noqa: E402
import ui_trigger as ui            # noqa: E402

PKG = "com.example.probe"
ACT = ".MainActivity"


def node(bounds, text="", rid="", clickable=True) -> str:
    return (f'<node class="android.widget.Button" text="{text}" resource-id="{rid}" '
            f'content-desc="" clickable="{"true" if clickable else "false"}" '
            f'enabled="true" bounds="{bounds}"/>')


class FakeScreen:
    """一块"点了会变、但不跳转"的界面：每次点击后多一个文本节点。

    只变一点点是刻意的：真实设备上点按钮后界面**会**变（Toast/计数/选中态），
    而 `explore()` 的 stale 判定正是比 dump 文本。若界面完全不变，第 2 轮就会走
    stale 恢复分支，测的就不是"点过什么"了。
    """

    def __init__(self, labels):
        self.labels = list(labels)
        self.taps: list[str] = []

    def xml(self) -> str:
        body = "".join(node(f"[80,{200 + i * 200}][1000,{320 + i * 200}]", text=t, rid=f"id/{t}")
                       for i, t in enumerate(self.labels))
        # 每次点击后多一行——让 dump 文本随点击变化，绕开 stale 判定。
        body += node("[0,2200][1080,2300]", text=f"clicks={len(self.taps)}", clickable=False)
        return f'<hierarchy rotation="0">{body}</hierarchy>'

    def dump(self, out=None, retries: int = 3) -> str:
        text = self.xml()
        if out is not None:
            Path(out).write_text(text, encoding="utf-8")
        return text

    def tap(self, target: dict, timeout: int = 30) -> None:
        self.taps.append(target.get("text") or "")


class ExploreStateTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.out = Path(self.tmp.name)
        self.screen = FakeScreen(("Next", "Add", "Settings", "About"))
        self.adb_calls: list[tuple] = []

        def fake_adb(*args, timeout=60, **_kw):
            self.adb_calls.append(args)
            return mock.Mock(stdout="", stderr="", returncode=0)

        patcher = mock.patch.multiple(
            flow.ui,
            dump=self.screen.dump,
            tap=self.screen.tap,
            foreground_package=lambda: PKG,
            foreground=lambda: f"{PKG}/{ACT}",
            handle_dialog=lambda evidence=None: (False, ""),
            dismiss_foreign_overlay=lambda pkg, evidence=None: (True, "noop"),
            screen_size=lambda: (1080, 2400),
            swipe_back_to_top=lambda evidence=None, steps=3: None,
        )
        patcher.start()
        self.addCleanup(patcher.stop)
        adb_patcher = mock.patch.object(flow.env, "adb", fake_adb)
        adb_patcher.start()
        self.addCleanup(adb_patcher.stop)
        sleep_patcher = mock.patch("time.sleep")
        sleep_patcher.start()
        self.addCleanup(sleep_patcher.stop)

    def tearDown(self):
        self.tmp.cleanup()

    def test_state_survives_across_segment_calls(self):
        """两次 10 秒分段调用 = 一次连续探索：第二次不能回头点第一次点过的按钮。"""
        state = flow.new_state()
        first = flow.explore(self.out, 10, 2, PKG, ACT, state)
        second = flow.explore(self.out, 10, 2, PKG, ACT, state)

        labels = [a["label"] for a in first + second if a["action"] == "tap"]
        self.assertEqual(4, len(labels), f"实得 {labels}")
        self.assertEqual(4, len(set(labels)), f"同一目标被重复点击：{labels}")

    def test_round_numbers_are_global_so_evidence_is_not_overwritten(self):
        """轮次号跨分段递增：4 轮的点击前/后 XML 必须都在，不能被同名覆盖。"""
        state = flow.new_state()
        flow.explore(self.out, 10, 2, PKG, ACT, state)
        flow.explore(self.out, 10, 2, PKG, ACT, state)
        for r in range(4):
            self.assertTrue((self.out / f"ui-{r:03d}-before.xml").exists(),
                            f"缺第 {r} 轮的点击前 XML（被后续分段覆盖了？）")
            self.assertTrue((self.out / f"ui-{r:03d}-after.xml").exists(),
                            f"缺第 {r} 轮的点击后 XML")
        self.assertEqual(4, state["round"], "两段各 2 轮之后，轮次号应停在 4")

    def _tapped_keys(self) -> set:
        """按 pick_candidate 的键口径（text, desc, rid, bounds）造"已点过"集合。"""
        ns = ui.nodes(self.screen.xml())
        return {(n["text"], n["desc"], n["rid"], n["bounds"]) for n in ns if n["clickable"]}

    def test_exhausted_screen_backtracks_with_back_key(self):
        """本屏候选全点过 → 按 BACK 回上一屏，而不是原地空转到窗口结束。"""
        state = flow.new_state()
        state["tapped"] = self._tapped_keys()
        state["inputs_done"] = True
        state["scrolls"] = flow.MAX_REVEAL_SCROLLS
        state["swipes_top"] = flow.MAX_SWIPE_TOP

        actions = flow.explore(self.out, 10, 2, PKG, ACT, state)
        recovers = [a.get("recover") for a in actions if a["action"] == "no_candidate"]
        self.assertIn("back", recovers, f"没有回退动作：{actions}")
        self.assertTrue(any(c[:4] == ("shell", "input", "keyevent", "4") for c in self.adb_calls),
                        f"没有发出 BACK 按键：{self.adb_calls}")
        # 只断言"退过一次"，不断言恰好 1 次：`backs` 的精确值取决于恢复链里
        # "滚动预算按屏重置"这个细节，写死会把合理重构变成假红。
        self.assertGreaterEqual(state["backs"], 1)

    def test_back_is_bounded(self):
        """BACK 有上限：不能把整轮窗口耗在"退不出去"的界面上。"""
        state = flow.new_state()
        state["tapped"] = self._tapped_keys()
        state["inputs_done"] = True
        state["scrolls"] = flow.MAX_REVEAL_SCROLLS
        state["swipes_top"] = flow.MAX_SWIPE_TOP
        state["backs"] = flow.MAX_BACKS

        actions = flow.explore(self.out, 10, 3, PKG, ACT, state)
        self.assertFalse(any(a.get("recover") == "back" for a in actions),
                         "BACK 已达上限仍继续回退——会无限空转")
        self.assertEqual("no_candidate", actions[-1]["action"])
        self.assertEqual("none", actions[-1]["recover"])

    def test_stale_screen_recovers_instead_of_breaking(self):
        """**点了没反应**（stale）比"没得点"更常见，它也必须走恢复链。

        2026-10-20 复核：真机上多数界面是"有按钮、点了界面不变"，这种情况落到 stale
        分支；而原实现 stale 只试一次滚动就 break——BACK/填输入根本进不去，
        探索在第一个死界面上就结束。本用例把"stale 必须给出 recover"钉住。
        """
        frozen = self.screen.xml()

        def frozen_dump(out=None, retries: int = 3) -> str:
            if out is not None:
                Path(out).write_text(frozen, encoding="utf-8")
            return frozen

        with mock.patch.object(flow.ui, "dump", frozen_dump):
            state = flow.new_state()
            actions = flow.explore(self.out, 10, 4, PKG, ACT, state)

        stale = [a for a in actions if a["action"] == "stale"]
        self.assertTrue(stale, f"没有触发 stale：{[a['action'] for a in actions]}")
        self.assertTrue(all(a.get("recover") not in (None, "none") for a in stale),
                        f"stale 时直接放弃了：{stale}")
        # 滚动预算仍然有上限：滚不动就不该反复滚。
        self.assertLessEqual(state["scrolls"], flow.MAX_REVEAL_SCROLLS)


if __name__ == "__main__":
    unittest.main(verbosity=2)
