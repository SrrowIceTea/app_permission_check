#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""离线守卫：验收脚本用到的钩子 bundle **必须解析得到**。

仅用于授权测试（自有设备与自有 APK）。

为什么需要这条：目录改名/抽取时，"引用没跟着改"是本项目反复出现的失败模式，
而且**离线回归全绿、真跑才炸**——2026-10-12 拆分把 `hook_egress` 与
`ssl_pinning_bypass` 移到 `core/frida_host/dist/`，移动端三处引用都改了，
唯独 `tools/device_acceptance.py` 漏了。那次的症状是 run.py 打印
`no such script` 后**空等 40 秒**等 ARMED，日志读起来像"钩子没挂上"。

这条测试不需要设备：只做"脚本里点名的钩子，文件在不在"。
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))

import device_acceptance as da  # noqa: E402

# 各验收脚本实际会启动的钩子（改脚本时同步这里；对不上就是本测试该报的）
DEVICE_ACCEPTANCE_HOOKS = ['hook_vhal', 'hook_egress', 'ssl_pinning_bypass']
GADGET_ACCEPTANCE_HOOKS = ['hook_vhal']
MULTI_ACCEPTANCE_HOOKS = ['fixture_control']


class HookBundleResolutionTest(unittest.TestCase):
    def test_device_acceptance_hooks_resolve(self):
        for script in DEVICE_ACCEPTANCE_HOOKS:
            with self.subTest(script=script):
                path = da.hook_bundle(script)      # 找不到会 SystemExit（响亮失败）
                self.assertTrue(path.exists(), f'{script} 解析到不存在的路径：{path}')

    def test_gadget_and_multi_hooks_resolve(self):
        for script in GADGET_ACCEPTANCE_HOOKS + MULTI_ACCEPTANCE_HOOKS:
            with self.subTest(script=script):
                self.assertTrue(da.hook_bundle(script).exists())

    def test_missing_hook_fails_loudly_with_both_dirs(self):
        """找不到时要**列出找过的目录**。只报"找不到"会让人不知道去哪补。"""
        with self.assertRaises(SystemExit) as cm:
            da.hook_bundle('不存在的钩子')
        msg = str(cm.exception)
        for base in da.HOOK_BUNDLE_DIRS:
            self.assertIn(str(base), msg)

    def test_manifest_covers_bundles_outside_vehicle(self):
        """session-manifest 的 hook_bundles 是"这批证据由哪个 bundle 产生"的凭据。
        只扫 vehicle/ 会静默漏掉移到 core 的那两个，证据链断在那里且不报错。"""
        found = {p.name for base in da.HOOK_BUNDLE_DIRS
                 for p in base.glob('*.bundle.js')}
        for script in DEVICE_ACCEPTANCE_HOOKS:
            self.assertIn(f'{script}.bundle.js', found,
                          f'{script}.bundle.js 不在 manifest 的扫描范围内')

    def test_shared_bundles_live_in_core(self):
        """共享的那两个应当在 core（移动端也在用）。放回 vehicle 会让移动端
        再次反向依赖 vehicle——那正是这次拆分要斩断的。"""
        self.assertTrue((ROOT / 'core/frida_host/dist/hook_egress.bundle.js').exists())
        self.assertTrue((ROOT / 'core/frida_host/dist/ssl_pinning_bypass.bundle.js').exists())


if __name__ == '__main__':
    unittest.main(verbosity=2)
