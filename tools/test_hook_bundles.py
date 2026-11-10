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

import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
sys.path.insert(0, str(ROOT))

import device_acceptance as da  # noqa: E402
from core.frida_host import freshness  # noqa: E402

# 各验收脚本实际会启动的钩子（改脚本时同步这里；对不上就是本测试该报的）
DEVICE_ACCEPTANCE_HOOKS = ['hook_vhal', 'hook_egress', 'ssl_pinning_bypass', 'hook_vehicle_all']
GADGET_ACCEPTANCE_HOOKS = ['hook_vhal']
MULTI_ACCEPTANCE_HOOKS = ['fixture_control']


class HookBundleResolutionTest(unittest.TestCase):
    def test_device_acceptance_hooks_resolve(self):
        for script in DEVICE_ACCEPTANCE_HOOKS:
            with self.subTest(script=script):
                # 新鲜度闸单独测（见 FreshnessGateTest）；这里只测"解析得到"，
                # 否则离线回归会因为"源码刚改、还没重建"变红，把真失败盖住。
                path = da.hook_bundle(script, verify_fresh=False)
                self.assertTrue(path.exists(), f'{script} 解析到不存在的路径：{path}')

    def test_gadget_and_multi_hooks_resolve(self):
        for script in GADGET_ACCEPTANCE_HOOKS + MULTI_ACCEPTANCE_HOOKS:
            with self.subTest(script=script):
                self.assertTrue(da.hook_bundle(script, verify_fresh=False).exists())

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


@unittest.skipUnless(shutil.which('git'), '需要 git 才能判定源码是否 dirty')
class FreshnessGateTest(unittest.TestCase):
    """产物新鲜度闸的三档（2026-11-10）。

    背景：dist/ 被 gitignore，设备上跑的是 11-06 的旧 bundle 而源码已是 11-10，
    没有任何环节会发现。这里用临时 git 仓库把三档钉死，不依赖真实 dist 状态：
      干净 + 一致 → pass；落后 → refuse；dirty + 一致 → warn_dirty。
    """

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        (self.root / 'src').mkdir()
        (self.root / 'src/entry.js').write_text(
            "import { dep } from './dep.js';\nexport function main() { return dep; }\n",
            encoding='utf-8')
        (self.root / 'src/dep.js').write_text('export const dep = 1;\n', encoding='utf-8')
        self.bundle = self.root / 'src/entry.bundle.js'
        self.bundle.write_text('BUNDLE', encoding='utf-8')
        self._git('init', '-q')
        self._git('config', 'user.email', 'test@example.invalid')
        self._git('config', 'user.name', 'test')
        self._git('add', '.')
        self._git('commit', '-qm', 'init')

    def tearDown(self):
        self._tmp.cleanup()

    def _git(self, *args):
        subprocess.run(['git', '-C', str(self.root), *args], check=True, capture_output=True)

    def _write_manifest(self):
        return freshness.write_manifest(self.bundle, self.root / 'src/entry.js', 'vehicle', self.root)

    def test_clean_matching_source_passes(self):
        self._write_manifest()
        gate = freshness.verify(self.bundle, self.root)
        self.assertEqual(('pass', 'clean'), (gate['tier'], gate['code']))

    def test_stale_source_refuses(self):
        self._write_manifest()
        with (self.root / 'src/dep.js').open('a', encoding='utf-8') as handle:
            handle.write('// changed\n')
        gate = freshness.verify(self.bundle, self.root)
        self.assertEqual(('refuse', 'stale'), (gate['tier'], gate['code']))
        self.assertIn('src/dep.js', gate['changed_sources'])
        self.assertIn('请先重建', freshness.refusal_text(gate))

    def test_dirty_source_warns_but_runs(self):
        with (self.root / 'src/dep.js').open('a', encoding='utf-8') as handle:
            handle.write('// local edit\n')
        manifest = self._write_manifest()
        self.assertTrue(manifest['dirty_at_build']['dirty'])
        gate = freshness.verify(self.bundle, self.root)
        self.assertEqual(('warn_dirty', 'dirty'), (gate['tier'], gate['code']))

    def test_missing_manifest_refuses(self):
        gate = freshness.verify(self.bundle, self.root)
        self.assertEqual(('refuse', 'no_manifest'), (gate['tier'], gate['code']))

    def test_tampered_bundle_refuses(self):
        self._write_manifest()
        self.bundle.write_text('BUNDLE+', encoding='utf-8')
        gate = freshness.verify(self.bundle, self.root)
        self.assertEqual(('refuse', 'bundle_modified'), (gate['tier'], gate['code']))


if __name__ == '__main__':
    unittest.main(verbosity=2)
