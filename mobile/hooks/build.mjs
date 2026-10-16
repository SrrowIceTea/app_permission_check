// 仅用于授权测试（已获授权的样本与设备）。
// 打包移动隐私钩子：为每个入口前置 frida-java-bridge 的 Java 全局，再交给 frida-compile。
//
// 两个必须照做的细节（照抄 vehicle/hooks 的实测结论）：
//   1) 临时入口 `.entry.<name>.js` 必须放在**本目录**：frida-compile 按入口文件自身
//      所在目录解析相对 import，放到别处会变成静默的「模块找不到」。
//   2) 单文件入口已经含 frida-java-bridge 时必须拒绝，否则 bridge 被注入两次。
import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const DIST = join(HERE, 'dist');
const PRELUDE = "import Java from 'frida-java-bridge';\nglobalThis.Java = Java;\n";
// bundle 规格：name → 入口代码（字符串）或 null（遗留模式：<name>.js 文件内容即入口）。
// 2026-10-16（A1 修复）：privacy/consent/egress_tp/ssl_pinning_tp 改为"导出 main +
// 薄入口"（文件不再顶层自执行），并新增 **hook_all**——四个模块在同一个 JS 上下文
// 里装配的单 agent 合并入口。为什么不让四个 run.py 各挂一个脚本：frida-java-bridge
// **不支持"多脚本各自替换方法"**（bridge 源码 ensureArtKnowsHowToHandleReplacementMethods
// 注释原文 "we don't support replacing methods from multiple scripts"）——实测双脚本
// ~50% 概率触发 ART 的 GetOatQuickMethodHeader FATAL（主线程 abort），单脚本 5/5 稳定。
const BUNDLES = [
  ['hook_privacy', "import { main } from './hook_privacy.js';\nJava.perform(main);"],
  ['hook_consent', "import { main } from './hook_consent.js';\nJava.perform(main);"],
  ['hook_egress_tp', "import { main } from './hook_egress_tp.js';\nJava.perform(main);"],
  ['ssl_pinning_tp', "import { main } from './ssl_pinning_tp.js';\nJava.perform(main);"],
  ['hook_all', [
    "import { main as privacyMain } from './hook_privacy.js';",
    "import { main as consentMain } from './hook_consent.js';",
    "import { main as egressMain } from './hook_egress_tp.js';",
    "import { main as tlsMain } from './ssl_pinning_tp.js';",
    "Java.perform(function () {",
    "  privacyMain();",
    "  consentMain();",
    "  egressMain();",
    "  tlsMain();",
    "});"
  ].join('\n')],
  // 遗留入口（文件自含 Java.perform，未参与合并）：保持旧行为。
  ['hook_cipher', null],
  ['hook_native_ssl', null]
];

const only = process.argv.slice(2).filter((a) => !a.startsWith('-'));
const targets = only.length ? BUNDLES.filter(([n]) => only.includes(n)) : BUNDLES;
if (targets.length === 0) {
  console.error(`没有匹配的入口。可选: ${BUNDLES.map(([n]) => n).join(', ')}`);
  process.exit(2);
}

const cli = join(HERE, 'node_modules', 'frida-compile', 'dist', 'cli.js');
if (!existsSync(cli)) {
  console.error(`找不到 frida-compile：${cli}\n先在本目录执行 npm install --ignore-scripts`);
  process.exit(2);
}

// ---- 依赖补丁：构建前自动重放 frida-java-bridge 补丁（Android 16 兼容修复）----
// patches/ 里的补丁直接改 node_modules（不入 git），每次 `npm install` 后都会丢；
// 这里在构建前幂等重放——已应用（marker 命中）则跳过，否则 `git apply` 并二次校验。
// 背景（2026-10-16，A1 修复）：Android 14+ 的 ART 把 `this`/对象参数以
// "JNI transition frame reference" 传给 native 方法；CheckJNI（userdebug 默认开启）
// 对任何校验型 JNI 调用都会拒绝它，而 Frida 的 trampoline 帧让校验所需的栈遍历
// 永远失败 → 任何 .implementation hook 在首次被调用时 abort
// （"jobject is an invalid JNI transition frame reference"，上游 frida#3700/#3745，
// 修复参考 MaYiFei1995/Camille_Android16 的 02 号补丁）。补丁把 transition ref
// 解码（堆基址自举）并提升为真全局引用（JavaVMExt::AddGlobalRef，不过校验）。
const PATCHES = [
  { patch: '02-class-factory-transition-ref.patch',
    target: 'lib/class-factory.js',
    marker: 'promoteTransitionRef' }
];

function applyDependencyPatches () {
  const bridgeDir = join(HERE, 'node_modules', 'frida-java-bridge');
  if (!existsSync(bridgeDir)) {
    console.error(`找不到 frida-java-bridge：${bridgeDir}\n先在本目录执行 npm install --ignore-scripts`);
    process.exit(2);
  }
  for (const { patch, target, marker } of PATCHES) {
    const patchPath = join(HERE, 'patches', patch);
    if (!existsSync(patchPath)) {
      console.error(`[fatal] 缺少补丁文件：patches/${patch}`);
      process.exit(2);
    }
    const targetPath = join(bridgeDir, target);
    if (readFileSync(targetPath, 'utf8').includes(marker)) {
      console.log(`[patch] 已应用：${patch}`);
      continue;
    }
    try {
      execFileSync('git', ['apply', patchPath], { cwd: bridgeDir, stdio: 'pipe' });
    } catch (e) {
      console.error(`[fatal] 补丁应用失败：${patch}\n` +
                    `${(e.stderr && e.stderr.toString()) || e.message}`);
      process.exit(2);
    }
    if (!readFileSync(targetPath, 'utf8').includes(marker)) {
      console.error(`[fatal] 补丁应用后校验失败（找不到 ${marker}）：${patch}`);
      process.exit(2);
    }
    console.log(`[patch] 重新应用：${patch}`);
  }
}

applyDependencyPatches();
mkdirSync(DIST, { recursive: true });

let failed = 0;
for (const [name, entryCode] of targets) {
  let sourceText;
  if (entryCode === null) {
    // 遗留模式：<name>.js 文件内容即入口（如 hook_cipher / hook_native_ssl）。
    const src = join(HERE, `${name}.js`);
    if (!existsSync(src)) {
      console.error(`[skip] 源文件不存在: ${name}.js`);
      failed++;
      continue;
    }
    sourceText = readFileSync(src, 'utf8');
  } else {
    // 薄入口：被装配的模块导出 main，这里只做装配（依赖由 frida-compile 解析）。
    sourceText = entryCode + '\n';
  }
  if (sourceText.includes('frida-java-bridge')) {
    console.error(`[refuse] ${name} 入口已含 frida-java-bridge，重复注入会出问题`);
    failed++; continue;
  }
  const entry = join(HERE, `.entry.${name}.js`);
  const out = join(DIST, `${name}.bundle.js`);
  writeFileSync(entry, PRELUDE + sourceText, 'utf8');
  try {
    execFileSync(process.execPath, [cli, entry, '-o', out], { stdio: 'inherit', timeout: 600000 });
    // 宿主机驱动（core/frida_host/run.py）用这个字面量判断"是不是打包过的脚本"。
    // 少了它，运行期会死在 ReferenceError: 'Java' is not defined。
    if (!readFileSync(out, 'utf8').includes('frida-java-bridge')) {
      console.error(`[fatal] ${out} 里没有 frida-java-bridge 标记，拒绝产出`);
      failed++;
    } else {
      console.log(`[ok] ${name} -> dist/${name}.bundle.js`);
    }
  } catch (e) {
    console.error(`[fatal] ${name} 打包失败: ${e.message}`);
    failed++;
  } finally {
    rmSync(entry, { force: true });
  }
}
process.exit(failed ? 1 : 0);
