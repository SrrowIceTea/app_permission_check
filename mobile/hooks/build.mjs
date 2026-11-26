// 仅用于授权测试（已获授权的样本与设备）。
// 打包移动隐私钩子，编译器由项目的 Frida Python 环境提供。
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
const PRELUDE = "import Java from './node_modules/frida-java-bridge/index.js';\nglobalThis.Java = Java;\n";
// bundle 规格：name → 入口代码（字符串）或 null（遗留模式：<name>.js 文件内容即入口）。
// 2026-10-16（A1 修复）：privacy/consent/egress_tp/ssl_pinning_tp 改为"导出 main +
// 薄入口"（文件不再顶层自执行），并新增 **hook_all**——四个模块在同一个 JS 上下文
// 里装配的单 agent 合并入口。为什么不让四个 run.py 各挂一个脚本：frida-java-bridge
// **不支持"多脚本各自替换方法"**（bridge 源码 ensureArtKnowsHowToHandleReplacementMethods
// 注释原文 "we don't support replacing methods from multiple scripts"）——实测双脚本
// ~50% 概率触发 ART 的 GetOatQuickMethodHeader FATAL（主线程 abort），单脚本 5/5 稳定。
const BUNDLES = [
  ['hook_privacy', "import { main, flushLocationReads } from './hook_privacy.js';\nrpc.exports.vscanFlushLocationReads = flushLocationReads;\nJava.perform(main);"],
  ['hook_consent', "import { main } from './hook_consent.js';\nJava.perform(main);"],
  ['hook_egress_tp', "import { main } from './hook_egress_tp.js';\nJava.perform(main);"],
  ['hook_window_benchmark', "import { main } from './hook_window_benchmark.js';\nmain();"],
  ['ssl_pinning_tp', "import { main } from './ssl_pinning_tp.js';\nJava.perform(main);"],
  ['hook_all', [
    // 内存 Hook（native TLS 明文 / JCE 明文）并入同一 agent（2026-10-18 接线）。
    // **必须显式调 main()，不能用 side-effect import**：ESM 的 import 会被提升到
    // 入口 `globalThis.Java = Java` 之前，实测直接 `ReferenceError: 'Java' is not defined`。
    "import { main as nativeSslMain } from './hook_native_ssl.js';",
    "import { main as nativeCryptoMain } from './hook_native_crypto.js';",
    "import { main as tlsMetaMain } from './hook_tls_meta.js';",
    "import { main as flutterSslMain } from './hook_flutter_ssl.js';",
    "import { main as nativePrivacyMain } from './hook_privacy_native.js';",
    "import { main as privacyMain, flushLocationReads } from './hook_privacy.js';",
    "import { main as consentMain } from './hook_consent.js';",
    "import { main as egressMain } from './hook_egress_tp.js';",
    "import { main as socketMetaMain } from './hook_socket_meta.js';",
    "import { main as tlsMain } from './ssl_pinning_tp.js';",
    "rpc.exports.vscanFlushLocationReads = flushLocationReads;",
    "function armComplete() {",
    "  socketMetaMain();",
    // tls_meta 排第一：它装 keylog 回调，而回调必须在握手**之前**装上才记得到密钥。
    // 它前面原本有 privacyMain（58 个 Java API，要几秒），实测日志里
    // `SSL_READ_PLAINTEXT` 早于 `tls_meta ARMED`，握手已经跑完了。
    // **诚实交代**：改序后覆盖率并没有可测量的提升（改序前后各 2 轮，都是 1 轮拿到
    // keylog、1 轮为 0）。根因不在顺序，而在"应用在我们装载 agent 之前就把连接建好了"，
    // 之后只是在旧连接上 SSL_read——那时 SSL_CTX_new / SSL_new 早已过去，任何后装都无从补。
    // 真正能解的是 spawn（第一条指令前就位），但本机 AVD 上 spawn 不可用
    // （实测 pid 在第 5s 消失并被重启，见 DECISIONS M038 / exp_spawn_keylog.py）。
    // 保留改序的理由是它仍然更正确：privacyMain 若抛异常，keylog 已经装好了。
    "  tlsMetaMain();",
    // nativePrivacy 必须先于 privacyMain（同为 i2 迁移，2026-10-21）：前者是纯
    // Interceptor.attach（不替换 ArtMethod、无 A1 崩点），把已命中符号写进
    // globalThis.__vscanNat；后者据此跳过对应 WATCH 条目（SKIPPED_JAVA）。
    "  nativePrivacyMain();",
    "  privacyMain();",
    "  consentMain();",
    "  egressMain();",
    "  tlsMain();",
    "  nativeSslMain();",
    // 应用层加密（EVP/AES）与 TLS 元数据（SNI/keylog）：与 nativeSsl 同层，
    // 都是纯 native attach，不替换 Java 方法（A1 单 agent 约束只约束 ArtMethod 替换）。
    // JCE 层钩子（hook_cipher.js 的 Cipher.update/doFinal 全重载替换）不再并入 hook_all
    // （i2 迁移，2026-10-21）：其覆盖（自绘加密明文）已由本层 EVP_EncryptUpdate/
    // EVP_DecryptUpdate 承接，且替换面收窄 = A1 崩点收窄。已知边界：native 侧拿不到
    // Cipher.getAlgorithm() 的算法名（Java 层有 algorithm 字段、native 层没有）；
    // 需要时仍可单独挂 dist/hook_cipher.bundle.js 排障。
    "  nativeCryptoMain();",
    // Flutter（静态剥符号 BoringSSL）：没有库就静默返回，扫到就替一条 0x50 锚点。
    "  flutterSslMain();",
    "}",
    "Java.perform(function () {",
    "  const warmupMs = Number('__VSCAN_SPAWN_WARMUP_MS__');",
    "  if (warmupMs > 0) {",
    "    privacyMain('startup');",
    "    setTimeout(() => Java.perform(armComplete), warmupMs);",
    "  } else {",
    "    armComplete();",
    "  }",
    "});"
  ].join('\n')],
  // 单模块入口：供单独挂载/排障（模块本身不自执行，装配写在这里）。
  ['hook_cipher', "import { main } from './hook_cipher.js';\nJava.perform(main);"],
  ['hook_native_ssl', "import { main } from './hook_native_ssl.js';\nJava.perform(main);"],
  ['hook_native_crypto', "import { main } from './hook_native_crypto.js';\nJava.perform(main);"],
  ['hook_privacy_native', "import { main } from './hook_privacy_native.js';\nJava.perform(main);"],
  ['fixture_trigger', "import { main } from './fixture_trigger.js';\nJava.perform(main);"],
  ['keylog_trigger', "import { main } from './keylog_trigger.js';\nJava.perform(main);"],
  ['hook_tls_meta', "import { main } from './hook_tls_meta.js';\nJava.perform(main);"],
  ['hook_flutter_ssl', "import { main } from './hook_flutter_ssl.js';\nJava.perform(main);"]
];

const only = process.argv.slice(2).filter((a) => !a.startsWith('-'));
const targets = only.length ? BUNDLES.filter(([n]) => only.includes(n)) : BUNDLES;
if (targets.length === 0) {
  console.error(`没有匹配的入口。可选: ${BUNDLES.map(([n]) => n).join(', ')}`);
  process.exit(2);
}

const venvPython = join(HERE, '..', '..', '.venv', process.platform === 'win32' ? 'Scripts/python.exe' : 'bin/python');
const python = process.env.VSCAN_PYTHON || (existsSync(venvPython) ? venvPython :
  (process.platform === 'win32' && process.env.LOCALAPPDATA
    ? join(process.env.LOCALAPPDATA, 'Programs/Python/Python313/python.exe') : 'python3'));
const compiler = join(HERE, 'compile_bundle.py');

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
    execFileSync(python, [compiler, entry, out], { stdio: 'inherit', timeout: 600000 });
    console.log(`[ok] ${name} -> dist/${name}.bundle.js`);
  } catch (e) {
    console.error(`[fatal] ${name} 打包失败: ${e.message}`);
    failed++;
  } finally {
    rmSync(entry, { force: true });
  }
}
process.exit(failed ? 1 : 0);
