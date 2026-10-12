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
const SCRIPTS = ['hook_privacy.js', 'hook_consent.js', 'hook_egress_tp.js', 'ssl_pinning_tp.js'];

const only = process.argv.slice(2).filter((a) => !a.startsWith('-'));
const targets = only.length ? SCRIPTS.filter((s) => only.includes(s)) : SCRIPTS;
if (targets.length === 0) {
  console.error(`没有匹配的入口。可选: ${SCRIPTS.join(', ')}`);
  process.exit(2);
}

const cli = join(HERE, 'node_modules', 'frida-compile', 'dist', 'cli.js');
if (!existsSync(cli)) {
  console.error(`找不到 frida-compile：${cli}\n先在本目录执行 npm install --ignore-scripts`);
  process.exit(2);
}
mkdirSync(DIST, { recursive: true });

let failed = 0;
for (const name of targets) {
  const src = join(HERE, name);
  if (!existsSync(src)) { console.error(`[skip] 源文件不存在: ${name}`); failed++; continue; }
  const body = readFileSync(src, 'utf8');
  if (body.includes('frida-java-bridge')) {
    console.error(`[refuse] ${name} 已含 frida-java-bridge，重复注入会出问题`);
    failed++; continue;
  }
  const stem = name.replace(/\.js$/, '');
  const entry = join(HERE, `.entry.${stem}.js`);
  const out = join(DIST, `${stem}.bundle.js`);
  writeFileSync(entry, PRELUDE + body, 'utf8');
  try {
    execFileSync(process.execPath, [cli, entry, '-o', out], { stdio: 'inherit', timeout: 600000 });
    // 宿主机驱动（core/frida_host/run.py）用这个字面量判断"是不是打包过的脚本"。
    // 少了它，运行期会死在 ReferenceError: 'Java' is not defined。
    if (!readFileSync(out, 'utf8').includes('frida-java-bridge')) {
      console.error(`[fatal] ${out} 里没有 frida-java-bridge 标记，拒绝产出`);
      failed++;
    } else {
      console.log(`[ok] ${name} -> dist/${stem}.bundle.js`);
    }
  } catch (e) {
    console.error(`[fatal] ${name} 打包失败: ${e.message}`);
    failed++;
  } finally {
    rmSync(entry, { force: true });
  }
}
process.exit(failed ? 1 : 0);
