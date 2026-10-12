// Node 入口；与 build.py 共用四个源文件，输出路径相同。
import { readFile, writeFile, mkdir, unlink } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
const root = dirname(fileURLToPath(import.meta.url));
await mkdir(join(root, 'dist'), { recursive: true });
for (const name of ['recon_cpm', 'hook_vhal', 'ssl_pinning_bypass', 'hook_egress']) {
  const entry = join(root, `.${name}.entry.js`);
  try {
    await writeFile(entry, "import Java from 'frida-java-bridge';\nglobalThis.Java = Java;\n" +
      await readFile(join(root, name + '.js'), 'utf8'));
    const run = spawnSync(process.execPath, [join(root, 'node_modules/frida-compile/dist/cli.js'),
      entry, '-o', join(root, 'dist', name + '.bundle.js')], { cwd: root, stdio: 'inherit' });
    if (run.status !== 0) throw run.error || new Error(`bundle failed: ${name}`);
  } finally { await unlink(entry); }
}
