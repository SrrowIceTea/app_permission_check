// 仅用于授权测试（自有设备 / 已授权的公开第三方样本）。
//
// 应用宝 CDN 的下载地址有一道 JS 挑战页：页面里的脚本算出 token 写进 cookie
// （EO-Bot-Js-Token）后重载，浏览器会自动完成这一步。**无浏览器时用 Node 跑同一段脚本**，
// 效果与浏览器相同——它算的是"你确实执行了 JS"，不是绕过某种授权。
//
// 用法：node solve_dl_challenge.mjs <挑战页 HTML 的路径>
//   输出：一行 cookie，形如  EO-Bot-Js-Token=xxxx
//
// 为什么要单独写：这是获取公开样本的最后一道坎，写在 Python 里没法执行 JS；
// 而把整段页面脚本抄成 Python 是维护负担。跑一次、拿 cookie、交给 urllib 下载即可。

import { readFileSync } from 'node:fs';

const path = process.argv[2];
if (!path) {
  console.error('用法: node solve_dl_challenge.mjs <challenge.html>');
  process.exit(2);
}
const html = readFileSync(path, 'utf8');

// 抓取所有内联 <script>（挑战逻辑在其中；带 src 的外链跳过）
const scripts = [...html.matchAll(/<script(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script>/gi)]
  .map((m) => m[1])
  .filter((s) => s.trim().length > 0);
if (scripts.length === 0) {
  console.error('页面里没有内联脚本：可能不是挑战页');
  process.exit(3);
}

const cookies = [];
const shim = {
  cookie: '',
  referrer: '',
  location: {
    href: 'https://imtt2.dd.qq.com/',
    replace() {},
    reload() {},
  },
  navigator: { userAgent: 'Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 Chrome/120 Mobile' },
  setTimeout: (fn) => { try { fn(); } catch (e) { /* 延迟任务失败不影响 token */ } },
  clearTimeout: () => {},
};

globalThis.window = globalThis;
globalThis.self = globalThis;
globalThis.document = new Proxy(shim, {
  set(target, prop, value) {
    if (prop === 'cookie') cookies.push(String(value));
    target[prop] = value;
    return true;
  },
  get(target, prop) {
    if (prop === 'cookie') return target.cookie;
    return target[prop];
  },
});
globalThis.location = shim.location;
globalThis.navigator = shim.navigator;
globalThis.setTimeout = shim.setTimeout;
globalThis.clearTimeout = shim.clearTimeout;

for (const src of scripts) {
  try {
    // 间接 eval：让脚本在全局作用域里定义 window.solveChallenge
    (0, eval)(src);
  } catch (e) {
    // 某个脚本块失败不致命：挑战逻辑可能只在其中一块里
    if (process.env.VSCAN_DEBUG) console.error('[script error]', e.message);
  }
}

const token = cookies.map((c) => c.split(';')[0]).find((c) => c.startsWith('EO-Bot-Js-Token='));
if (!token) {
  console.error('没能算出 token。已捕获的 cookie 赋值:', JSON.stringify(cookies).slice(0, 300));
  process.exit(4);
}
console.log(token);
