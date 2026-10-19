// ============================================================================
// 仅用于授权测试（自有设备与自有 APK）/ For authorized testing on owned devices and APKs only.
// V-Scanner Phase 3 — hook_native_ssl.js：native TLS 明文截获钩子（BoringSSL）
//
// 为什么需要它：Java 层钩子（conscrypt TrustManager / OkHttp Pinner）只能「放宽校验」，
// 拿不到 native 栈里的明文。而 TLS 最终都收敛到 BoringSSL 的 SSL_write / SSL_read——
// SSL_write 的 buf 参数就是「即将外发的明文」，SSL_read 的 buf 就是「收到的明文」。
// 在这里截获，就绕开了「协议逆向」，直接覆盖 native TLS 路径。
//
// 覆盖：任何**导出了** SSL_write/SSL_read 的模块。实测（Android 37 / x86_64 模拟器）：
//   - libjavacrypto.so（conscrypt 静态链接的 BoringSSL）导出这两个符号 → 默认 JSSE/OkHttp 栈可截；
//   - libssl.so 同样导出 → 独立 BoringSSL 的栈可截；
//   - 两者在进程里可能同时存在，逐个模块各挂一份（地址不同、覆盖不同调用方）。
// 不覆盖：符号被剥掉/内联的静态 BoringSSL（部分 Cronet 构建）、自绘加密不经 TLS 的路径
//         （见 hook_cipher.js 覆盖 JCE 那半边）。
//
// 三个必须照做的实测结论（Frida 17，2026-10-18）：
//   1) `Module.findExportByName` 在 Frida 17 已被删除（只有 `Module.getGlobalExportByName`）。
//      旧写法包在 try/catch 里 → 永远静默 SYMBOL_ABSENT，看起来像"设备不支持"。
//   2) `Module.getGlobalExportByName` **查不到** dlopen 进来的库：Android 的 linker 默认
//      RTLD_LOCAL，符号不进全局作用域（实测 libssl.so 已加载仍报 "unable to find global
//      export"）。必须逐模块 `module.findExportByName(sym)`。
//   3) 库是**懒加载**的：attach 时 libssl.so 往往还没被 dlopen（实测 BreezyWeather 冷启动
//      2s 时没有，产生流量后才有）。只在 arm 时扫一次会永久漏掉，必须监听 dlopen 重扫。
//
// 只观察：Interceptor.attach 只读参数、不改写，不 replace、不篡改返回值。
// ============================================================================
'use strict';
import { packages } from './scope.js';

import { makeLogger, procName, decodeUtf8 } from './vscan_runtime.js';
import { withStack } from './stack_capture.js';

var vlog = makeLogger('native_ssl', '/data/local/tmp/vscan.log');

var CFG = {
  whitelist: packages(),
  maxPlainBytes: 2048,
  maxContext: 8,
  maxApp: 8,
  // 两个方向各两条：_ex 是 BoringSSL 新 API（长度是 size_t* 出参），老 API 仍被大量使用。
  writes: ['SSL_write', 'SSL_write_ex'],
  reads: ['SSL_read', 'SSL_read_ex'],
  // 找不到符号时用来区分「库没加载」和「库在但符号被剥」——这是能力边界判定的证据。
  hintModules: ['libssl.so', 'libjavacrypto.so', 'libflutter.so', 'libcronet.so',
                'libcronet.2.so', 'libmonochrome.so', 'libboringssl.so'],
  rescanMinGapMs: 150
};

var HOOKED = {};        // key: sym@module → true，防重复挂载
var ARMED = [];         // 人类可读清单，进 ARMED 事件
var LAST_RESCAN = 0;
var PKG = null;

// 逐模块查导出符号。返回 [{addr, module}]（同址去重）。
// **不要**换成 Module.getGlobalExportByName：RTLD_LOCAL 的库查不到（见文件头第 2 条）。
function findAll(sym) {
  var hits = [];
  var seen = {};
  var mods;
  try { mods = Process.enumerateModules(); } catch (e) { return hits; }
  for (var i = 0; i < mods.length; i++) {
    var p = null;
    try { p = mods[i].findExportByName(sym); } catch (e) { continue; }
    if (p === null) continue;
    var k = p.toString();
    if (seen[k]) continue;
    seen[k] = true;
    hits.push({ addr: p, module: mods[i].name });
  }
  return hits;
}

// size_t（_ex 变体出参）：32 位读 4 字节，64 位读 8 字节。
function readSizeT(p) {
  try {
    return Process.pointerSize === 8 ? p.readU64().toNumber() : p.readU32();
  } catch (e) { return 0; }
}

// 读 native 明文 buffer：记真实长度，预览前 maxPlainBytes 字节。
function readBuf(ptr, len) {
  var out = { byte_len: len };
  if (len <= 0 || ptr === null) return out;
  var n = Math.min(len, CFG.maxPlainBytes);
  try {
    var bytes = ptr.readByteArray(n);
    if (bytes === null) return out;
    var u8 = new Uint8Array(bytes);
    var hex = '', ascii = '';
    for (var i = 0; i < u8.length; i++) {
      var b = u8[i];
      hex += ('0' + b.toString(16)).slice(-2);
      ascii += (b >= 32 && b < 127) ? String.fromCharCode(b) : '.';
    }
    out.hex = hex; out.ascii = ascii; out.utf8 = decodeUtf8(u8);
    if (len > CFG.maxPlainBytes) out.truncated = true;
  } catch (e) { out.read_error = String(e); }
  return out;
}

// native 栈兜底：Java 栈在纯 native 上下文可能拿不到，这里记模块+偏移做调试线索。
function nativeBacktrace(context) {
  try {
    var bt = Thread.backtrace(context, Backtracer.ACCURATE);
    var frames = [];
    for (var i = 0; i < bt.length && i < 12; i++) {
      var m = Process.findModuleByAddress(bt[i]);
      if (m) frames.push(m.name + '+0x' + bt[i].sub(m.base).toString(16));
      else frames.push('@' + bt[i].toString());
    }
    return frames;
  } catch (e) { return []; }
}

function record(sym, direction, buf, len, context, moduleName, how) {
  var d = readBuf(buf, len);
  var extra = {
    symbol: sym, direction: direction, module: moduleName, arms: how,
    byte_len: d.byte_len, hex: d.hex, ascii: d.ascii, utf8: d.utf8,
    truncated: d.truncated || undefined
  };
  if (d.read_error) extra.read_error = d.read_error;
  withStack(extra, PKG, CFG.maxContext, CFG.maxApp);
  var nb = nativeBacktrace(context);
  if (nb.length > 0) extra.native_backtrace = nb;
  vlog('SSL_' + (direction === 'write' ? 'WRITE' : 'READ') + '_PLAINTEXT', extra);
}

function attachWrite(found, sym, how) {
  var key = sym + '@' + found.module;
  if (HOOKED[key]) return 0;
  try {
    var isEx = sym.indexOf('_ex') > 0;
    Interceptor.attach(found.addr, {
      onEnter: function (args) {
        // SSL_write(SSL*, const void *buf, int num) / SSL_write_ex(SSL*, buf, num, size_t *written)
        // **_ex 的长度是 args[2]，不是 args[3]**：args[3] 是 written 出参，onEnter 时还没写，
        // 读它只会得到 0（2026-10-18 修）。两者的 buf 都在 args[1]。
        try {
          var num = isEx ? readSizeT(args[2]) : args[2].toInt32();
          if (num > 0) record(sym, 'write', args[1], num, this.context, found.module, how);
        } catch (e) { vlog('ERROR', { where: sym + ' onEnter', msg: String(e) }); }
      }
    });
    HOOKED[key] = true;
    ARMED.push(key);
    return 1;
  } catch (e) {
    vlog('ERROR', { where: 'attach ' + key, msg: String(e) });
    return 0;
  }
}

function attachRead(found, sym, how) {
  var key = sym + '@' + found.module;
  if (HOOKED[key]) return 0;
  try {
    var isEx = sym.indexOf('_ex') > 0;
    Interceptor.attach(found.addr, {
      onEnter: function (args) {
        // SSL_read(SSL*, void *buf, int num)：buf 是输出，读完才有明文
        this.buf = args[1];
        this.outLen = isEx ? args[3] : null;
      },
      onLeave: function (retval) {
        try {
          var n = this.outLen !== null ? readSizeT(this.outLen) : retval.toInt32();
          if (n > 0) record(sym, 'read', this.buf, n, this.context, found.module, how);
        } catch (e) { vlog('ERROR', { where: sym + ' onLeave', msg: String(e) }); }
      }
    });
    HOOKED[key] = true;
    ARMED.push(key);
    return 1;
  } catch (e) {
    vlog('ERROR', { where: 'attach ' + key, msg: String(e) });
    return 0;
  }
}

// 扫一遍所有已加载模块，把还没挂过的符号挂上。返回本次新增条数。
function armAll(how) {
  var added = 0;
  var i;
  for (i = 0; i < CFG.writes.length; i++) {
    var wh = findAll(CFG.writes[i]);
    for (var a = 0; a < wh.length; a++) added += attachWrite(wh[a], CFG.writes[i], how);
  }
  for (i = 0; i < CFG.reads.length; i++) {
    var rh = findAll(CFG.reads[i]);
    for (var b = 0; b < rh.length; b++) added += attachRead(rh[b], CFG.reads[i], how);
  }
  return added;
}


// dlopen 兜底轮询（2026-10-18 实测新增）：app_process 场景下 dlopen watcher 在
// 「attach 时库未加载、之后才 dlopen」时没有触发重扫——第一轮 netprobe 对照里
// 6s 后 conscrypt 才加载，钩子仍是 0 且无 RESCAN_HOOKED。根因是 dlopen 在
// 各模块里解析到同一地址，无法区分 linker 真实实现与 PLT 转发；不深究 linker
// 细节，直接用低频轮询兜住：每 2s 重扫一次，连续 3 次无新增或满 30 轮后停止。
function startRescanPoll() {
  var idle = 0, rounds = 0;
  var timer = setInterval(function () {
    rounds++;
    var added = armAll('poll');
    if (added > 0) {
      idle = 0;
      vlog('RESCAN_HOOKED', { how: 'poll', added: added, hooks: ARMED });
    } else {
      idle++;
    }
    if (idle >= 3 || rounds >= 30) {
      clearInterval(timer);
      vlog('RESCAN_STOPPED', { rounds: rounds, hooks: ARMED.length });
    }
  }, 2000);
  return timer;
}

// dlopen 后重扫：库是懒加载的，只在 arm 时扫一次会永久漏掉（见文件头第 3 条）。
function watchModuleLoads() {
  var names = ['android_dlopen_ext', 'dlopen'];
  var watched = [];
  for (var i = 0; i < names.length; i++) {
    var hits = findAll(names[i]);
    for (var j = 0; j < hits.length; j++) {
      (function (found, sym) {
        try {
          Interceptor.attach(found.addr, {
            onEnter: function (args) {
              var p = null;
              try { p = args[0].readCString(); } catch (e) { p = null; }
              this.path = p;
            },
            onLeave: function () {
              try {
                var path = this.path ? String(this.path) : '';
                var hot = /ssl|crypto|flutter|cronet|monochrome|boring|chromium/i.test(path);
                var now = Date.now();
                // 热路径（SSL 相关库）立刻重扫；其余库在还没挂上任何钩子时按节流重扫。
                if (!hot && (ARMED.length > 0 || now - LAST_RESCAN < CFG.rescanMinGapMs)) return;
                if (now - LAST_RESCAN < CFG.rescanMinGapMs) return;
                LAST_RESCAN = now;
                var added = armAll('dlopen');
                if (added > 0) {
                  vlog('RESCAN_HOOKED', { after_module: path, added: added, hooks: ARMED });
                }
              } catch (e) {}
            }
          });
          watched.push(sym + '@' + found.module);
        } catch (e) { vlog('ERROR', { where: 'watch ' + sym, msg: String(e) }); }
      })(hits[j], names[i]);
    }
  }
  return watched;
}

// 找不到符号时，把「相关库到底在不在」写进日志——这是边界结论的依据，不能靠猜。
function reportAbsence() {
  var present = [];
  var mods = [];
  try { mods = Process.enumerateModules(); } catch (e) {}
  for (var i = 0; i < CFG.hintModules.length; i++) {
    for (var j = 0; j < mods.length; j++) {
      if (mods[j].name === CFG.hintModules[i]) { present.push(mods[j].name); break; }
    }
  }
  vlog('SYMBOL_ABSENT', {
    symbols: CFG.writes.concat(CFG.reads),
    modules_scanned: mods.length,
    hint_modules_present: present,
    note: '没有任何已加载模块导出这些符号：可能是库尚未加载、或 BoringSSL 被静态链接且符号被剥' +
          '（部分 Cronet/Flutter 构建）。加载后仍会由 dlopen 重扫补挂。'
  });
}

export function main() {
  try {
    PKG = procName();
    if (CFG.whitelist.length > 0 && CFG.whitelist.indexOf(PKG) < 0) {
      vlog('SKIP', { reason: 'not in whitelist', package: PKG, whitelist: CFG.whitelist });
      return;
    }
    vlog('START', { script: 'hook_native_ssl.js', package: PKG, frida: Frida.version });
    var added = armAll('arm');
    var watched = watchModuleLoads();
    startRescanPoll();
    if (added === 0) reportAbsence();
    vlog('ARMED', { hooks: ARMED, count: ARMED.length, dlopen_watchers: watched });
    console.log('[native_ssl] ARMED in ' + PKG + ' (' + ARMED.length + ' hooks, ' +
                watched.length + ' dlopen watchers)');
  } catch (e) {
    vlog('ERROR', { where: 'main', msg: String(e && e.stack ? e.stack : e) });
  }
}

// 不自执行：装配由入口负责（单独运行用 dist/hook_native_ssl.bundle.js；
// 合并运行由 hook_all 在同一 Java.perform 里调用 main）。
// **不能用 side-effect import 自装配**：ESM 的 import 会被提升到入口的
// `globalThis.Java = Java` 之前，实测直接 `ReferenceError: 'Java' is not defined`（2026-10-18）。
