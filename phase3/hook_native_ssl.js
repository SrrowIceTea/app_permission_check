// ============================================================================
// 仅用于授权测试（自有设备与自有 APK）/ For authorized testing on owned devices and APKs only.
// V-Scanner Phase 3 — hook_native_ssl.js：native TLS 明文截获钩子（BoringSSL）
//
// 为什么需要它：Java 层钩子（conscrypt TrustManager / OkHttp Pinner）只能「放宽校验」，
// 拿不到 native 栈里的明文。而 Android 的 TLS 最终都收敛到 BoringSSL 的 SSL_write /
// SSL_read——SSL_write 的 buf 参数就是「即将外发的明文」，SSL_read 的 buf 就是「收到的明文」。
// 在这里截获，就绕开了「协议逆向」，直接覆盖 native TLS 路径。
//
// 覆盖：走系统 libssl.so（BoringSSL）的 TLS，含 OkHttp → conscrypt 的 native 路径。
// 不覆盖：静态链接自有 BoringSSL 且符号不导出的栈（Cronet 常见）、自绘加密不经 JCE 的
//         native 路径（见 hook_cipher.js 覆盖 JCE 那半边）。
//
// 只观察：Interceptor.attach 只读参数、不改写，不 replace、不篡改返回值。
// ============================================================================
'use strict';
import { packages } from './scope.js';

import { makeLogger, procName } from './vscan_runtime.js';
import { withStack } from './stack_capture.js';

var vlog = makeLogger('native_ssl', '/data/local/tmp/vscan.log');

var CFG = {
  whitelist: packages(),
  maxPlainBytes: 2048,
  maxContext: 8,
  maxApp: 8,
  // 候选库名与符号。库名因 ROM 而异，逐个探测；找不到就如实报 SYMBOL_ABSENT，不编造。
  modules: ['libssl.so', 'libssl.3.so', 'libssl.so.3', 'libboringssl.so'],
  symbols: ['SSL_write', 'SSL_read']
};

// 在候选库与已加载模块里找导出符号。返回 { addr, module } 或 null。
function findSymbol(sym) {
  for (var i = 0; i < CFG.modules.length; i++) {
    try {
      var p = Module.findExportByName(CFG.modules[i], sym);
      if (p !== null) return { addr: p, module: CFG.modules[i] };
    } catch (e) {}
  }
  try {
    var mods = Process.enumerateModules();
    for (var j = 0; j < mods.length; j++) {
      if (mods[j].name.indexOf('ssl') < 0) continue;
      try {
        var a = Module.findExportByName(mods[j].name, sym);
        if (a !== null) return { addr: a, module: mods[j].name };
      } catch (e) {}
    }
  } catch (e) {}
  return null;
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
    var hex = '', ascii = '', utf8 = '';
    for (var i = 0; i < u8.length; i++) {
      var b = u8[i];
      hex += ('0' + b.toString(16)).slice(-2);
      ascii += (b >= 32 && b < 127) ? String.fromCharCode(b) : '.';
      utf8 += String.fromCharCode(b);
    }
    out.hex = hex; out.ascii = ascii; out.utf8 = utf8;
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

function record(sym, direction, buf, len, context, moduleName) {
  var d = readBuf(buf, len);
  var extra = {
    symbol: sym, direction: direction, module: moduleName,
    byte_len: d.byte_len, hex: d.hex, ascii: d.ascii, utf8: d.utf8,
    truncated: d.truncated || undefined
  };
  if (d.read_error) extra.read_error = d.read_error;
  withStack(extra, PKG, CFG.maxContext, CFG.maxApp);
  var nb = nativeBacktrace(context);
  if (nb.length > 0) extra.native_backtrace = nb;
  vlog('SSL_' + (direction === 'write' ? 'WRITE' : 'READ') + '_PLAINTEXT', extra);
}

function attachWrite(found) {
  try {
    Interceptor.attach(found.addr, {
      onEnter: function (args) {
        // SSL_write(SSL*, const void *buf, int num) → args[1]=buf, args[2]=num
        try {
          var num = args[2].toInt32();
          if (num > 0) record('SSL_write', 'write', args[1], num, this.context, found.module);
        } catch (e) { vlog('ERROR', { where: 'SSL_write onEnter', msg: String(e) }); }
      }
    });
    return true;
  } catch (e) {
    vlog('ERROR', { where: 'attach SSL_write', msg: String(e) });
    return false;
  }
}

function attachRead(found) {
  try {
    Interceptor.attach(found.addr, {
      onEnter: function (args) {
        this.buf = args[1];   // SSL_read(SSL*, void *buf, int num)：buf 是输出，读完才有明文
      },
      onLeave: function (retval) {
        try {
          var n = retval.toInt32();
          if (n > 0) record('SSL_read', 'read', this.buf, n, this.context, found.module);
        } catch (e) { vlog('ERROR', { where: 'SSL_read onLeave', msg: String(e) }); }
      }
    });
    return true;
  } catch (e) {
    vlog('ERROR', { where: 'attach SSL_read', msg: String(e) });
    return false;
  }
}

var PKG = null;

Java.perform(function () {
  try {
    PKG = procName();
    if (CFG.whitelist.length > 0 && CFG.whitelist.indexOf(PKG) < 0) {
      vlog('SKIP', { reason: 'not in whitelist', package: PKG, whitelist: CFG.whitelist });
      return;
    }
    vlog('START', { script: 'hook_native_ssl.js', package: PKG, frida: Frida.version });
    var armed = [];
    for (var i = 0; i < CFG.symbols.length; i++) {
      var sym = CFG.symbols[i];
      var found = findSymbol(sym);
      if (found === null) {
        vlog('SYMBOL_ABSENT', { symbol: sym, note: '候选库中均未找到该导出符号；native TLS 明文不可用' });
        continue;
      }
      var ok = (sym === 'SSL_write') ? attachWrite(found) : attachRead(found);
      if (ok) {
        armed.push(sym + '@' + found.module);
        vlog('SYMBOL_HOOKED', { symbol: sym, module: found.module });
      }
    }
    vlog('ARMED', { hooks: armed, count: armed.length });
    console.log('[native_ssl] ARMED in ' + PKG + ' (' + armed.length + ' hooks)');
  } catch (e) {
    vlog('ERROR', { where: 'main', msg: String(e && e.stack ? e.stack : e) });
  }
});
