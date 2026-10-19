// ============================================================================
// 仅用于授权测试（自有设备与自有 APK）/ For authorized testing on owned devices and APKs only.
// V-Scanner Phase 3 — hook_cipher.js：JCE 自绘加密的明文截获钩子
//
// 为什么需要它：申报书的「内存 Hook」方案——在数据进入加密函数之前，直接截获内存里的
// 对走 JCE（javax.crypto.Cipher）自绘加密的应用，明文出现在 Cipher.update / doFinal 的入参里
// （encrypt 方向），或 doFinal 的返回值里（decrypt 方向）。这里挂钩这两个方法把它读出来，
// 事件 src=cipher。
//
// 覆盖：应用自己用 Cipher（AES 等）加密后再外发的路径。
// 不覆盖：native 加密（BoringSSL 的 SSL_write，见 hook_native_ssl.js）、
//         手工 XOR / 直接操作 byte[] 等不经过 JCE 的路径。
//
// 只观察：先执行原实现 → 记录 → 原样返回；异常原样重抛。不阻断、不改值。
// ============================================================================
'use strict';
import { packages } from './scope.js';

import { makeLogger, procName, decodeUtf8 } from './vscan_runtime.js';
import { withStack } from './stack_capture.js';

var vlog = makeLogger('cipher', '/data/local/tmp/vscan.log');

var CFG = {
  whitelist: packages(),
  maxPlainBytes: 2048,   // 明文预览上限（字节）；超出标 truncated，仍记真实长度
  maxContext: 8,         // 非应用帧保留数
  maxApp: 8              // 应用帧保留数
};

// opmode → 方向名。JCE 公开常量，非 android.car 私有 API。
var DECRYPT_MODE = 2;
var OP_NAMES = {};
try {
  var _C = Java.use('javax.crypto.Cipher');
  OP_NAMES[_C.ENCRYPT_MODE.value] = 'encrypt';
  OP_NAMES[_C.DECRYPT_MODE.value] = 'decrypt';
  OP_NAMES[_C.WRAP_MODE.value] = 'wrap';
  OP_NAMES[_C.UNWRAP_MODE.value] = 'unwrap';
} catch (e) {}

// byte[] → hex + ascii + utf8 预览。buf 是 Java byte[] 引用。
function describeBytes(buf) {
  if (buf === null || typeof buf === 'undefined') return { byte_len: -1 };
  var arr = null;
  try { arr = Java.array('byte', buf); } catch (e) {}
  if (arr === null) return { byte_len: -1, note: 'not byte[]' };
  var n = Math.min(arr.length, CFG.maxPlainBytes);
  var hex = '', ascii = '';
  var u8 = new Uint8Array(n);
  for (var i = 0; i < n; i++) {
    var b = arr[i] & 0xff;
    u8[i] = b;
    hex += ('0' + b.toString(16)).slice(-2);
    ascii += (b >= 32 && b < 127) ? String.fromCharCode(b) : '.';
  }
  var out = { byte_len: arr.length, hex: hex, ascii: ascii, utf8: decodeUtf8(u8) };
  if (arr.length > CFG.maxPlainBytes) out.truncated = true;
  return out;
}

function opModeOf(cipher) {
  try { return cipher.getOpMode(); } catch (e) { return -1; }
}

function buildExtra(cipher, buf, phase) {
  var mode = opModeOf(cipher);
  var alg = 'unknown';
  try { alg = String(cipher.getAlgorithm()); } catch (e) {}
  var d = describeBytes(buf);
  return {
    algorithm: alg, opmode: mode, op: OP_NAMES[mode] || String(mode), phase: phase,
    byte_len: d.byte_len, hex: d.hex, ascii: d.ascii, utf8: d.utf8,
    truncated: d.truncated || undefined
  };
}

// 在 args 里找第一个 byte[]。注意：对 doFinal(byte[] output,int) 这类「纯输出」重载，
// 第一个 byte[] 其实是 output 缓冲区而非明文——v1 不做区分，夹具用单参重载规避该歧义。
function firstByteArray(args) {
  for (var i = 0; i < args.length; i++) {
    var a = args[i];
    if (a === null || typeof a === 'undefined') continue;
    try { if (a.$className === '[B') return a; } catch (e) {}
  }
  return null;
}

function hookOne(cls, mName, phase, onReturn) {
  var hooked = [];
  var holder = null;
  try { holder = cls[mName]; } catch (e) { holder = null; }
  if (!holder) {
    vlog('METHOD_NOT_EXPOSED', { where: 'Cipher.' + mName,
                                 note: '未通过 Frida bridge 暴露，跳过' });
    return hooked;
  }
  var overloads = [];
  try { overloads = holder.overloads || []; } catch (e) { overloads = []; }
  for (var k = 0; k < overloads.length; k++) {
    (function (ov) {
      try {
        ov.implementation = function () {
          var args = Array.prototype.slice.call(arguments);
          try {
            var buf = firstByteArray(args);
            if (buf !== null) {
              vlog('CIPHER_PLAINTEXT',
                   withStack(buildExtra(this, buf, phase), PKG, CFG.maxContext, CFG.maxApp));
            }
          } catch (e) { vlog('ERROR', { where: 'Cipher.' + mName + ' capture', msg: String(e) }); }
          var ret = null, threw = null;
          try { ret = ov.apply(this, args); } catch (e) { threw = e; }
          // decrypt 方向的 doFinal：明文在返回值里（入参是密文）。
          if (onReturn && !threw) {
            try { onReturn(this, ret); } catch (e) {}
          }
          if (threw) throw threw;   // 观察模式：异常原样重抛
          return ret;
        };
        hooked.push('Cipher.' + mName + '#' + k);
      } catch (e) { vlog('ERROR', { where: 'hook Cipher.' + mName + '#' + k, msg: String(e) }); }
    })(overloads[k]);
  }
  return hooked;
}

function hookCipher() {
  var cls = null;
  try { cls = Java.use('javax.crypto.Cipher'); } catch (e) { cls = null; }
  if (cls === null) {
    vlog('NOT_PRESENT', { target: 'javax.crypto.Cipher', note: '解析不到该类，跳过' });
    return [];
  }
  var hooked = [];
  hooked = hooked.concat(hookOne(cls, 'update', 'update', null));
  hooked = hooked.concat(hookOne(cls, 'doFinal', 'doFinal', function (cipher, ret) {
    try {
      if (opModeOf(cipher) !== DECRYPT_MODE) return;
      if (ret === null || typeof ret === 'undefined' || ret.$className !== '[B') return;
      vlog('CIPHER_PLAINTEXT',
           withStack(buildExtra(cipher, ret, 'doFinal_return'),
                     PKG, CFG.maxContext, CFG.maxApp));
    } catch (e) {}
  }));
  return hooked;
}

var PKG = null;

// 不自执行：单独运行用 dist/hook_cipher.bundle.js；合并运行由 hook_all 调用 main。
// （ESM import 提升会早于入口的 globalThis.Java 赋值，side-effect import 会 ReferenceError）
export function main() {
  try {
    PKG = procName();
    if (CFG.whitelist.length > 0 && CFG.whitelist.indexOf(PKG) < 0) {
      vlog('SKIP', { reason: 'not in whitelist', package: PKG, whitelist: CFG.whitelist });
      return;
    }
    vlog('START', { script: 'hook_cipher.js', package: PKG, frida: Frida.version });
    var hooked = hookCipher();
    vlog('ARMED', { hooks: hooked, count: hooked.length });
    console.log('[cipher] ARMED in ' + PKG + ' (' + hooked.length + ' overloads)');
  } catch (e) {
    vlog('ERROR', { where: 'main', msg: String(e && e.stack ? e.stack : e) });
  }
}
