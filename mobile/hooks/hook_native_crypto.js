// ============================================================================
// 仅用于授权测试（自有设备与自有 APK）/ For authorized testing on owned devices and APKs only.
// V-Scanner — hook_native_crypto.js：native 应用层加密的明文截获钩子
//
// 为什么需要它：hook_native_ssl 覆盖的是「TLS 记录层」——SSL_write 收到什么。
// 但很多 App 在交给 TLS **之前**就先自己做了一次 AES，SSL_write 看到的已经是密文。
// 这类应用层加密绝大多数收敛到两个家族：
//   - OpenSSL/BoringSSL 的 EVP 接口（EVP_EncryptUpdate / EVP_DecryptUpdate）
//   - 低层 AES（AES_cbc_encrypt / AES_encrypt / AES_ctr128_encrypt）
// 在这两个家族上取**入参**（加密）或**出参**（解密），拿到的就是业务明文。
//
// 与 hook_native_ssl 的关系：同构但不共享代码——后者已验证跑通，不为复用引入回归风险。
//
// 噪音来源与过滤（关键，不写清楚会重蹈「抓了一堆密文当明文」的覆辙）：
//   TLS 自身的记录层加密**也走 EVP**（BoringSSL 的 tls_seal_record 内部调
//   EVP_EncryptUpdate）。不过滤的话，每一条 TLS 流量都会多出一条「EVP 明文」，
//   而且内容是 TLS 记录密文，把日志淹掉还误导结论。两道过滤：
//     1) 回溯前 6 帧，符号名命中 ^(ssl_|tls_|dtls_|SSL_|DTLS_) → 判定为 TLS 内部，跳过；
//     2) 兜底内容启发式：入参以 HTTP 方法/状态行开头 → 那是 TLS 要加密的 HTTP 报文，
//        已由 hook_native_ssl 的 SSL_write 覆盖，跳过。
//   第 2 条同时也在符号被剥（第 1 条失效）时提供保护。
//
// 节流：低层 AES 是「每 16 字节一次」的调用，不节流会瞬间打爆日志。
//   按 symbol|direction|module 做 120ms 间隔 + 全局 800 条上限；超限只记一次 DROPPED。
//
// 只观察：Interceptor.attach 只读参数、不改写，不 replace、不篡改返回值。
// ============================================================================
'use strict';
import { packages } from './scope.js';

import { makeLogger, procName, decodeUtf8 } from './runtime.js';
import { withStack } from './stack_capture.js';

var vlog = makeLogger('native_crypto', '/data/local/tmp/vscan-mobile.log');

var CFG = {
  whitelist: packages(),
  maxPlainBytes: 2048,
  maxContext: 8,
  maxApp: 8,
  evpEnc: ['EVP_EncryptUpdate'],
  evpDec: ['EVP_DecryptUpdate'],
  // 低层 AES：覆盖「绕过 EVP 直接调底层 API」的库。AES_encrypt 是单块接口，
  // 循环加密时调用极密，靠节流压到可读。
  aesBlock: ['AES_encrypt'],
  aesBulk: ['AES_cbc_encrypt', 'AES_ctr128_encrypt'],
  emitGapMs: 120,
  maxEvents: 800,
  btDepth: 6,
  // 找不到符号时用来区分「库没加载」和「库在但符号被剥」——边界结论要留证据。
  hintModules: ['libcrypto.so', 'libssl.so', 'libjavacrypto.so', 'libflutter.so',
                'libcronet.so', 'libmonochrome.so', 'libboringssl.so'],
  rescanMinGapMs: 150
};

var HOOKED = {};
var ARMED = [];
var LAST = {};
var EMITTED = 0;
var DROPPED = 0;
var DROPPED_NOTIFIED = false;
var LAST_RESCAN = 0;
var PKG = null;

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

// 回溯帧的符号名。DebugSymbol 对导出符号有效；本地符号（被剥）返回空，
// 此时退回模块+偏移——过滤条件 2 仍然兜得住。
function frameNames(context) {
  var out = [];
  try {
    var bt = Thread.backtrace(context, Backtracer.ACCURATE);
    for (var i = 0; i < bt.length && i < CFG.btDepth; i++) {
      var n = '';
      try { n = String(DebugSymbol.fromAddress(bt[i]).name || ''); } catch (e) {}
      if (n) {
        out.push(n);
      } else {
        var m = Process.findModuleByAddress(bt[i]);
        out.push(m ? m.name + '+0x' + bt[i].sub(m.base).toString(16) : '@' + bt[i].toString());
      }
    }
  } catch (e) {}
  return out;
}

// 判「这次 EVP/AES 调用是不是 TLS 记录层自己在干活」。
// 是 → 跳过：它的输入是 TLS 要加密的报文（或输出是已解密的报文），
//      前者已由 SSL_write 覆盖、后者已由 SSL_read 覆盖，重复记录只会污染证据。
function isTlsRecordLayer(frames, ptr, len) {
  for (var i = 0; i < frames.length; i++) {
    if (/^(ssl_|tls_|dtls_|SSL_|DTLS_)/.test(frames[i])) return true;
  }
  // 兜底：符号被剥时靠内容判别。HTTP 报文不可能同时是应用层加密的入参。
  if (ptr !== null && len >= 4) {
    try {
      var head = ptr.readCString(8) || '';
      if (/^(GET |POST |PUT |HEAD |DELET|OPTION|PATCH)/.test(head)) return true;
      if (/^HTTP\/1\./.test(head)) return true;
    } catch (e) {}
  }
  return false;
}

function passThrottle(key) {
  if (EMITTED >= CFG.maxEvents) {
    DROPPED++;
    if (!DROPPED_NOTIFIED) {
      DROPPED_NOTIFIED = true;
      vlog('NATIVE_CRYPTO_DROPPED', {
        reason: 'max_events', max_events: CFG.maxEvents,
        note: '已达事件上限，后续同类调用不再记录；如需完整抓取请调大 CFG.maxEvents 或缩小采集窗口。'
      });
    }
    return false;
  }
  var now = Date.now();
  if (LAST[key] !== undefined && now - LAST[key] < CFG.emitGapMs) { DROPPED++; return false; }
  LAST[key] = now;
  EMITTED++;
  return true;
}

function emit(sym, ev, direction, ptr, len, context, moduleName, how) {
  if (ptr === null || len <= 0) return;
  var frames = frameNames(context);
  if (isTlsRecordLayer(frames, ptr, len)) return;
  if (!passThrottle(sym + '|' + direction + '|' + moduleName)) return;
  var d = readBuf(ptr, len);
  var extra = {
    symbol: sym, direction: direction, module: moduleName, arms: how,
    byte_len: d.byte_len, hex: d.hex, ascii: d.ascii, utf8: d.utf8,
    truncated: d.truncated || undefined,
    native_backtrace: frames
  };
  if (d.read_error) extra.read_error = d.read_error;
  withStack(extra, PKG, CFG.maxContext, CFG.maxApp);
  vlog(ev, extra);
}

// int EVP_EncryptUpdate(ctx, out, int *outl, const unsigned char *in, int inl)
// 加密方向：明文在**入参** in，onEnter 即可读。
function attachEvpEnc(found, sym, how) {
  var key = sym + '@' + found.module;
  if (HOOKED[key]) return 0;
  try {
    Interceptor.attach(found.addr, {
      onEnter: function (args) {
        try {
          var n = args[4].toInt32();
          emit(sym, 'EVP_ENCRYPT_PLAINTEXT', 'encrypt', args[3], n, this.context, found.module, how);
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

// 解密方向：明文在**出参** out，长度由 outl 在 onLeave 才写入。
// 取错方向是这类钩子最常见的错——onEnter 读 out 只会拿到上一轮的残留。
function attachEvpDec(found, sym, how) {
  var key = sym + '@' + found.module;
  if (HOOKED[key]) return 0;
  try {
    Interceptor.attach(found.addr, {
      onEnter: function (args) {
        this.out = args[1];
        this.outl = args[2];
      },
      onLeave: function () {
        try {
          var n = 0;
          try { n = this.outl.readInt32(); } catch (e) { n = 0; }
          if (n > 0) emit(sym, 'EVP_DECRYPT_PLAINTEXT', 'decrypt', this.out, n, this.context, found.module, how);
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

// void AES_encrypt(const unsigned char *in, unsigned char *out, const AES_KEY *key)
// 单块、永远加密方向、固定 16 字节。
function attachAesBlock(found, sym, how) {
  var key = sym + '@' + found.module;
  if (HOOKED[key]) return 0;
  try {
    Interceptor.attach(found.addr, {
      onEnter: function (args) {
        try { emit(sym, 'AES_BLOCK_PLAINTEXT', 'encrypt', args[0], 16, this.context, found.module, how); }
        catch (e) { vlog('ERROR', { where: sym + ' onEnter', msg: String(e) }); }
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

// 批量 AES：
//   AES_cbc_encrypt(in, out, length, key, ivec, enc)  —— enc=1 加密 / 0 解密，方向由参数决定
//   AES_ctr128_encrypt(in, out, len, key, ivec, num)  —— 只有加密方向（CTR 的「解密」就是再加密）
function attachAesBulk(found, sym, how) {
  var key = sym + '@' + found.module;
  if (HOOKED[key]) return 0;
  var isCbc = sym.indexOf('cbc') >= 0;
  try {
    Interceptor.attach(found.addr, {
      onEnter: function (args) {
        try {
          var len = args[2].toInt32();
          if (len <= 0) return;
          if (!isCbc) {
            emit(sym, 'AES_BULK_PLAINTEXT', 'encrypt', args[0], len, this.context, found.module, how);
            return;
          }
          // AES_cbc_encrypt 的 enc 是 int（AES_ENCRYPT=1 / AES_DECRYPT=0）
          var enc = args[5].toInt32();
          if (enc === 1) {
            emit(sym, 'AES_BULK_PLAINTEXT', 'encrypt', args[0], len, this.context, found.module, how);
          } else {
            this.out = args[1];
            this.len = len;
          }
        } catch (e) { vlog('ERROR', { where: sym + ' onEnter', msg: String(e) }); }
      },
      onLeave: function () {
        if (!isCbc || this.out === undefined) return;
        try { emit(sym, 'AES_BULK_PLAINTEXT', 'decrypt', this.out, this.len, this.context, found.module, how); }
        catch (e) { vlog('ERROR', { where: sym + ' onLeave', msg: String(e) }); }
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

function armAll(how) {
  var added = 0, i, a;
  for (i = 0; i < CFG.evpEnc.length; i++) {
    var e1 = findAll(CFG.evpEnc[i]);
    for (a = 0; a < e1.length; a++) added += attachEvpEnc(e1[a], CFG.evpEnc[i], how);
  }
  for (i = 0; i < CFG.evpDec.length; i++) {
    var e2 = findAll(CFG.evpDec[i]);
    for (a = 0; a < e2.length; a++) added += attachEvpDec(e2[a], CFG.evpDec[i], how);
  }
  for (i = 0; i < CFG.aesBlock.length; i++) {
    var e3 = findAll(CFG.aesBlock[i]);
    for (a = 0; a < e3.length; a++) added += attachAesBlock(e3[a], CFG.aesBlock[i], how);
  }
  for (i = 0; i < CFG.aesBulk.length; i++) {
    var e4 = findAll(CFG.aesBulk[i]);
    for (a = 0; a < e4.length; a++) added += attachAesBulk(e4[a], CFG.aesBulk[i], how);
  }
  return added;
}

// 与 hook_native_ssl 同因：库是懒加载的，只在 arm 时扫一次会永久漏掉。

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
                if (!hot && (ARMED.length > 0 || now - LAST_RESCAN < CFG.rescanMinGapMs)) return;
                if (now - LAST_RESCAN < CFG.rescanMinGapMs) return;
                LAST_RESCAN = now;
                var added = armAll('dlopen');
                if (added > 0) vlog('RESCAN_HOOKED', { after_module: path, added: added, hooks: ARMED });
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
    symbols: CFG.evpEnc.concat(CFG.evpDec, CFG.aesBlock, CFG.aesBulk),
    modules_scanned: mods.length,
    hint_modules_present: present,
    note: '没有任何已加载模块导出这些符号：可能库尚未加载，或加密被静态链接并剥符号。' +
          '加载后仍会由 dlopen 重扫补挂。'
  });
}

export function main() {
  try {
    PKG = procName();
    if (CFG.whitelist.length > 0 && CFG.whitelist.indexOf(PKG) < 0) {
      vlog('SKIP', { reason: 'not in whitelist', package: PKG, whitelist: CFG.whitelist });
      return;
    }
    vlog('START', { script: 'hook_native_crypto.js', package: PKG, frida: Frida.version });
    var added = armAll('arm');
    var watched = watchModuleLoads();
    startRescanPoll();
    if (added === 0) reportAbsence();
    vlog('ARMED', { hooks: ARMED, count: ARMED.length, dlopen_watchers: watched });
    console.log('[native_crypto] ARMED in ' + PKG + ' (' + ARMED.length + ' hooks, ' +
                watched.length + ' dlopen watchers)');
  } catch (e) {
    vlog('ERROR', { where: 'main', msg: String(e && e.stack ? e.stack : e) });
  }
}

// 不自执行：装配由入口负责（dist/hook_native_crypto.bundle.js 或 hook_all）。
