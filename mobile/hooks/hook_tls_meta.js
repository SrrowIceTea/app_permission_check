// ============================================================================
// 仅用于授权测试（自有设备与自有 APK）/ For authorized testing on owned devices and APKs only.
// V-Scanner — hook_tls_meta.js：TLS 元数据（SNI / 会话密钥）采集
//
// 为什么需要它：hook_native_ssl 在「符号导出」的前提下才拿得到明文。遇到静态链接
// 且剥符号的 BoringSSL（部分 Cronet / Flutter 构建），那条路直接断掉。本模块补两条
// 不依赖 SSL_write/SSL_read 符号的旁路：
//
//   1) SNI（SSL_set_tlsext_host_name）：即使明文不可见，「哪个进程在什么时候连了
//      哪个域名」仍然成立——合规报告里这已经够定性，且成本极低。
//   2) keylog（SSL_CTX_set_keylog_callback）：BoringSSL 会以标准 NSS keylog 格式
//      吐出握手密钥（CLIENT_RANDOM / CLIENT_HANDSHAKE_TRAFFIC_SECRET / ...）。
//      拿到它就能用 Wireshark 直接解 pcap——**不需要**定位任何加解密函数，
//      因此对「符号被剥」的场景是真正的旁路。
//
// keylog 的装法：hook SSL_CTX_new 的返回值，主动把回调挂上去。**不是** hook
// SSL_CTX_set_keylog_callback——那是 App 自己调用的入口，App 不调我们就什么都拿不到。
//
// 边界（必须如实记录，不能假装覆盖）：
//   - keylog 只在 BoringSSL 提供该符号时可用；OpenSSL 1.1.1+ 也有，但 Android
//     上的实现要逐个模块探测（见 KEYLOG_UNAVAILABLE 事件）。
//   - 当前仓库没有 pcap 采集链路，keylog 事件的价值需要配合外部抓包
//     （tcpdump / Wireshark）才能兑现，单独看只是一串密钥行。
//   - 我们会在 ctx 新建后立刻装回调；如果 App 之后自己覆盖，后续连接就没有 keylog，
//     此时以 KEYLOG_INSTALLED 是否出现来判断，不要假设「装了就一直有」。
//
// 只观察：不改写任何参数、不替换任何函数、不改返回值。唯一的写操作是对新 ctx
// 调用官方的 setter（只注册回调，不影响协议行为）。
// ============================================================================
'use strict';
import { packages } from './scope.js';

import { makeLogger, procName } from './runtime.js';

var vlog = makeLogger('tls_meta', '/data/local/tmp/vscan-mobile.log');

var CFG = {
  whitelist: packages(),
  sniSyms: ['SSL_set_tlsext_host_name'],
  // SSL_CTX_new 是「新建上下文」的两个常见入口；_ex 是带 library context 的变体。
  ctxNewSyms: ['SSL_CTX_new', 'SSL_CTX_new_ex'],
  // SSL_new 是**兜底入口**（2026-10-18 补）：attach 模式下 App 的 SSL_CTX 往往在我们
  // 挂上钩子之前就已经建好了，只 hook SSL_CTX_new 会一条 keylog 都拿不到（实测 F-Droid
  // 一轮：7 条 ARMED、5 条 SSL_WRITE_PLAINTEXT，keylog 为 0）。改从每条连接入手，
  // 用 SSL_get_SSL_CTX 反查上下文再补装回调——握手发生在 SSL_new 之后，赶得上。
  sslNewSyms: ['SSL_new'],
  ctxGetter: 'SSL_get_SSL_CTX',
  keylogSetter: 'SSL_CTX_set_keylog_callback',
  maxKeylog: 2000,
  hintModules: ['libssl.so', 'libjavacrypto.so', 'libflutter.so', 'libcronet.so',
                'libmonochrome.so', 'libboringssl.so'],
  rescanMinGapMs: 150
};

var HOOKED = {};
var ARMED = [];
var KEYLOG_SEEN = {};
var KEYLOG_CTX = {};
var KEYLOG_COUNT = 0;
var KEYLOG_DROPPED = false;
var LAST_RESCAN = 0;
var PKG = null;

// 一个进程里可能有多个 BoringSSL 副本（libssl.so / libjavacrypto.so 各自静态链接），
// 回调只需要一个，但 setter 必须按模块取——不同副本的地址不同。
var KEYLOG_CB = new NativeCallback(function (ssl, line) {
  try {
    if (line === null) return;
    var s = line.readCString();
    if (!s) return;
    var label = s.split(' ')[0] || 'UNKNOWN';
    var key = String(ssl) + '|' + label;
    if (KEYLOG_SEEN[key]) return;
    if (KEYLOG_COUNT >= CFG.maxKeylog) {
      if (!KEYLOG_DROPPED) {
        KEYLOG_DROPPED = true;
        vlog('KEYLOG_DROPPED', { reason: 'max_keylog', max: CFG.maxKeylog });
      }
      return;
    }
    KEYLOG_SEEN[key] = true;
    KEYLOG_COUNT++;
    vlog('TLS_KEYLOG', {
      label: label,
      line: s,
      ssl: String(ssl),
      note: '可用于 Wireshark 解密对应连接的 pcap（Preferences → Protocols → TLS → (Pre)-Master-Secret log）。'
    });
  } catch (e) {}
}, 'void', ['pointer', 'pointer']);

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

function frameNames(context, depth) {
  var out = [];
  try {
    var bt = Thread.backtrace(context, Backtracer.ACCURATE);
    for (var i = 0; i < bt.length && i < depth; i++) {
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

// 在**同一个模块**里取 setter 地址：不同 BoringSSL 副本的 SSL_CTX 不能混用。
function setterForModule(moduleName, probeAddr) {
  var mod = null;
  try { mod = Process.findModuleByAddress(probeAddr); } catch (e) { return null; }
  if (mod === null) return null;
  var addr = null;
  try { addr = mod.findExportByName(CFG.keylogSetter); } catch (e) { return null; }
  if (addr === null) return null;
  try { return new NativeFunction(addr, 'void', ['pointer', 'pointer']); } catch (e) { return null; }
}

function attachSni(found, sym, how) {
  var key = sym + '@' + found.module + '@' + found.addr;
  if (HOOKED[key]) return 0;
  try {
    Interceptor.attach(found.addr, {
      onEnter: function (args) {
        try {
          var host = null;
          try { host = args[1].readCString(); } catch (e) { host = null; }
          if (!host) return;
          vlog('TLS_SNI', {
            host: String(host),
            symbol: sym,
            module: found.module,
            arms: how,
            native_backtrace: frameNames(this.context, 5)
          });
        } catch (e) { vlog('ERROR', { where: sym + ' onEnter', msg: String(e) }); }
      }
    });
    HOOKED[key] = true;
    ARMED.push(sym + '@' + found.module + '+sni');
    return 1;
  } catch (e) {
    vlog('ERROR', { where: 'attach ' + key, msg: String(e) });
    return 0;
  }
}

function attachCtxNew(found, sym, how) {
  var key = sym + '@' + found.module + '@' + found.addr;
  if (HOOKED[key]) return 0;
  var setter = setterForModule(found.module, found.addr);
  if (setter === null) {
    vlog('KEYLOG_UNAVAILABLE', {
      module: found.module,
      symbol: CFG.keylogSetter,
      reason: 'setter_not_exported_in_module',
      note: '该模块不导出 SSL_CTX_set_keylog_callback，keylog 旁路对此副本不可用。'
    });
    HOOKED[key] = true;
    return 0;
  }
  try {
    Interceptor.attach(found.addr, {
      onEnter: function (args) { this.ok = false; },
      onLeave: function (retval) {
        try {
          var ctx = retval;
          if (ctx === null || ctx.isNull()) return;
          // 同一 ctx 只装一次；SSL_CTX_new 失败返回 NULL 的情况上面已挡掉。
          if (this.ctx === undefined) this.ctx = ctx;
          setter(ctx, KEYLOG_CB);
          if (!this.ok) {
            this.ok = true;
            vlog('KEYLOG_INSTALLED', {
              module: found.module,
              arms: how,
              ctx: String(ctx),
              note: '已在新建的 SSL_CTX 上装 keylog 回调；若 App 后续覆盖，仅后续连接受影响。'
            });
          }
        } catch (e) { vlog('ERROR', { where: sym + ' onLeave', msg: String(e) }); }
      }
    });
    HOOKED[key] = true;
    ARMED.push(sym + '@' + found.module + '+keylog');
    return 1;
  } catch (e) {
    vlog('ERROR', { where: 'attach ' + key, msg: String(e) });
    return 0;
  }
}

function attachSslNew(found, sym, how) {
  var key = sym + '@' + found.module + '@' + found.addr;
  if (HOOKED[key]) return 0;
  var setter = setterForModule(found.module, found.addr);
  if (setter === null) return 0;
  var mod = null, getterAddr = null;
  try { mod = Process.findModuleByAddress(found.addr); } catch (e) { return 0; }
  if (mod === null) return 0;
  try { getterAddr = mod.findExportByName(CFG.ctxGetter); } catch (e) { return 0; }
  if (getterAddr === null) return 0;
  var getCtx = null;
  try { getCtx = new NativeFunction(getterAddr, 'pointer', ['pointer']); } catch (e) { return 0; }

  try {
    Interceptor.attach(found.addr, {
      onLeave: function (retval) {
        try {
          if (retval.isNull()) return;
          var ctx = getCtx(retval);
          if (ctx.isNull()) return;
          var k = String(ctx);
          if (KEYLOG_CTX[k]) return;         // 同一个 ctx 只装一次，别按连接刷日志
          KEYLOG_CTX[k] = true;
          setter(ctx, KEYLOG_CB);
          vlog('KEYLOG_INSTALLED', {
            module: found.module,
            arms: how + '+ssl_new',
            ctx: k,
            note: 'SSL_new 时按 SSL_get_SSL_CTX 反查上下文补装 keylog：覆盖 attach 之前已建好的 SSL_CTX。'
          });
        } catch (e) { vlog('ERROR', { where: sym + ' onLeave', msg: String(e) }); }
      }
    });
    HOOKED[key] = true;
    ARMED.push(sym + '@' + found.module + '+keylog');
    return 1;
  } catch (e) {
    vlog('ERROR', { where: 'attach ' + key, msg: String(e) });
    return 0;
  }
}

function armAll(how) {
  var added = 0, i, a;
  for (i = 0; i < CFG.sniSyms.length; i++) {
    var s1 = findAll(CFG.sniSyms[i]);
    for (a = 0; a < s1.length; a++) added += attachSni(s1[a], CFG.sniSyms[i], how);
  }
  for (i = 0; i < CFG.ctxNewSyms.length; i++) {
    var s2 = findAll(CFG.ctxNewSyms[i]);
    for (a = 0; a < s2.length; a++) added += attachCtxNew(s2[a], CFG.ctxNewSyms[i], how);
  }
  for (i = 0; i < CFG.sslNewSyms.length; i++) {
    var s3 = findAll(CFG.sslNewSyms[i]);
    for (a = 0; a < s3.length; a++) added += attachSslNew(s3[a], CFG.sslNewSyms[i], how);
  }
  return added;
}


// dlopen 兜底轮询（2026-10-18 实测新增）：app_process 场景下 dlopen watcher 在
// 「attach 时库未加载、之后才 dlopen」时没有触发重扫——第一轮 netprobe 对照里
// 6s 后 conscrypt 才加载，钩子仍是 0 且无 RESCAN_HOOKED。根因是 dlopen 在
// 各模块里解析到同一地址，无法区分 linker 真实实现与 PLT 转发；不深究 linker
// 细节，直接用低频轮询兜住。
//
// **停止阈值放宽过一次**（2026-10-18）：原先是「连续 3 轮空闲（6s）或 30 轮」，
// 实测 F-Droid 一轮在 6s 内没有任何 SSL 符号可用就停了（RESCAN_STOPPED rounds=3），
// 而真正的握手发生在本轮第 12s 才开始的页面刷新上——采集窗口比库加载窗口长时，
// 早期放弃等于整轮失明。改成连续 12 轮空闲（24s）或 90 轮（3min）。
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
    if (idle >= 12 || rounds >= 90) {
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
    symbols: CFG.sniSyms.concat(CFG.ctxNewSyms, [CFG.keylogSetter]),
    modules_scanned: mods.length,
    hint_modules_present: present,
    note: 'SNI/keylog 依赖 libssl 系导出符号；静态链接且剥符号的构建拿不到，' +
          '此时只能退回 hook_native_ssl 的明文路径或外部 pcap。'
  });
}

export function main() {
  try {
    PKG = procName();
    if (CFG.whitelist.length > 0 && CFG.whitelist.indexOf(PKG) < 0) {
      vlog('SKIP', { reason: 'not in whitelist', package: PKG, whitelist: CFG.whitelist });
      return;
    }
    vlog('START', { script: 'hook_tls_meta.js', package: PKG, frida: Frida.version });
    var added = armAll('arm');
    var watched = watchModuleLoads();
    startRescanPoll();
    if (added === 0) reportAbsence();
    vlog('ARMED', { hooks: ARMED, count: ARMED.length, dlopen_watchers: watched });
    console.log('[tls_meta] ARMED in ' + PKG + ' (' + ARMED.length + ' hooks, ' +
                watched.length + ' dlopen watchers)');
  } catch (e) {
    vlog('ERROR', { where: 'main', msg: String(e && e.stack ? e.stack : e) });
  }
}

// 不自执行：装配由入口负责（dist/hook_tls_meta.bundle.js 或 hook_all）。
