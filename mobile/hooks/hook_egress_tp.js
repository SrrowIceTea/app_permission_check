// ============================================================================
// 仅用于授权测试（自有设备 / 已授权的公开第三方样本）。
// V-Scanner Mobile — hook_egress_tp.js：第三方样本的出站连接观察钩子。
//
// **为什么 vehicle/hooks 的 hook_egress.js 在真实第三方 App 上一条也抓不到**（实测，非推测）：
//   它只挂钩 `java.net.Socket.connect`。真实样本的 HTTPS 由 Apache HttpClient
//   （loopj AsyncHttpClient → cz.msebera.httpclient）发出，其 SSL socket 来自
//   `SSLSocketFactory.createSocket()`，而 connect() 在 conscrypt 的子类
//   （OpenSSLSocketImpl / ConscryptEngineSocket）里被**重写**。
//   Frida 挂的是 `java.net.Socket` 上**声明**的那个方法，子类重写不经过它——
//   于是钩子看着 ARMED、事件一条不来。"钩错层"与"应用没动作"长得一模一样，
//   这正是本项目铁律要分开判的那一类。
//
// 本文件的策略：不猜 HTTP 栈，直接挂 **Java 层 socket 连接的唯一汇聚点**
//   `libcore.io.Linux.connect(fd, InetAddress|SocketAddress, port)`
// （PlainSocketImpl、conscrypt、NIO 最终都走它）；保留 `java.net.Socket.connect`
// 作为兼容层与交叉校验。另外记录 `java.net.URI.<init>(String)`：查询串里可能
// 直接带精确坐标（实测本样本 open-meteo 请求的 URL 就含 latitude/longitude），
// 那是比"只知道主机名"更有价值的**明文外发证据**。
//
// 只观察：先执行原实现 → 记录 → 原样返回；异常原样重抛。不阻断、不改值、不改目标。
// 事件格式与 vehicle/hooks 一致（src=egress、ev=EGRESS_CONNECT），Phase 4 的时间归因
// 无需改动；仅多一个 `via` 字段标明捕获层，以及新增 ev=EGRESS_URL。
// ============================================================================
'use strict';
import { packages } from './scope.js';

import { makeLogger, procName } from './runtime.js';

var vlog = makeLogger('egress', '/data/local/tmp/vscan.log');

var CFG = {
  whitelist: packages(),
  urlScheme: /^https?:\/\//i,
  maxUrlLen: 1200,
  urlClasses: ['java.net.URI', 'java.net.URL'],
  dedupMs: 40
};

var PKG = null;
var Cls = { ISA: null, InetAddress: null };
var lastSeen = {};
var seenUrl = {};

function remember(key, now, windowMs) {
  var prev = lastSeen[key];
  if (prev !== undefined && now - prev < windowMs) return false;
  lastSeen[key] = now;
  return true;
}

function hostPort(host, ip, port) {
  return String(host || ip || '?') + ':' + port;
}

function describeSocketAddress(addr) {
  var out = { host: null, port: -1, literal_ip: null };
  if (Cls.ISA === null) return out;
  try {
    var isa = Java.cast(addr, Cls.ISA);
    try { out.host = String(isa.getHostString()); } catch (e) {}
    try { out.port = isa.getPort(); } catch (e) {}
    try { out.literal_ip = String(isa.getAddress().getHostAddress()); } catch (e) {}
  } catch (e) {}
  if (out.host === 'null') out.host = null;
  if (out.literal_ip === 'null') out.literal_ip = null;
  return out;
}

function describeInet(inet, port) {
  var out = { host: null, port: port, literal_ip: null };
  try {
    var ia = Java.cast(inet, Cls.InetAddress);
    try { out.literal_ip = String(ia.getHostAddress()); } catch (e) {}
  } catch (e) {}
  if (out.host === 'null') out.host = null;
  if (out.literal_ip === 'null') out.literal_ip = null;
  return out;
}

function withStack(extra) {
  try {
    var frames = Java.use('java.lang.Thread').currentThread().getStackTrace();
    var context = [], app = [];
    for (var i = 0; i < frames.length; i++) {
      var s = String(frames[i].toString());
      if (s.indexOf('VMStack') >= 0 || s.indexOf('Thread.getStackTrace') >= 0) continue;
      if (PKG && PKG !== 'unknown' && s.indexOf(PKG + '.') >= 0) {
        if (app.length < 8) app.push(s);
      } else if (context.length < 20) {
        context.push(s);
      }
    }
    extra.stack = context;
    extra.app_frames = app;
  } catch (e) { extra.stack = []; extra.app_frames = []; }
  return extra;
}

function installLibcoreConnect(cls, sig, hooked) {
  var via = cls + '.connect';
  var isInet = sig.length === 3 && sig[1] === 'java.net.InetAddress';
  try {
    var C = Java.use(cls);
    var ov = C.connect.overload.apply(C.connect, sig);
    ov.implementation = function () {
      var args = Array.prototype.slice.call(arguments);
      var info = isInet ? describeInet(args[1], args[2]) : describeSocketAddress(args[1]);
      var now = Date.now();
      try {
        var r = ov.apply(this, args);
        if (remember(hostPort(info.host, info.literal_ip, info.port), now, CFG.dedupMs)) {
          vlog('EGRESS_CONNECT', withStack({
            package: PKG, via: via, target_host: info.host, target_port: info.port,
            target_ip: info.literal_ip, outcome: 'ok'
          }));
        }
        return r;
      } catch (e) {
        vlog('EGRESS_CONNECT', withStack({
          package: PKG, via: via, target_host: info.host, target_port: info.port,
          target_ip: info.literal_ip, outcome: 'error',
          error_class: String(e.$className || e.name), error_message: String(e.message)
        }));
        throw e;
      }
    };
    hooked.push(via + '(' + sig.join(',') + ')');
  } catch (e) {
    vlog('HOOK_MISS', { where: via, sig: sig.join(','), msg: String(e) });
  }
}

function hookLibcoreConnect() {
  var hooked = [];
  var combos = [
    ['libcore.io.BlockGuardOs', ['java.io.FileDescriptor', 'java.net.SocketAddress']],
    ['libcore.io.BlockGuardOs', ['java.io.FileDescriptor', 'java.net.InetAddress', 'int']],
    ['libcore.io.Linux', ['java.io.FileDescriptor', 'java.net.SocketAddress']],
    ['libcore.io.Linux', ['java.io.FileDescriptor', 'java.net.InetAddress', 'int']],
    ['libcore.io.Posix', ['java.io.FileDescriptor', 'java.net.SocketAddress']]
  ];
  for (var i = 0; i < combos.length; i++) {
    installLibcoreConnect(combos[i][0], combos[i][1], hooked);
  }
  return hooked;
}

function hookSocketConnect() {
  var hooked = [];
  try {
    var Socket = Java.use('java.net.Socket');
    var ovs = Socket.connect.overloads;
    for (var i = 0; i < ovs.length; i++) {
      (function (ov) {
        try {
          ov.implementation = function () {
            var args = Array.prototype.slice.call(arguments);
            var info = describeSocketAddress(args[0]);
            var now = Date.now();
            var r = ov.apply(this, args);
            if (remember(hostPort(info.host, info.literal_ip, info.port), now, CFG.dedupMs)) {
              vlog('EGRESS_CONNECT', withStack({
                package: PKG, via: 'java.net.Socket.connect', target_host: info.host,
                target_port: info.port, target_ip: info.literal_ip, outcome: 'ok'
              }));
            }
            return r;
          };
          hooked.push('java.net.Socket.connect#' + i);
        } catch (e) { vlog('HOOK_MISS', { where: 'Socket.connect#' + i, msg: String(e) }); }
      })(ovs[i]);
    }
  } catch (e) { vlog('ERROR', { where: 'hookSocketConnect', msg: String(e) }); }
  return hooked;
}

function installUriInit(cls, hooked) {
  var via = cls + '.$init(String)';
  try {
    var C = Java.use(cls);
    var ov = C.$init.overload('java.lang.String');
    ov.implementation = function () {
      var args = Array.prototype.slice.call(arguments);
      var r = ov.apply(this, args);
      try {
        var u = String(args[0]);
        if (CFG.urlScheme.test(u) && u.length <= CFG.maxUrlLen && !seenUrl[u]) {
          seenUrl[u] = 1;
          vlog('EGRESS_URL', { package: PKG, via: via, url: u });
        }
      } catch (e) {}
      return r;
    };
    hooked.push(via);
  } catch (e) { vlog('HOOK_MISS', { where: via, msg: String(e) }); }
}

function hookUriInit() {
  var hooked = [];
  for (var i = 0; i < CFG.urlClasses.length; i++) {
    installUriInit(CFG.urlClasses[i], hooked);
  }
  return hooked;
}

Java.perform(function () {
  try {
    Cls.ISA = Java.use('java.net.InetSocketAddress');
    Cls.InetAddress = Java.use('java.net.InetAddress');
    PKG = procName();
    if (CFG.whitelist.length > 0 && CFG.whitelist.indexOf(PKG) < 0) {
      vlog('SKIP', { reason: 'not in whitelist', package: PKG, whitelist: CFG.whitelist });
      return;
    }
    vlog('START', { script: 'hook_egress_tp.js', package: PKG, frida: Frida.version });
    var hooked = hookLibcoreConnect().concat(hookSocketConnect(), hookUriInit());
    var libcore = hooked.filter(function (h) { return h.indexOf('libcore') === 0; });
    vlog('ARMED', { hooks: hooked, count: hooked.length, libcore_hooks: libcore.length });
    console.log('[egress_tp] ARMED in ' + PKG + ' (' + hooked.length + ' hooks, libcore=' +
                libcore.length + ')');
  } catch (e) {
    vlog('ERROR', { where: 'main', msg: String(e && e.stack ? e.stack : e) });
  }
});
