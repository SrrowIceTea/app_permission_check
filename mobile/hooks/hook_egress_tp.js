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

import { makeLogger, procName, NO_STACK } from './runtime.js';

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
  if (NO_STACK) { extra.stack = []; extra.app_frames = []; return extra; }
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
  // i2 Native 迁移（2026-10-21）：libcore.io.Linux.connect(fd, InetAddress, int)
  // 的 Java 方法体是薄壳（直接进 JNI），真正实现是 libopenjdk 导出的
  // Java_libcore_io_Linux_connect——已迁到 hookNativeLinuxConnect（Interceptor.attach，
  // 不替换 ArtMethod）。armed 时本层跳过该重载，证据 SKIPPED_JAVA × NATIVE_MIGRATED
  // 成对留痕；符号未导出则标记不存在，本层原样接管（覆盖率不丢）。
  // 只跳 1 个重载：BlockGuardOs 两条与 Linux 的 SocketAddress 重载保留——它们能拿
  // hostname（getHostString/getHostAddress），是 native 层（只有 IP:port）的补充，
  // 且与 native 事件按 'ip:port' 同键去重，不会双记。
  var natArmed = globalThis.__vscanNat || {};
  // A6（§8.1）：`libcore.io.Posix` 在 API 37 上不存在（`ClassNotFoundException`，
  // 每轮都记一条 HOOK_MISS，看起来像"钩子坏了"其实是**死目标**）。已移除；
  // BlockGuardOs / Linux 是本镜像上实测挂得上的汇聚点，保留。
  var combos = [
    ['libcore.io.BlockGuardOs', ['java.io.FileDescriptor', 'java.net.SocketAddress']],
    ['libcore.io.BlockGuardOs', ['java.io.FileDescriptor', 'java.net.InetAddress', 'int']],
    ['libcore.io.Linux', ['java.io.FileDescriptor', 'java.net.SocketAddress']],
    ['libcore.io.Linux', ['java.io.FileDescriptor', 'java.net.InetAddress', 'int']]
  ];
  for (var i = 0; i < combos.length; i++) {
    var isLinuxInet = combos[i][0] === 'libcore.io.Linux' && combos[i][1].length === 3;
    if (isLinuxInet && natArmed.linux_connect) {
      vlog('SKIPPED_JAVA', { where: 'libcore.io.Linux.connect', sig: combos[i][1].join(','),
                             note: '已由 native.Linux.connect 接管（NATIVE_MIGRATED）。' });
      continue;
    }
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

// ============================================================================
// native connect 层（2026-10-19）：Interceptor 挂 libc connect，覆盖 Java 层够不到的
// 出站连接——WebView（Chromium 在 sandboxed 进程）、Cronet、纯 native 网络栈等。
//
// 与 Java 层（Linux.connect/BlockGuardOs.connect/Socket.connect）互补：
//   - Java 层拿得到 hostname（getHostString）但漏 native 栈；
//   - native 层拿得到真实 IP:port（覆盖所有走 libc connect 的栈），但拿不到 hostname
//     （connect 只收 sockaddr，没有域名）。
// 归因的 target_match 是 host/IP 三选一，native 层提供 `target_ip` 即可与 flow 的
// `server_ip` 对上；hostname 缺失不影响匹配（event.ip == flow.ip）。
//
// 只观察：Interceptor.attach 只读参数，不 replace、不改写、不篡改返回值。
// ============================================================================
function ipv4ToStr(p) {
  try {
    return [p.readU8(), p.readU8(), p.readU8(), p.readU8()].join('.');
  } catch (e) { return null; }
}

// IPv6 16 字节 → 压缩形式（RFC 5952 最简，够归因比对用即可）。
function ipv6ToStr(bytes) {
  var g = [];
  for (var i = 0; i < 16; i += 2) g.push((bytes[i] << 8) | bytes[i + 1]);
  var bestStart = -1, bestLen = 0, curStart = -1, curLen = 0;
  for (var j = 0; j < 8; j++) {
    if (g[j] === 0) {
      if (curStart < 0) { curStart = j; curLen = 0; }
      curLen++;
      if (curLen > bestLen) { bestLen = curLen; bestStart = curStart; }
    } else { curStart = -1; curLen = 0; }
  }
  if (bestLen < 2) return g.map(function (x) { return x.toString(16); }).join(':');
  var head = [], tail = [];
  for (var k = 0; k < 8; k++) {
    if (k < bestStart) head.push(g[k].toString(16));
    if (k >= bestStart + bestLen) tail.push(g[k].toString(16));
  }
  return head.join(':') + '::' + tail.join(':');
}

// 解析 sockaddr：返回 { ip, port }，无法解析返回 null。
function parseSockaddr(sa) {
  if (sa === null || sa === undefined) return null;
  try {
    var fam = sa.readU16();
    if (fam === 2) {  // AF_INET
      var port = (sa.add(2).readU8() << 8) | sa.add(3).readU8();
      var ip = ipv4ToStr(sa.add(4));
      return { ip: ip, port: port };
    } else if (fam === 10) {  // AF_INET6
      var port6 = (sa.add(2).readU8() << 8) | sa.add(3).readU8();
      var b = new Uint8Array(sa.add(8).readByteArray(16));
      return { ip: ipv6ToStr(b), port: port6 };
    }
  } catch (e) {}
  return null;
}

var nativeConnectHooked = false;

function hookNativeConnect() {
  var hooked = [];
  if (nativeConnectHooked) return hooked;
  var addr = null;
  try { addr = Module.getGlobalExportByName('connect'); } catch (e) {}
  if (addr === null) {
    // 兜底：枚举模块找 libc.so 的 connect（RTLD_LOCAL 场景 getGlobalExportByName 查不到）。
    try {
      var mods = Process.enumerateModules();
      for (var i = 0; i < mods.length && addr === null; i++) {
        if (mods[i].name.indexOf('libc') !== 0) continue;
        try { addr = mods[i].findExportByName('connect'); } catch (e) {}
      }
    } catch (e) {}
  }
  if (addr === null) {
    vlog('HOOK_MISS', { where: 'native.connect', msg: 'libc connect 符号未找到' });
    return hooked;
  }
  try {
    Interceptor.attach(addr, {
      onEnter: function (args) {
        try {
          var target = parseSockaddr(args[1]);
          if (target === null) return;   // AF_UNIX / 解析失败：不是 IP 外发，跳过
          var now = Date.now();
          // 与 Java 层同口径去重：同一 host:port 短窗内只记一次。
          if (remember(target.ip + ':' + target.port, now, CFG.dedupMs)) {
            vlog('EGRESS_CONNECT', withStack({
              package: PKG, via: 'native.connect', target_host: null,
              target_port: target.port, target_ip: target.ip, outcome: 'ok'
            }));
          }
        } catch (e) {}
      }
    });
    hooked.push('native.connect@libc');
    nativeConnectHooked = true;
  } catch (e) {
    vlog('HOOK_MISS', { where: 'native.connect', msg: String(e) });
  }
  return hooked;
}

// ============================================================================
// native Linux.connect 层（2026-10-21，i2 迁移）：本镜像把 JNI 符号全剥光（实测
// dynsym/symtab 均无 Java_libcore_io_Linux_connect），改用**只读 ArtMethod** 解析：
// Java.use('libcore.io.Linux').connect 的 (FileDescriptor, InetAddress, int) 重载
// handle(+0x10) = entry_point_from_jni_（布局实测见 hook_privacy_native.js 头注释）。
// 只读、不替换 ArtMethod（A1 崩点收窄）；守卫：入口必须落在已加载模块内且非 libart。
// 事件格式与 Java 层一致（describeInet 本来就只记 literal_ip，native 侧同样只给
// target_ip + target_port；hostname 由保留的 BlockGuardOs/SocketAddress 重载补齐）。
// 去重键 'ip:port' 与 native.connect（libc）同键——同一连接不会双记。只观察不改写。
// ============================================================================
function resolveLinuxConnectJni() {
  var out = [];
  Java.perform(function () {
    try {
      var c = Java.use('libcore.io.Linux');
      var holder = c['connect'];
      if (!holder) return;
      var ovs = holder.overloads || [holder];
      var mods = Process.enumerateModules();
      for (var i = 0; i < ovs.length; i++) {
        var sig = String(ovs[i].argumentTypes);
        // 只认 (FileDescriptor, InetAddress, int)：另一端（SocketAddress）是纯 Java 壳，
        // 会先解析 hostname 再落到这条 JNI。
        if (sig.split(',').length !== 3) continue;
        var h = ovs[i].handle;
        if (!h) continue;
        var p = h.add(0x10).readPointer();
        if (p.isNull()) continue;
        var inMod = false;
        for (var j = 0; j < mods.length; j++) {
          if (p.compare(mods[j].base) >= 0 && p.compare(mods[j].base.add(mods[j].size)) < 0) {
            inMod = mods[j].name !== 'libart.so';
            break;
          }
        }
        if (!inMod) continue;
        out.push({ addr: p });
      }
    } catch (e) {}
  });
  return out;
}

function hookNativeLinuxConnect() {
  var hooked = [];
  var hits = resolveLinuxConnectJni();
  for (var i = 0; i < hits.length; i++) {
    (function (found) {
      var key = 'native.Linux.connect@' + found.addr;
      try {
        Interceptor.attach(found.addr, {
          onEnter: function (args) {
            // Linux.connect(env, thiz, fd, InetAddress, port)：真参自 args[2] 起。
            try {
              var port = -1;
              var ip = null;
              try { port = args[4].toInt32(); } catch (e) {}
              try {
                Java.perform(function () {
                  try {
                    var ia = Java.cast(args[3], Cls.InetAddress);
                    if (ia !== null) {
                      var v = String(ia.getHostAddress());
                      ip = v === 'null' || v === null ? null : v;
                    }
                  } catch (e2) {}
                });
              } catch (e3) {}
              var now = Date.now();
              // 与 native.connect（libc）同键 IP:port 去重：Java 层几条重载也会撞这个键。
              if (remember(hostPort(null, ip, port), now, CFG.dedupMs)) {
                vlog('EGRESS_CONNECT', withStack({
                  package: PKG, via: 'native.Linux.connect', target_host: null,
                  target_port: port, target_ip: ip, outcome: 'ok'
                }));
              }
            } catch (e) {}
          }
        });
        hooked.push(key);
        vlog('NATIVE_MIGRATED', { key: 'linux_connect', entry: found.addr.toString(),
                                  api: 'libcore.io.Linux.connect(fd,InetAddress,int)',
                                  note: '只读 ArtMethod(+0x10) 解析 JNI 入口；对应 Java 层重载已跳过（SKIPPED_JAVA）。' });
        globalThis.__vscanNat = globalThis.__vscanNat || {};
        globalThis.__vscanNat.linux_connect = true;
      } catch (e) {
        vlog('HOOK_MISS', { where: 'native.Linux.connect', msg: String(e) });
      }
    })(hits[i]);
  }
  if (hits.length === 0) {
    vlog('NATIVE_RESOLVE_MISS', { key: 'linux_connect',
                                  note: '类未加载或 ArtMethod 槽位未通过守卫：Java 层原样接管（HOOK 不丢）。' });
  }
  return hooked;
}

export function main() {
  try {
    Cls.ISA = Java.use('java.net.InetSocketAddress');
    Cls.InetAddress = Java.use('java.net.InetAddress');
    PKG = procName();
    if (CFG.whitelist.length > 0 && CFG.whitelist.indexOf(PKG) < 0) {
      vlog('SKIP', { reason: 'not in whitelist', package: PKG, whitelist: CFG.whitelist });
      return;
    }
    vlog('START', { script: 'hook_egress_tp.js', package: PKG, frida: Frida.version });
    // native Linux.connect 先装配：hookLibcoreConnect 依据 armed 标记决定跳过哪个重载。
    var hooked = hookNativeLinuxConnect().concat(
      hookLibcoreConnect(), hookSocketConnect(), hookUriInit(), hookNativeConnect());
    var libcore = hooked.filter(function (h) { return h.indexOf('libcore') === 0; });
    var nativeHooks = hooked.filter(function (h) { return h.indexOf('native.') === 0; });
    vlog('ARMED', { hooks: hooked, count: hooked.length, libcore_hooks: libcore.length,
                    native_hooks: nativeHooks.length });
    console.log('[egress_tp] ARMED in ' + PKG + ' (' + hooked.length + ' hooks, libcore=' +
                libcore.length + ', native=' + nativeHooks.length + ')');
  } catch (e) {
    vlog('ERROR', { where: 'main', msg: String(e && e.stack ? e.stack : e) });
  }
}

// 独立入口由构建提供（build.mjs 的薄入口）——本文件不自执行，见 hook_privacy.js
// 顶部关于"单 agent 合并"的注释（2026-10-16 A1 修复：多脚本各自替换不被 bridge 支持）。
