// ============================================================================
// 仅用于授权测试（自有设备与自有 APK）/ For authorized testing on owned devices and APKs only.
// V-Scanner Phase 3 — hook_egress.js：出站连接观察钩子
//
// **为什么需要它**：Phase 4 的 mitmproxy 看不到包名，而系统层拿不到可靠归属——
// 模拟器的 SLIRP 不保留源端口（`||` 类推断全部失效），按 `/proc/net/tcp` 轮询又因为
// 应用连接只活几十毫秒而抓不到，TIME_WAIT 行还丢 uid。
//
// 唯一能**确定**归属的地方就是应用进程本身：它天然知道自己是哪个包。
// 这里挂钩 `java.net.Socket.connect`，记录 (时间戳, 包名, 目标主机, 目标端口, 线程, 栈)。
// Phase 4 的 addon 用时间就近把代理流对到这些事件上。
//
// 只观察：先执行原实现 → 记录 → 原样返回；异常原样重抛。不阻断、不改值、不改目标。
// 日志 JSONL，src=egress。与其它脚本共用同一格式。
// ============================================================================
'use strict';
import { packages } from './scope.js';

import { makeLogger, procName } from './vscan_runtime.js';

// 事件记录格式与进程名取自共用运行时。本文件那份原先把日志路径**写死**在
// 函数体里、不走 CFG.logPath，console 行也少了 extras——同一件事的第三、四种写法。
// 见 vscan_runtime.js 顶部说明。
var vlog = makeLogger('egress', '/data/local/tmp/vscan.log');

var CFG = {
  // 只记录这些包名的出站连接。留空则本进程内的全部记录
  // （脚本本来就只注入到目标进程，白名单是双保险）。
  whitelist: packages(),
  // 忽略明显无意义的回环/本地目标，减少噪声。审计关注的是外发。
  ignoreLoopback: false,
  // 栈的取舍。**不能只取前 N 帧**——这条踩过：
  // 实测 `Socket.connect` 的第 1..12 帧**全是 okhttp 内部**
  // （Platform.connectSocket → RealConnection → … → HttpURLConnectionImpl），
  // 应用自己的那一帧在更下面，一刀切「前 12 帧」恰好把它切掉。
  // 危险之处在于日志里 12 帧看着满满当当，没人会怀疑缺了最关键的一帧——
  // 而「违规代码行号」正是要从那一帧里取。
  maxStackFrames: 20,   // 非应用帧保留多少（保留上下文，够看清走的是哪条 HTTP 栈）
  maxAppFrames: 8       // 应用自己的帧收够这么多就停（这是归因到代码行的依据）
};

function isAppFrame(s) {
  // 应用自己的帧：类名以本进程包名为前缀。`PKG + '.'` 而非 `indexOf(PKG)`——
  // 后者会让 `com.vscanner.targetapp2` 的帧在 targetapp 进程里也判成自己的
  // （targetapp 是 targetapp2 的**前缀**，这个坑本项目的验收脚本已经踩过一次）。
  return !!PKG && PKG !== 'unknown' && s.indexOf(PKG + '.') >= 0;
}

// 采集栈，并**单独挑出应用自己的帧**。
//
// 返回两个字段而不是一个：`stack` 保留完整上下文（含 okhttp 等框架帧，
// 用来判断走的是哪条 HTTP 栈），`app_frames` 只放应用自己的帧——
// 那是「违规代码行号」的唯一依据。让消费者自己从 `stack` 里筛也行，
// 但那样每个消费者都要重写一遍筛选规则，且很容易漏掉合成帧（见下）。
function stackOf() {
  try {
    var frames = Java.use('java.lang.Thread').currentThread().getStackTrace();
    var context = [], app = [], skipped = 0;
    for (var i = 0; i < frames.length; i++) {
      var s = String(frames[i].toString());
      if (s.indexOf('VMStack') >= 0 || s.indexOf('Thread.getStackTrace') >= 0) continue;
      if (isAppFrame(s)) {
        if (app.length < CFG.maxAppFrames) app.push(s);
        else skipped++;
      } else if (context.length < CFG.maxStackFrames) {
        context.push(s);
      }
    }
    var out = { stack: context, app_frames: app };
    // 应用帧多到装不下时报个数，别静默截断——静默截断正是这次修的那个 bug。
    if (skipped > 0) out.app_frames_skipped = skipped;
    return out;
  } catch (e) { return { stack: [], app_frames: [] }; }
}

// 把 stackOf() 的两个字段摊平进记录。写成 helper 而不是在每个调用点各摊一次：
// vlog 的 extra 是逐键拷贝的，摊不平就得在两个分支里各写两遍，容易漏一处。
function withStack(extra) {
  var st = stackOf();
  extra.stack = st.stack;
  extra.app_frames = st.app_frames;
  if (st.app_frames_skipped) extra.app_frames_skipped = st.app_frames_skipped;
  return extra;
}

var PKG = null;

var ISA = null;
try { ISA = Java.use('java.net.InetSocketAddress'); } catch (e) {}

function describe(addr) {
  // 钩子拿到的是个 Java 对象引用，**必须 Java.cast 到具体类型**才能调它的方法。
  // 不 cast 的话方法调用静默失败（这里表现为 host=null、port=-1），不报错——
  // 于是日志里全是 "-> None:-1"，看起来像"连了个没有地址的目标"。
  var isa = addr;
  try { if (ISA !== null) isa = Java.cast(addr, ISA); } catch (e) { isa = addr; }

  // 不解析域名：getHostName() 会触发反向 DNS，可能阻塞，而且审计不需要。
  var host = null, port = -1, literal = null;
  try { host = String(isa.getHostString()); } catch (e) {}
  try { port = isa.getPort(); } catch (e) {}
  try { literal = String(isa.getAddress().getHostAddress()); } catch (e) {}
  if (host === 'null') host = null;
  if (literal === 'null') literal = null;
  return { host: host, port: port, literal_ip: literal };
}

function hookSocketConnect() {
  var hooked = [];
  try {
    var Socket = Java.use('java.net.Socket');
    var overloads = Socket.connect.overloads;
    for (var i = 0; i < overloads.length; i++) {
      (function (ov) {
        try {
          ov.implementation = function () {
            var args = Array.prototype.slice.call(arguments);
            var info = null;
            try { info = describe(args[0]); } catch (e) {}
            try {
              // 先放行，失败原样抛出——但连接尝试本身要记下来，
              // "尝试外发被拒绝"与"没有外发"是两回事。
              var result = ov.apply(this, args);
              if (info) {
                vlog('EGRESS_CONNECT', withStack({
                  package: PKG, target_host: info.host, target_port: info.port,
                  target_ip: info.literal_ip, outcome: 'ok'
                }));
              }
              return result;
            } catch (e) {
              if (info) {
                vlog('EGRESS_CONNECT', withStack({
                  package: PKG, target_host: info.host, target_port: info.port,
                  target_ip: info.literal_ip, outcome: 'error',
                  error_class: String(e.$className || e.name), error_message: String(e.message)
                }));
              }
              throw e; // 观察模式：不改写结果，异常照原样抛出
            }
          };
          hooked.push('java.net.Socket.connect#' + i);
        } catch (e) { vlog('ERROR', { where: 'hook Socket.connect#' + i, msg: String(e) }); }
      })(overloads[i]);
    }
  } catch (e) { vlog('ERROR', { where: 'hookSocketConnect', msg: String(e) }); }
  return hooked;
}

Java.perform(function () {
  try {
    PKG = procName();
    if (CFG.whitelist.length > 0 && CFG.whitelist.indexOf(PKG) < 0) {
      vlog('SKIP', { reason: 'not in whitelist', package: PKG, whitelist: CFG.whitelist });
      return;
    }
    vlog('START', { script: 'hook_egress.js', package: PKG, frida: Frida.version });
    var hooked = hookSocketConnect();
    vlog('ARMED', { hooks: hooked, count: hooked.length });
    console.log('[egress] ARMED in ' + PKG + ' (' + hooked.length + ' overloads)');
  } catch (e) {
    vlog('ERROR', { where: 'main', msg: String(e && e.stack ? e.stack : e) });
  }
});
