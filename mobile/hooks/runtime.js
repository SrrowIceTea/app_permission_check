// ============================================================================
// 仅用于授权测试（已获授权的样本与设备）。
// V-Scanner Mobile — runtime.js：移动钩子的共享运行时。
//
// 与 vehicle/hooks/vscan_runtime.js 的区别：
//   1) 新增 threadName() / stackStr() —— 同意链与隐私读取事件需要线程名与
//      调用栈做时序归因（"同意前读取"靠的就是 ts 比对，栈用来确认是应用代码
//      主动调用还是系统回调）。
//   2) 日志路径按模块传入（不再写死 /data/local/tmp/vscan.log）。
//
// 其余契约与车载版一致：makeLogger 返回的函数永远不抛，观测失败不影响被测应用。
// ============================================================================
'use strict';

export function makeLogger(src, logPath) {
  var evtSeq = 0;
  return function vlog(ev, extra) {
    evtSeq++;
    try {
      var rec = {};
      if (extra) {
        for (var k in extra) if (Object.prototype.hasOwnProperty.call(extra, k)) rec[k] = extra[k];
      }
      rec.v = '1';
      rec.src = src;
      rec.ev = ev;
      rec.evt_id = evtSeq;
      rec.ts = Date.now();
      rec.pid = Process.id;
      rec.tid = Process.getCurrentThreadId();
      var line = JSON.stringify(rec);
      var sent = false, persisted = false;
      try { send({ vscan: 1, line: line }); sent = true; } catch (e1) {}
      try {
        var f = new File(logPath, 'a');
        f.write(line + '\n');
        f.flush();
        f.close();
        persisted = true;
      } catch (e2) {}
      console.log('[' + src + '] ' + ev +
                  (sent ? '' : ' SEND_FAIL') + (persisted ? '' : ' DEVICE_WRITE_DENIED') +
                  ' ' + JSON.stringify(extra || {}).slice(0, 400));
    } catch (e) { console.log('[' + src + '] VLOG_FAIL: ' + e); }
  };
}

// 与车载侧同序：tryUse 紧跟在 makeLogger 之后（纯声明次序，无语义差异；
// 对齐后 hooks 一致性守卫（mobile/tools/test_hooks_parity.py）只为真正单侧的内容建白名单）。
export function tryUse(name) {
  try { return Java.use(name); } catch (e) { return null; }
}

// ---- 明文预览：字节 → 真 UTF-8 字符串 ----
// **不能**用 String.fromCharCode(b) 逐字节拼：那得到的是 Latin-1，一个汉字 3 字节会
// 变成 3 个乱码字符，中文响应在 utf8 字段里不可读（hex 对、人读不了）。
// 预览上限可能把多字节序列切在中间：截断处给替换符，不抛、不错位。
export function decodeUtf8(u8) {
  var s = '', i = 0, n = u8.length;
  while (i < n) {
    var b = u8[i], cp = 0, extra = 0;
    if (b < 0x80) { cp = b; extra = 0; }
    else if ((b & 0xE0) === 0xC0) { cp = b & 0x1F; extra = 1; }
    else if ((b & 0xF0) === 0xE0) { cp = b & 0x0F; extra = 2; }
    else if ((b & 0xF8) === 0xF0) { cp = b & 0x07; extra = 3; }
    else { s += '\uFFFD'; i++; continue; }
    if (i + extra >= n) { s += '\uFFFD'; break; }
    var ok = true;
    for (var k = 1; k <= extra; k++) {
      var c = u8[i + k];
      if ((c & 0xC0) !== 0x80) { ok = false; break; }
      cp = (cp << 6) | (c & 0x3F);
    }
    if (!ok) { s += '\uFFFD'; i++; continue; }
    s += (typeof String.fromCodePoint === 'function')
      ? String.fromCodePoint(cp) : String.fromCharCode(cp);
    i += extra + 1;
  }
  return s;
}

export function procName() {
  try {
    var app = Java.use('android.app.ActivityThread').currentApplication();
    if (app !== null) return String(app.getApplicationContext().getPackageName());
  } catch (e) {}
  try {
    var f = new File('/proc/self/cmdline', 'r');
    var ab = f.readBytes(512);
    f.close();
    var s = '';
    var u8 = new Uint8Array(ab);
    for (var i = 0; i < u8.length; i++) { if (u8[i] === 0) break; s += String.fromCharCode(u8[i]); }
    return s;
  } catch (e) { return 'unknown'; }
}

// ---- 事件期缓存与栈开关（批次 4 · A1 假设 H1，见 DEV_FIX_REPORT §5.1）----
// 假设：崩点在被替换的 ArtMethod 内做 Java.use()。故把 Thread 的 Java.use 收敛到
// ARMED 阶段解析一次（armRuntimeCache），事件路径只做调用；解析失败时字段退化为
// 'unknown'/''，事件照发——观测失败绝不改变被测行为。
// `__VSCAN_NO_STACK__` 由宿主在注入前替换为 '1'/'0'（与 __VSCAN_WATCH_LIMIT__
// 同一机制）；未替换时 parseInt 得到 NaN → 开关为关（保持旧行为）。
// **注意写法**：必须走 parseInt 消费——frida-compile 的压缩器会把直接的字面量
// 比较（`"__VSCAN_NO_STACK__" === "1"`）常量折叠成 false，占位符还没来得及被
// 宿主替换就没了（2026-10-14 实测 477KB bundle 里被折叠为 `var NO_STACK = false`）。
var THREAD_CLS = null;
// 导出给 stack_capture.js / hook_egress_tp.js：NO_STACK=1 时**所有** Java 栈捕获
// （runtime.stackStr / stack_capture.captureStack / egress withStack）都跳过——
// 栈捕获（Thread.getStackTrace → WalkStack）是 A1 残留 GetOatQuickMethodHeader
// abort 的直接触发路径（tombstone_05），这是它的总开关。
export var NO_STACK = parseInt("__VSCAN_NO_STACK__", 10) === 1;

export function armRuntimeCache() {
  try {
    THREAD_CLS = Java.use('java.lang.Thread');
    return THREAD_CLS !== null;
  } catch (e) { THREAD_CLS = null; return false; }
}

// ---- A1 降概率尝试（2026-10-16，**未消除**；10-19 复核见 mobile/A1_RESIDUAL_20261019.md）----
// 证据：58 档夹具自检挂上钩子、按钮触发后，崩溃在 `Jit thread pool` 上
// （SIGSEGV / SEGV_ACCERR，fault addr 落在 JIT 代码区）——JIT 编译线程与
// "Frida 替换 ArtMethod entrypoint"读写同一方法结构，状态不一致即崩。
// 在替换任何 ArtMethod **之前**把已编译方法退回解释器（deoptimize），
// 期望让 JIT 从干净状态起步、不与钩子抢同一份机器码。
// **实测结论（2026-10-16/10-19）：这条没生效也没用**——emulator 不认
// `dalvik.vm.usejit=false`，deopt=1/2 与不 deopt 的死亡率没有可辨差别，
// 所以默认就是 off；保留只为 A/B 对照。真正的崩点已定位到
// `art::HBasicBlockBuilder::Build`（JIT 线程编译某方法时读到不自洽的 dex/ArtMethod），
// 属上游 bridge 缺陷，本仓修不掉。
// `__VSCAN_DEOPTIMIZE__`：0=关（默认，保持旧行为；A/B 对照用）、
// 1=deoptimizeEverything（全部退回解释器）、2=deoptimizeBootImage（只处理
// boot image 类——被监视 API 全是系统类，观测面等价且对应用自身代码更温和）。
// **写法同 NO_STACK**：必须 parseInt 消费——直接字面量比较会被 frida-compile
// 常量折叠掉占位符（2026-10-14 实测）。
var RAW_DEOPTIMIZE = "__VSCAN_DEOPTIMIZE__";

export function deoptimizeBeforeArm() {
  var mode = parseInt(RAW_DEOPTIMIZE, 10);
  if (!isFinite(mode) || mode <= 0) return 'off';
  try {
    if (mode === 2) { Java.deoptimizeBootImage(); return 'boot_image'; }
    Java.deoptimizeEverything(); return 'everything';
  } catch (e) {
    // 去优化失败不阻断挂钩：如实回报模式串，由事件留痕（失败可诊断）。
    return 'failed:' + String((e && e.message) || e).slice(0, 60);
  }
}

export function threadName() {
  if (NO_STACK || THREAD_CLS === null) return 'unknown';
  try {
    return String(THREAD_CLS.currentThread().getName());
  } catch (e) { return 'unknown'; }
}

var STACK_MAX_FRAMES = 30;
var STACK_MAX_LEN = 1200;

export function stackStr() {
  if (NO_STACK || THREAD_CLS === null) return '';
  try {
    var frames = THREAD_CLS.currentThread().getStackTrace();
    var parts = [];
    for (var i = 0; i < frames.length && parts.length < STACK_MAX_FRAMES; i++) {
      var s = String(frames[i].toString());
      if (s.indexOf('VMStack') >= 0 || s.indexOf('Thread.getStackTrace') >= 0) continue;
      parts.push(s);
    }
    var out = parts.join(' <- ');
    return out.length <= STACK_MAX_LEN ? out : out.slice(0, STACK_MAX_LEN) + '…';
  } catch (e) { return ''; }
}
