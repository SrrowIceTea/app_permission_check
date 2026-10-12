// ============================================================================
// 仅用于授权测试（已获授权的样本与设备）。
// V-Scanner Mobile — runtime.js：移动钩子的共享运行时。
//
// 与 phase3/vscan_runtime.js 的区别：
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

export function tryUse(name) {
  try { return Java.use(name); } catch (e) { return null; }
}

export function threadName() {
  try {
    return String(Java.use('java.lang.Thread').currentThread().getName());
  } catch (e) { return 'unknown'; }
}

var STACK_MAX_FRAMES = 30;
var STACK_MAX_LEN = 1200;

export function stackStr() {
  try {
    var frames = Java.use('java.lang.Thread').currentThread().getStackTrace();
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
