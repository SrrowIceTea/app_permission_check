// ============================================================================
// 仅用于授权测试（自有设备与自有 APK）/ For authorized testing on owned devices and APKs only.
// V-Scanner Phase 3 — hook_vhal.js：VHAL 读取观察钩子（交付物 2）
// 只观察：先执行原实现 → 记录 → 原样返回返回值；异常原样重抛。不阻断、不改值。
// 记录字段：属性 ID/名称、值、时间戳、线程名、完整栈（Thread.currentThread().getStackTrace()）、
// 归属（包名/uid）。日志 /data/local/tmp/vscan.log（JSONL，src=vhal）。
// 三种挂载方式（自动检测进程）：
//   A) 附加 system_server（Phase 0 方式）：钩 CPM 进程内调用 + CarPropertyService（若本进程承载）；
//      归属经 Binder.getCallingUid() → PackageManager.getNameForUid（system 模式）。
//      注：本模拟器上车属性服务实际运行在独立的 com.android.car 进程（实测），
//      故 A 模式通常看不到应用侧读取 —— 见 README 的 B/C 模式。
//   B) frida -f <白名单包>：钩应用进程内 CPM，栈帧直接归因到应用代码（推荐用于归因）。
//   C) 附加承载 CarPropertyService 的 com.android.car 进程：全局观察 + uid 归属。
// 默认白名单：仅记录 CFG.whitelist 内包名的读取（白名单外照常执行、不记录）。
// ============================================================================
'use strict';
import { packages } from './scope.js';
import { propertyValue } from './property_value.js';

import { hookSubscriptions } from './subscription_hooks.js';
import { hookBatchReads } from './vhal_batch.js';
import { makeLogger, procName, transportEnabled } from './vscan_runtime.js';
import { createReadScope, recordDelegate } from './vhal_read_scope.js';

// 事件记录格式与进程名取自共用运行时。抽出来的首要理由不是省代码：
// 这四份拷贝**已经漂移**了，而本文件那份原先没有外层 try/catch——
// 记录一失败就会把异常抛回被挂钩的 CarPropertyManager.getProperty，
// 也就是"观测失败改变了被测应用的行为"。见 vscan_runtime.js 顶部说明。
var vlog = makeLogger('vhal', '/data/local/tmp/vscan.log');

var CFG = {
  whitelist: packages(),
  cpm: 'android.car.hardware.property.CarPropertyManager',
  cps: 'com.android.car.hardware.property.CarPropertyService', // 运行时发现，非公开 SDK
  // 8 个属性：rules.db vhal_properties 表 + javap(android-36 android.car.jar VehiclePropertyIds) 双重核对一致
  watch: {
    286261504: 'INFO_VIN', 291504647: 'PERF_VEHICLE_SPEED', 289408000: 'GEAR_SELECTION',
    289408001: 'CURRENT_GEAR', 291504644: 'PERF_ODOMETER', 291504901: 'ENGINE_RPM',
    291504903: 'FUEL_LEVEL', 291504905: 'EV_BATTERY_LEVEL'
  }
};

let ThreadClass;
function currentThread() {
  if (!ThreadClass) ThreadClass = Java.use('java.lang.Thread');
  return ThreadClass.currentThread();
}

function threadName(thread) {
  try { return String(thread.getName()); }
  catch (e) { return '(unavailable)'; }
}

// 任务书指定：Thread.currentThread().getStackTrace()
function stackStr(pkg, thread) {
  try {
    var el = (thread || currentThread()).getStackTrace();
    var lines = [];
    var prefix = pkg && transportEnabled() ? pkg + '.' : null;
    for (var i = 0; i < el.length; i++) {
      var frame = el[i];
      if (!prefix || i < 12 || String(frame.getClassName()).startsWith(prefix))
        lines.push(String(frame.toString()));
    }
    return lines.join('\n');
  } catch (e) { return '(stack unavailable: ' + e + ')'; }
}

function fmtVal(v) {
  if (v === null || typeof v === 'undefined') return String(v);
  try {
    var cn = v.$className;
    if (cn === 'android.car.hardware.CarPropertyValue') {
      try {
        var st = v.getStatus(); // API 35 设备用 getStatus()（getPropertyStatus 为 API 36 新增）
        return 'CarPropertyValue{status=' + st + ',value=' + fmtVal(v.getValue()) + '}';
      } catch (e) { return 'CarPropertyValue{fmt_err:' + e + '}'; }
    }
    if (cn === '[B') {
      var a = Java.array('byte', v);
      var hex = '', ascii = '';
      for (var i = 0; i < a.length && i < 64; i++) {
        hex += ('0' + (a[i] & 0xff).toString(16)).slice(-2);
        ascii += (a[i] >= 32 && a[i] < 127) ? String.fromCharCode(a[i]) : '.';
      }
      return 'bytes[' + a.length + ']=' + hex + ' "' + ascii + '"';
    }
    return String(v);
  } catch (e) {
    try { return '' + v; } catch (e2) { return '(unprintable: ' + e2 + ')'; }
  }
}

var STATE = { pkg: null, uid: -1, isSystem: false, ctx: null, uidPkg: {} };

function detect() {
  STATE.uid = Java.use('android.os.Process').myUid();
  STATE.isSystem = (STATE.uid === 1000);
  STATE.pkg = procName();
  var app = null;
  try { app = Java.use('android.app.ActivityThread').currentApplication(); } catch (e) {}
  if (app !== null) {
    try { STATE.pkg = String(app.getApplicationContext().getPackageName()); } catch (e) {}
    try { STATE.ctx = app.getApplicationContext(); } catch (e) {}
  }
  if (STATE.ctx === null) {
    // system_server 等系统进程：currentApplication() 为 null（Phase 0），用 systemMain().getSystemContext()
    try { STATE.ctx = Java.use('android.app.ActivityThread').systemMain().getSystemContext(); } catch (e) {}
  }
  return STATE;
}

function callerInfo() {
  if (!STATE.isSystem) return { pkg: STATE.pkg, uid: STATE.uid };
  try {
    var uid = Java.use('android.os.Binder').getCallingUid(); // 静态方法，javap(android.jar) 已核实
    if (STATE.uidPkg[uid] === undefined) {
      var pkg = null;
      try { pkg = STATE.ctx.getPackageManager().getNameForUid(uid); } catch (e) {}
      STATE.uidPkg[uid] = pkg ? String(pkg) : null;
    }
    return { pkg: STATE.uidPkg[uid], uid: uid };
  } catch (e) { return { pkg: null, uid: -1 }; }
}

var skippedPkgs = {};
function whitelisted(pkg) {
  if (pkg && CFG.whitelist.indexOf(pkg) >= 0) return true;
  var k = pkg || '(unknown)';
  if (!skippedPkgs[k]) {
    skippedPkgs[k] = 1;
    vlog('SKIP_CALLER', { pkg: k, note: 'not in whitelist; call executes normally, not recorded' });
  }
  return false;
}

function buildExtra(api, propId, areaId, caller, outcome, value, excClass, excMsg, intArg1) {
  var thread;
  try { thread = currentThread(); } catch (e) {}
  var ex = {
    mode: STATE.isSystem ? 'system_process' : 'app',
    api: api,
    pkg: caller.pkg, uid: caller.uid,
    user_id: caller.uid >= 0 ? Math.floor(caller.uid / 100000) : null,
    prop_id: propId, prop_name: CFG.watch[propId], area_id: areaId,
    outcome: outcome,
    thread_name: threadName(thread),
    stack: stackStr(caller.pkg, thread)
  };
  if (intArg1 !== undefined) ex.int_arg_1 = intArg1; // 服务侧(propId,areaId) 次序自校准用
  if (value !== undefined && value !== null) ex.value = value;
  if (excClass) { ex.exc_class = excClass; ex.exc_msg = excMsg; }
  return ex;
}

const readScope = createReadScope();

function makeReadImpl(api, propIdx, orig, selfCheck) {
  return function () {
    var args = Array.prototype.slice.call(arguments);
    var propId = args[propIdx];
    if (!CFG.watch[propId]) return orig.apply(this, args);
    var area = args[propIdx + 1];
    var caller = callerInfo();
    if (!whitelisted(caller.pkg)) return orig.apply(this, args);
    var frame = transportEnabled() && !STATE.isSystem && api.startsWith('cpm.')
      ? readScope.enter(Process.getCurrentThreadId(), api, propId, area) : null;
    var ret, thrown, threw = false;
    try {
      ret = orig.apply(this, args);
    } catch (e) {
      thrown = e;
      threw = true;
    } finally {
      if (frame) readScope.leave(frame);
    }
    try {
      var cls = threw ? String(thrown.$className || thrown.name || '?') : null;
      var message = threw ? String(thrown.message || thrown) : null;
      if (threw && /^(?:Error: )?java\.lang\.SecurityException(?::|$)/.test(message)) {
        cls = 'java.lang.SecurityException';
      }
      var value = threw ? {} : propertyValue(ret, frame && !frame.merged ? fmtVal : null);
      var outcome = threw ? (cls.includes('Security') ? 'denied' : 'error')
        : value.value_raw === null ? 'unavailable' : 'ok';
      if (frame && frame.merged) {
        recordDelegate(frame.outer, api, outcome);
      } else {
        // A scalar wrapper can return a default even when its canonical read failed.
        var fallback = !threw && frame && frame.delegate && frame.delegate !== 'ok';
        var extra = buildExtra(api, propId, area, caller, fallback ? 'unavailable' : outcome,
                              threw ? null : value.value ?? fmtVal(ret), cls, message, selfCheck ? args[1] : undefined);
        Object.assign(extra, value);
        if (frame && frame.nested_suppressed) extra.nested_suppressed = frame.nested_suppressed;
        if (fallback) {
          extra.nested_outcome = frame.delegate;
          extra.value_raw = null;
        }
        vlog('VHAL_READ', extra);
      }
    } catch (e) {
      vlog('ERROR', { where: 'VHAL read observation', msg: String(e) });
    }
    if (threw) throw thrown;
    return ret;
  };
}

// 批量/异步读取共用同一个事件形状，避免两套字段漂移。
function emitBatchRead(api, propId, areaId, caller, outcome, value) {
  vlog('VHAL_READ', buildExtra(api, propId, areaId, caller, outcome, value));
}

function hookCpm() {
  var hooked = [];
  var CPM = Java.use(CFG.cpm);
  try {
    var ov = CPM.getProperty.overload('int', 'int');
    ov.implementation = makeReadImpl('cpm.getProperty(II)', 0, ov, false);
    hooked.push('cpm.getProperty(II)');
  } catch (e) { vlog('ERROR', { where: 'hook cpm.getProperty(II)', msg: String(e) }); }
  try {
    var ov2 = CPM.getProperty.overload('java.lang.Class', 'int', 'int');
    ov2.implementation = makeReadImpl('cpm.getProperty(Class,II)', 1, ov2, false);
    hooked.push('cpm.getProperty(Class,II)');
  } catch (e) { vlog('ERROR', { where: 'hook cpm.getProperty(Class,II)', msg: String(e) }); }
  try {
    var ov3 = CPM.getFloatProperty.overload('int', 'int');
    ov3.implementation = makeReadImpl('cpm.getFloatProperty(II)', 0, ov3, false);
    hooked.push('cpm.getFloatProperty(II)');
  } catch (e) { vlog('ERROR', { where: 'hook cpm.getFloatProperty(II)', msg: String(e) }); }
  // getIntProperty(II)I / getBooleanProperty(II)Z：设备实测签名
  // （vehicle/rules/device_calibration/cpm-signatures-device35.json + android-36 jar javap 双源）
  try {
    var ov4 = CPM.getIntProperty.overload('int', 'int');
    ov4.implementation = makeReadImpl('cpm.getIntProperty(II)', 0, ov4, false);
    hooked.push('cpm.getIntProperty(II)');
  } catch (e) { vlog('ERROR', { where: 'hook cpm.getIntProperty(II)', msg: String(e) }); }
  try {
    var ov5 = CPM.getBooleanProperty.overload('int', 'int');
    ov5.implementation = makeReadImpl('cpm.getBooleanProperty(II)', 0, ov5, false);
    hooked.push('cpm.getBooleanProperty(II)');
  } catch (e) { vlog('ERROR', { where: 'hook cpm.getBooleanProperty(II)', msg: String(e) }); }
  return hooked;
}

// 服务侧钩子（system 模式）：CarPropertyService 为运行时发现的类（非公开 SDK，非规则库），
// 只钩运行时实际存在、且形如 name(II) 的方法；propId 取第 0 个 int 参数，
// 第 1 个 int 参数同时记入 int_arg_1 供自校准（用真实读取验证次序假设）。
function hookCarPropertyService() {
  var found = null;
  Java.enumerateLoadedClasses({
    onMatch: function (n) { if (n === CFG.cps) found = n; },
    onComplete: function () {}
  });
  if (found === null) {
    vlog('CPS_ABSENT', { note: 'CarPropertyService 未在本进程加载。本模拟器上车属性服务运行在独立的 com.android.car 进程；'
                          + '要观察应用侧读取请用 B 模式（frida -f 白名单包）或 C 模式（附加该进程）。' });
    return [];
  }
  var cls = Java.use(found);
  var wanted = { getProperty: 1, getFloatProperty: 1, getBooleanProperty: 1, getIntProperty: 1 };
  var hooked = [];
  var methods = cls.class.getDeclaredMethods();
  for (var i = 0; i < methods.length; i++) {
    var m = methods[i];
    if (!wanted[m.getName()]) continue;
    var pts = m.getParameterTypes();
    if (pts.length !== 2 || pts[0].getName() !== 'int' || pts[1].getName() !== 'int') continue;
    (function (mName) {
      try {
        var ov = cls[mName].overload('int', 'int');
        ov.implementation = makeReadImpl('cps.' + mName + '(II)', 0, ov, true);
        hooked.push('cps.' + mName + '(II)');
      } catch (e) { vlog('ERROR', { where: 'hook cps.' + mName, msg: String(e) }); }
    })(m.getName());
  }
  return hooked;
}

function main() {
  try {
    detect();
    vlog('START', { script: 'hook_vhal.js', pkg: STATE.pkg, uid: STATE.uid,
                    mode: STATE.isSystem ? 'system_process' : 'app',
                    whitelist: CFG.whitelist, frida: Frida.version });
    if (!STATE.isSystem && CFG.whitelist.indexOf(STATE.pkg) < 0) {
      vlog('NOT_TARGET', { pkg: STATE.pkg, note: 'package not in whitelist; no hooks armed' });
      return;
    }
    var hooked = hookCpm();
    if (!STATE.isSystem) hooked = hooked.concat(hookBatchReads({
      CPM: Java.use(CFG.cpm), vlog: vlog, watch: CFG.watch,
      callerInfo: callerInfo, whitelisted: whitelisted,
      isSystem: function () { return STATE.isSystem; },
      emit: emitBatchRead
    }));
    if (!STATE.isSystem) hooked = hooked.concat(hookSubscriptions(
      Java.use(CFG.cpm), vlog, CFG.watch, callerInfo, stackStr));
    if (STATE.isSystem) hooked = hooked.concat(hookCarPropertyService());
    vlog('ARMED', { hooks: hooked, watch_props: CFG.watch });
    console.log('hook_vhal.js ARMED in ' + STATE.pkg + ' (uid=' + STATE.uid + ') — observing; Ctrl+C to exit.');
  } catch (e) {
    vlog('ERROR', { where: 'main', msg: String(e && e.stack ? e.stack : e) });
  }
}
Java.perform(main);
