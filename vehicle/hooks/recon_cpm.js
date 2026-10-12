// ============================================================================
// 仅用于授权测试（自有设备与自有 APK）/ For authorized testing on owned devices and APKs only.
// V-Scanner Phase 3 — recon_cpm.js：CarPropertyManager 侦察脚本（交付物 1）
// 目标：
//   1) 枚举设备上实际的 CPM 方法表面（运行时反射读取，非硬编码）；
//   2) 用设备上的 VehiclePropertyIds 静态字段交叉核对 rules.db 的 8 个属性 ID/名称；
//   3) 判定 getPropertyList() 能否通过 Frida Java 桥调用（按任务书 quirk：
//      Java.use(className).getPropertyList.call(cpm)，并如实复现直接调用形式）；
//   4) 若本进程是 system_server：用 ActivityThread.systemMain().getSystemContext()
//      创建 Car 客户端（currentApplication() 在 system_server 为 null，勿用），
//      实测 getProperty(II) / getFloatProperty(II) 读取 8 个属性；
//   5) 若本进程加载了 CarPropertyService（com.android.car 进程），dump 其方法表面
//      （运行时发现，非公开 SDK —— 标注 runtime_source:'device'）。
// 只观察、不修改任何返回值。全部结果写 /data/local/tmp/vscan.log（JSONL，src=recon）。
// 运行：frida -U -p <pid> -l recon_cpm.js（见 vehicle/hooks/README.md）
// ============================================================================
'use strict';

import { makeLogger, procName } from './vscan_runtime.js';

// 事件记录格式与进程名取自共用运行时。抽出来的首要理由不是省代码：
// 这四份拷贝**已经漂移**了，而本文件那份原先没有外层 try/catch——
// 记录一失败就会把异常抛回被挂钩的调用。见 vscan_runtime.js 顶部说明。
var vlog = makeLogger('recon', '/data/local/tmp/vscan.log');

var CFG = {
  cpm: 'android.car.hardware.property.CarPropertyManager',
  vpids: 'android.car.VehiclePropertyIds',
  cps: 'com.android.car.hardware.property.CarPropertyService',
  // 8 个属性：ID/名称取自 vehicle/rules/baseline_android14/rules.db vhal_properties 表，
  // 并已用 javap 对 platforms/android-36/optional/android.car.jar 的 VehiclePropertyIds 逐一核对一致。
  expected: {
    286261504: 'INFO_VIN', 291504647: 'PERF_VEHICLE_SPEED', 289408000: 'GEAR_SELECTION',
    289408001: 'CURRENT_GEAR', 291504644: 'PERF_ODOMETER', 291504901: 'ENGINE_RPM',
    291504903: 'FUEL_LEVEL', 291504905: 'EV_BATTERY_LEVEL'
  },
  // value_type=FLOAT 的 5 个（rules.db vhal_properties 表）
  floatProps: [291504647, 291504644, 291504901, 291504903, 291504905]
};

function fmtVal(v) {
  if (v === null || typeof v === 'undefined') return String(v);
  try {
    var cn = v.$className;
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

function detect() {
  var uid = Java.use('android.os.Process').myUid();
  var pkg = procName();
  var isSystem = (uid === 1000);
  var app = null;
  try { app = Java.use('android.app.ActivityThread').currentApplication(); } catch (e) {}
  if (app !== null) {
    try { pkg = String(app.getApplicationContext().getPackageName()); } catch (e) {}
  }
  return { pkg: pkg, uid: uid, isSystem: isSystem };
}

function listLoaded(filter) {
  var out = [];
  Java.enumerateLoadedClasses({
    onMatch: function (n) { if (filter(n)) out.push(n); },
    onComplete: function () {}
  });
  return out;
}

function sigsOf(cls) {
  var methods = cls.class.getDeclaredMethods();
  var out = [];
  for (var i = 0; i < methods.length; i++) {
    var m = methods[i];
    var ts = [];
    var pts = m.getParameterTypes();
    for (var j = 0; j < pts.length; j++) ts.push(pts[j].getName());
    out.push(m.getName() + '(' + ts.join(',') + ')');
  }
  return out;
}

function sectionClasses() {
  var interesting = listLoaded(function (n) {
    return n.indexOf('hardware.property') >= 0 ||
           n.indexOf('CertificatePinner') >= 0 ||
           n.indexOf('TrustManagerImpl') >= 0;
  });
  vlog('CLASS_LIST', { filter: 'hardware.property|CertificatePinner|TrustManagerImpl',
                       count: interesting.length, classes: interesting });
}

function sectionCpmMethods() {
  try {
    var CPM = Java.use(CFG.cpm);
    var sigs = sigsOf(CPM);
    vlog('ENUM_METHODS', { class: CFG.cpm, count: sigs.length, methods: sigs });
  } catch (e) {
    vlog('ERROR', { where: 'ENUM_METHODS', msg: String(e) });
  }
}

function sectionPropConstants() {
  try {
    var VPI = Java.use(CFG.vpids);
    var Modifier = Java.use('java.lang.reflect.Modifier');
    var fields = VPI.class.getDeclaredFields();
    var got = {};
    for (var i = 0; i < fields.length; i++) {
      var f = fields[i];
      try {
        if (Modifier.isStatic(f.getModifiers()) && Modifier.isPublic(f.getModifiers()) &&
            f.getType().getName() === 'int') {
          got[f.getName()] = f.getInt(null);
        }
      } catch (e) {}
    }
    var ok = [], missing = [], mismatch = [];
    for (var id in CFG.expected) {
      if (!Object.prototype.hasOwnProperty.call(CFG.expected, id)) continue;
      var name = CFG.expected[id];
      var nid = parseInt(id, 10);
      var foundName = null;
      for (var k in got) { if (got[k] === nid) { foundName = k; break; } }
      if (foundName === null) missing.push({ prop_name: name, prop_id: nid });
      else if (foundName === name) ok.push({ prop_name: name, prop_id: nid });
      else mismatch.push({ prop_name: name, prop_id: nid, device_field: foundName, device_value: got[foundName] });
    }
    vlog('PROP_CONSTANTS', { source: 'device VehiclePropertyIds static int fields',
                             fields_total: Object.keys(got).length,
                             ok: ok, missing: missing, mismatch: mismatch });
  } catch (e) {
    vlog('ERROR', { where: 'PROP_CONSTANTS', msg: String(e) });
  }
}

function testGetPropertyList(cpm) {
  var CPM = Java.use(CFG.cpm);
  // 形式 1：任务书 quirk —— Java.use(className).getPropertyList.call(cpm)
  try {
    var list = CPM.getPropertyList.call(cpm);
    var sample = [];
    var n = list.size();
    for (var i = 0; i < n && i < 30; i++) {
      try {
        sample.push({ prop_id: list.get(i).getPropertyId(), type: String(list.get(i).getPropertyType()) });
      } catch (e) { sample.push({ raw: String(list.get(i)) }); }
    }
    vlog('GET_PROP_LIST', { ok: true, form: 'getPropertyList.call(cpm)', count: n, sample: sample });
    return; // 桥问题已判定，不再试其它形式
  } catch (e) {
    vlog('GET_PROP_LIST', { ok: false, form: 'getPropertyList.call(cpm)',
                            exc_class: String(e.$className || e.name), exc_msg: String(e.message) });
  }
  // 形式 2：直接调用（任务书记录其曾抛 "not a function"，如实复现）
  try {
    var list2 = cpm.getPropertyList();
    vlog('GET_PROP_LIST', { ok: true, form: 'cpm.getPropertyList() direct', count: list2.size() });
  } catch (e) {
    vlog('GET_PROP_LIST', { ok: false, form: 'cpm.getPropertyList() direct',
                            exc_class: String(e.$className || e.name), exc_msg: String(e.message) });
  }
  // 形式 3：显式无参 overload
  try {
    var list3 = CPM.getPropertyList.overload().call(cpm);
    vlog('GET_PROP_LIST', { ok: true, form: 'getPropertyList.overload().call(cpm)', count: list3.size() });
  } catch (e) {
    vlog('GET_PROP_LIST', { ok: false, form: 'getPropertyList.overload().call(cpm)',
                            exc_class: String(e.$className || e.name), exc_msg: String(e.message) });
  }
}

function testGetProperty8(cpm) {
  var CPM = Java.use(CFG.cpm);
  for (var id in CFG.expected) {
    if (!Object.prototype.hasOwnProperty.call(CFG.expected, id)) continue;
    var nid = parseInt(id, 10);
    var name = CFG.expected[id];
    try {
      var ret = CPM.getProperty.overload('int', 'int').call(cpm, nid, 0);
      var status = null, value = null;
      try { status = ret.getStatus(); value = fmtVal(ret.getValue()); } catch (e) {}
      vlog('GET_PROP_TEST', { prop_id: nid, prop_name: name, api: 'getProperty(II)',
                              ok: true, status: status, value: value });
    } catch (e) {
      vlog('GET_PROP_TEST', { prop_id: nid, prop_name: name, api: 'getProperty(II)',
                              ok: false, exc_class: String(e.$className || e.name), exc_msg: String(e.message) });
    }
  }
}

function testGetFloat(cpm) {
  var CPM = Java.use(CFG.cpm);
  for (var i = 0; i < CFG.floatProps.length; i++) {
    var nid = CFG.floatProps[i];
    var name = CFG.expected[String(nid)];
    try {
      var ret = CPM.getFloatProperty.overload('int', 'int').call(cpm, nid, 0);
      vlog('GET_FLOAT_TEST', { prop_id: nid, prop_name: name, api: 'getFloatProperty(II)',
                               ok: true, value: String(ret) });
    } catch (e) {
      vlog('GET_FLOAT_TEST', { prop_id: nid, prop_name: name, api: 'getFloatProperty(II)',
                               ok: false, exc_class: String(e.$className || e.name), exc_msg: String(e.message) });
    }
  }
}

function bridgeTest() {
  var Car = null, car = null, cpm = null;
  try {
    Car = Java.use('android.car.Car');
    // Phase 0：system_server 内 currentApplication() 为 null，必须用 systemMain().getSystemContext()
    var ctx = Java.use('android.app.ActivityThread').systemMain().getSystemContext();
    vlog('BRIDGE_STEP', { step: 'getSystemContext', ctx_class: String(ctx.$className) });
    car = Car.createCar(ctx); // createCar(Context)，javap 已核实
    vlog('BRIDGE_STEP', { step: 'createCar', ok: car !== null });
    var deadline = Date.now() + 10000;
    var connected = false;
    while (Date.now() < deadline) {
      try { if (car.isConnected()) { connected = true; break; } } catch (e) {}
      Java.use('java.lang.Thread').sleep(250);
    }
    vlog('BRIDGE_STEP', { step: 'wait_connect', connected: connected });
    cpm = car.getCarManager(Car.PROPERTY_SERVICE.value);
    vlog('BRIDGE_STEP', { step: 'getCarManager', cpm_class: cpm === null ? 'null' : String(cpm.$className) });
    if (cpm === null) {
      vlog('ERROR', { where: 'bridgeTest', msg: 'getCarManager returned null' });
      return;
    }
    testGetPropertyList(cpm);
    testGetProperty8(cpm);
    testGetFloat(cpm);
  } catch (e) {
    vlog('BRIDGE_FAIL', { exc_class: String(e.$className || e.name), exc_msg: String(e.message),
                          stack: String(e.stack || '').slice(0, 800) });
  } finally {
    try { if (car !== null) car.disconnect(); } catch (e2) { vlog('ERROR', { where: 'disconnect', msg: String(e2) }); }
  }
}

function sectionCpsIfLoaded() {
  var found = listLoaded(function (n) { return n === CFG.cps; });
  if (found.length === 0) {
    vlog('CPS_ABSENT', { note: 'CarPropertyService 未在本进程加载（本进程不承载车属性服务）。' });
    return;
  }
  try {
    var cls = Java.use(found[0]);
    var sigs = sigsOf(cls);
    vlog('CPS_METHODS', { class: found[0], runtime_source: 'device (runtime discovery; not in rules.db / public android.car.jar)',
                          count: sigs.length, methods: sigs });
  } catch (e) { vlog('ERROR', { where: 'CPS_METHODS', msg: String(e) }); }
}

function main() {
  try {
    var info = detect();
    vlog('START', { script: 'recon_cpm.js', pkg: info.pkg, uid: info.uid,
                    is_system: info.isSystem, arch: Process.arch, frida: Frida.version });
    sectionClasses();
    sectionCpmMethods();
    sectionPropConstants();
    if (info.isSystem) bridgeTest();
    sectionCpsIfLoaded();
    vlog('END', {});
  } catch (e) {
    vlog('ERROR', { where: 'main', msg: String(e && e.stack ? e.stack : e) });
  }
}
Java.perform(main);
