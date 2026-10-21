// ============================================================================
// 仅用于授权测试（自有设备与自有 APK）/ For authorized testing on owned devices and APKs only.
// V-Scanner Mobile — hook_privacy_native.js：高频敏感 API 的 native 层观测（i2 迁移）。
//
// 为什么：A1（ArtMethod 替换 → ART/JIT 竞态 SIGSEGV）的崩点在被替换方法的
// trampoline 内。把「高频 + 本身有 native/JNI 实现」的观测点从 Java 层
// ov.implementation 迁到 Interceptor.attach —— **不替换、不修改任何 ArtMethod**，
// 对应 API 的崩溃风险归零。低频纯 Java API（Binder/纯 Java、无 in-process native
// 实现可挂，如 NetworkInterface.getHardwareAddress 实测纯 Java；Chromium 系
// RegisterNatives 动态注册）仍留 Java 层，接受残余、概率已降低的风险。
//
// 解析方式（2026-10-21 实测，API 37.2 x86_64 镜像）：
//   1) 本镜像把 JNI 符号从 dynsym/symtab 全部剥光（enumerateSymbols 查不到任何
//      native_* 名字），**导出符号路线不可行**。
//   2) 可行路线 = 只读 ArtMethod：Java.use(cls)[method].overloads[i].handle 即
//      ArtMethod*（jmethodID）；该镜像 ArtMethod 布局 +0x10 处是
//      entry_point_from_jni_（native 方法专属，非 native 方法此处是别的含义）。
//      功能验证（探针实测）：camera_native_setup → +0x10 挂上后 Camera.open(0)
//      真实调用 1:1 命中；sensor nativeInitBaseEventQueue → registerListener 1:1
//      命中；java.lang.System.nanoTime（intrinsic，非 JNI）不命中 = 负对照成立。
//   3) 自限守卫：读到的指针必须落在某个已加载模块内且不属于 libart.so
//      （+0x18 是 libart 的统一 trampoline，常量跨方法；若未来 ART 布局变动，
//      +0x10 读到的会是 libart 内指针或垃圾 → 守卫拒绝 → Java 层回退接管）。
//      读 ArtMethod 全程只读，不写、不改 —— 不引入 A1 类崩点。
//
// 迁移清单（WATCH 条目 → JNI 方法；libcore.io.Linux.connect 的迁移在
// hook_egress_tp.js，事件归 EGRESS_CONNECT）：
//   SensorManager.registerListener → SystemSensorManager$BaseEventQueue.nativeInitBaseEventQueue
//   Camera.open                    → android.hardware.Camera.native_setup
//   AudioRecord.startRecording     → android.media.AudioRecord.native_start
//
// JNI 参数布局（真参自 args[2] 起；签名来自本镜像 overload 实读）：
//   native_setup(weakThis, cameraId, CameraCompatibilityInfo, Z, Parcel, I) → cameraId=args[3]
//   nativeInitBaseEventQueue(eventQ, weakRef, msgQueue, packageName, mode,
//                            opPackageName, methodName) → packageName=args[5], mode=args[6]
//   native_start(syncEvent, sessionId) → sessionId=args[3]
//
// 事件格式契约：与 Java 层 hook_privacy.js **完全一致**——直接复用 buildExtra，
// 且 src 用同一个 'privacy'；仅多 hook='native' + symbol/module/nat_* 字段。
// native 回调里可以放心 Java.perform（A1 崩点在 ArtMethod trampoline，attach 路径没有）。
// ============================================================================
'use strict';
import { packages } from './scope.js';

import { makeLogger, procName, armRuntimeCache } from './runtime.js';
import { buildExtra } from './hook_privacy.js';
import { matchBySpec, preview } from './dispatch.js';
import { WATCH } from './targets.generated.js';

// src 用 'privacy'：下游按 src/ev 归因，迁移后 PRIVACY_READ 必须同源，差异只在 hook 字段。
var vlog = makeLogger('privacy', '/data/local/tmp/vscan-mobile.log');

var CFG = {
  whitelist: packages(),
  rescanMinGapMs: 150
};

// ArtMethod 的 entry_point_from_jni_ 槽位偏移（x86_64，本镜像实测；见文件头）。
var ART_JNI_SLOT = 0x10;

var HOOKED = {};
var ARMED = [];
var PKG = null;
var JStr = null;   // java.lang.String：arm 阶段解析一次，事件路径不再 Java.use

// armed 标记容器：hook_privacy.js / hook_egress_tp.js 据此跳过已迁移的 Java 层替换。
// 解析失败的目标不设标记 → Java 层原样接管（覆盖率不丢）。
globalThis.__vscanNat = globalThis.__vscanNat || {};

// 迁移目标：cls + method（bridge 侧取值，与 Java 层 WATCH 条目一一对应）。
var TARGETS = [
  { key: 'sensor_registerListener',
    api: 'android.hardware.SensorManager.registerListener',
    cls: 'android.hardware.SystemSensorManager$BaseEventQueue',
    method: 'nativeInitBaseEventQueue',
    capture: 'enter',
    onEvent: function (args) {
      // args[5]=packageName(jstring)，args[6]=mode(jint)，args[7]=opPackageName(jstring)。
      var nat = { mode: null, package_name: null, op_package: null };
      try { nat.mode = args[6].toInt32(); } catch (e) {}
      try {
        Java.perform(function () {
          try {
            var s = Java.cast(args[5], JStr);
            nat.package_name = s === null ? null : preview(String(s), 200);
          } catch (e2) {}
          try {
            var o = Java.cast(args[7], JStr);
            nat.op_package = o === null ? null : preview(String(o), 200);
          } catch (e2) {}
        });
      } catch (e3) {}
      return { ret: null, nat: nat };
    }
  },
  { key: 'camera_open',
    api: 'android.hardware.Camera.open',
    cls: 'android.hardware.Camera',
    method: 'native_setup',
    capture: 'enter',
    onEvent: function (args) {
      // args[3]=cameraId（jint）。
      var nat = { camera_id: null };
      try { nat.camera_id = args[3].toInt32(); } catch (e) {}
      return { ret: null, nat: nat };
    }
  },
  { key: 'audiorecord_start',
    api: 'android.media.AudioRecord.startRecording',
    cls: 'android.media.AudioRecord',
    method: 'native_start',
    capture: 'enter',
    onEvent: function (args) {
      var nat = { sync_event: null, session_id: null };
      try { nat.sync_event = args[2].toInt32(); } catch (e) {}
      try { nat.session_id = args[3].toInt32(); } catch (e) {}
      return { ret: null, nat: nat };
    }
  }
];

// 按 cls.method 从 WATCH 找到被迁移的条目（api 字段、spec、dataType 与 Java 层同源）。
function matchEntry(api) {
  for (var i = 0; i < WATCH.length; i++) {
    if (WATCH[i].cls + '.' + WATCH[i].method === api) return WATCH[i];
  }
  return null;
}

var MOD_CACHE = [];
function loadModCache() {
  try { MOD_CACHE = Process.enumerateModules(); } catch (e) { MOD_CACHE = []; }
}

// 守卫：指针必须落在某已加载模块内且不是 libart（统一 trampoline 在 libart）。
// 布局变动 / 槽位读错时这里拒绝 → 回退 Java。
function validEntry(p) {
  if (p === null || p.isNull()) return null;
  for (var i = 0; i < MOD_CACHE.length; i++) {
    var m = MOD_CACHE[i];
    if (p.compare(m.base) >= 0 && p.compare(m.base.add(m.size)) < 0) {
      return m.name === 'libart.so' ? null : m.name;
    }
  }
  return null;
}

// 只读解析：Java.use → 方法 → overloads → handle(+ART_JNI_SLOT)。全程不写 ArtMethod。
function resolveByArtMethod(target) {
  var out = [];
  Java.perform(function () {
    try {
      var c = Java.use(target.cls);
      var holder = c[target.method];
      if (!holder) return;
      var ovs = holder.overloads || [holder];
      for (var i = 0; i < ovs.length; i++) {
        var h = ovs[i].handle;
        if (!h) continue;
        var p = h.add(ART_JNI_SLOT).readPointer();
        var modName = validEntry(p);
        if (!modName) continue;
        out.push({ addr: p, module: modName, sig: String(ovs[i].argumentTypes) });
      }
    } catch (e) {}
  });
  return out;
}

function emit(target, data) {
  var entry = target._entry;
  if (!entry) return;
  var dts;
  try { dts = matchBySpec(entry.spec, [], entry.dataType); } catch (e) { dts = []; }
  if (!dts || dts.length === 0) return;
  var extra;
  try {
    // args=[]：这几类 spec 全是 direct，match/discriminator/describe 都不读入参。
    extra = buildExtra(entry, dts, [], data.ret, 'ok', null);
  } catch (e) { return; }
  extra.hook = 'native';
  extra.native_entry = target.resolved.addr.toString();
  extra.module = target.resolved.module;
  if (data.nat) {
    for (var k in data.nat) {
      if (Object.prototype.hasOwnProperty.call(data.nat, k)) extra['nat_' + k] = data.nat[k];
    }
  }
  vlog('PRIVACY_READ', extra);
}

function attachTarget(target) {
  target.resolved = target._resolvedHits[0];   // 每个目标实际只有 1 个重载（实测）
  var key = target.key + '@' + target.resolved.addr;
  if (HOOKED[key]) return 1;
  try {
    if (target.capture === 'leave') {
      Interceptor.attach(target.resolved.addr, {
        onEnter: function (args) { this._jargs = args; },
        onLeave: function (retval) {
          try {
            var d = target.onEvent(this._jargs, retval);
            emit(target, d);
          } catch (e) { vlog('ERROR', { where: target.key + ' onLeave', msg: String(e) }); }
        }
      });
    } else {
      Interceptor.attach(target.resolved.addr, {
        onEnter: function (args) {
          try {
            var d = target.onEvent(args);
            emit(target, d);
          } catch (e) { vlog('ERROR', { where: target.key + ' onEnter', msg: String(e) }); }
        }
      });
    }
    HOOKED[key] = true;
    ARMED.push(key);
    vlog('NATIVE_MIGRATED', { key: target.key, api: target.api, entry: target.resolved.addr.toString(),
                              module: target.resolved.module, sig: target.resolved.sig,
                              note: '只读 ArtMethod(+' + ART_JNI_SLOT.toString(16) + ') 解析 JNI 入口，'
                                    + '对应 WATCH 条目由 hook_privacy.js 跳过（SKIPPED_JAVA）。' });
    globalThis.__vscanNat[target.key] = true;
    return 1;
  } catch (e) {
    vlog('ERROR', { where: 'attach ' + target.key, entry: target.resolved.addr.toString(), msg: String(e) });
    return 0;
  }
}

function armTarget(target, how) {
  if (!target._resolvedHits) {
    target._resolvedHits = resolveByArtMethod(target);
  }
  if (target._resolvedHits.length === 0) {
    if (how === 'arm') {
      if (target._triedMiss) return 0;
      target._triedMiss = true;
      vlog('NATIVE_RESOLVE_MISS', { key: target.key, api: target.api, cls: target.cls,
                                    method: target.method,
                                    note: '类未加载或 ArtMethod 槽位未通过守卫：该 API 回退 Java 层接管，覆盖率不丢。' });
    }
    return 0;
  }
  return attachTarget(target);
}

function armAll(how) {
  var added = 0;
  for (var i = 0; i < TARGETS.length; i++) {
    var t = TARGETS[i];
    if (how === 'arm' && !t._entry) t._entry = matchEntry(t.api);
    added += armTarget(t, how);
  }
  return added;
}

// 类懒加载兜底：arm 时类可能还没被 app 摸过（Java.use 会触发加载，但 attach 早于
// 类初始化时可能解析不到）。低频重试直到全部解析或 30 轮（5 分钟）为止。
function startRescanPoll() {
  var rounds = 0;
  var timer = setInterval(function () {
    rounds++;
    var pending = TARGETS.filter(function (t) { return !t._resolvedHits || t._resolvedHits.length === 0; });
    if (pending.length === 0 || rounds >= 30) {
      clearInterval(timer);
      vlog('RESCAN_STOPPED', { rounds: rounds, hooks: ARMED.length,
                               unresolved: pending.map(function (t) { return t.key; }) });
      return;
    }
    loadModCache();
    var added = armAll('poll');
    if (added > 0) vlog('RESCAN_HOOKED', { how: 'poll', added: added, hooks: ARMED });
  }, 2000);
  return timer;
}

export function main() {
  try {
    PKG = procName();
    if (CFG.whitelist.length > 0 && CFG.whitelist.indexOf(PKG) < 0) {
      vlog('SKIP', { reason: 'not in whitelist', package: PKG, whitelist: CFG.whitelist });
      return;
    }
    vlog('START', { script: 'hook_privacy_native.js', package: PKG, frida: Frida.version,
                    art_jni_slot: '0x' + ART_JNI_SLOT.toString(16) });
    armRuntimeCache();          // 事件路径 threadName/stackStr 的 arm 期缓存
    try { JStr = Java.use('java.lang.String'); } catch (e) { JStr = null; }
    loadModCache();
    var added = armAll('arm');
    startRescanPoll();
    vlog('ARMED', { hooks: ARMED, count: ARMED.length, targets: TARGETS.length,
                    migrated_keys: Object.keys(globalThis.__vscanNat) });
    console.log('[priv_native] ARMED in ' + PKG + ' (' + ARMED.length + '/' + TARGETS.length + ' targets)');
  } catch (e) {
    vlog('ERROR', { where: 'main', msg: String(e && e.stack ? e.stack : e) });
  }
}

// 不自执行：装配由入口负责（单独运行用 dist/hook_privacy_native.bundle.js；
// 合并运行由 hook_all 调用 main）——同 hook_native_ssl.js 的注释（side-effect
// import 会在入口 `globalThis.Java = Java` 之前被提升，直接 ReferenceError）。