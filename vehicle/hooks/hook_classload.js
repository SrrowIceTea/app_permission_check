// 仅用于授权测试（自有设备与自有 APK）/ For authorized testing on owned devices and APKs only.
// V-Scanner F1 — hook_classload.js：运行时类加载记录 + 宿主/第三方/未知归因
//
// 为什么需要它：静态分析只知道"dex 里引用了哪些类"，不知道**运行时真正加载了哪些**。
// 反射加载、动态 dex、加壳残留都只在运行时出现；第三方 SDK 是否真的被装载，
// 也只有运行时能回答。归因口径见 classload_attribution.js（种子表 + 未知一律 unknown）。
//
// 挂哪里：`BaseDexClassLoader.findClass` 是**所有** APK dex 类首次加载的必经点——
// PathClassLoader / DexClassLoader / InMemoryDexClassLoader / DelegateLastClassLoader
// 都继承它，`Class.forName` 最终也走到这里。父加载器（BootClassLoader）里的
// java.* / android.* 不会经过它，正好把平台类噪声挡在外面。
// 另外挂 `ClassLoader.defineClass`：自定义加载器/加壳器直接定义字节码时，
// findClass 看不到，这条是**动态加载证据**的另一半。
//
// 只观察：先执行原实现 → 记录 → 原样返回；异常原对象重抛。不阻断、不改值。
//
// 事件（src=classload，JSONL）：
//   CLASSLOAD_START     配置与种子表大小
//   CLASSLOAD_BATCH     一批首次加载，items = [cls, origin, class_kind, sdk_prefix, loader_id, source]
//   CLASSLOAD_TRUNCATED 命中 max_classes 上限（dropped 计数，不静默截断）
//   ARMED / ERROR       挂载结果（含逐条失败原因）
// 记录按"类名首次出现"去重；批量发送是为了不让几千次 findClass 各打一条事件。

'use strict';
import { packages } from './scope.js';
import { makeLogger, procName } from './vscan_runtime.js';
import { attribute, SDK_TABLE_SIZE } from './classload_attribution.js';

var log = makeLogger('classload', '/data/local/tmp/vscan-vehicle-classload.log');

var CFG = {
  // 上限存在的理由：一次会话加载 8k–20k 个类很常见（androidx/kotlin 占大头），
  // 无上限会把证据包撑到几十 MB。到顶后停止逐类记录，但**必须**留 TRUNCATED 事件。
  maxClasses: 8000,
  batchSize: 200,
  flushMs: 3000,
  // 找不到的类只留样本：反射探测/加壳器会反复试探不存在的类名，全留是纯噪声。
  missingSamples: 20
};

var PKG = null, UID = 0;
var seen = new Set(), missingSeen = new Set();
var pending = [], loaders = new Map();
var missing = 0, missingSamples = [], reportedMissing = 0;
var dropped = 0, truncated = false, nextDropReport = 1000;
var batchSeq = 0, timer = null;

// 同一个 loader 实例只登记一次。key 用 identity hashCode：ClassLoader 不覆写它。
function loaderId(loader) {
  try {
    var key = String(loader.hashCode());
    var known = loaders.get(key);
    if (known) return known.id;
    var name = '';
    try { name = String(loader.toString()); } catch (e) {
      try { name = String(loader.getClass().getName()); } catch (e2) { name = 'unknown'; }
    }
    var entry = {id: loaders.size, name: name.slice(0, 240)};
    loaders.set(key, entry);
    return entry.id;
  } catch (e) { return -1; }
}

function flush() {
  try {
    if (missing > reportedMissing) {
      reportedMissing = missing;
      log('CLASSLOAD_MISSING', {pkg: PKG, uid: UID, user_id: Math.floor(UID / 100000),
        missing: missing, samples: missingSamples});
    }
    if (truncated && dropped >= nextDropReport) {
      nextDropReport += 1000;
      log('CLASSLOAD_TRUNCATED', {pkg: PKG, uid: UID, user_id: Math.floor(UID / 100000),
        max_classes: CFG.maxClasses, seen: seen.size, dropped: dropped});
    }
  } catch (e) {}
  if (pending.length === 0) return;
  var items = pending;
  pending = [];
  try {
    log('CLASSLOAD_BATCH', {
      pkg: PKG, uid: UID, user_id: Math.floor(UID / 100000),
      seq: ++batchSeq, count: items.length,
      loaders: Array.from(loaders.values()), items: items
    });
  } catch (e) {}
}

function record(raw, loader, source) {
  try {
    var attr = attribute(raw, PKG);
    var name = attr.normalized;
    if (!name || seen.has(name)) return;
    if (seen.size >= CFG.maxClasses) {
      dropped++;
      if (!truncated) {
        truncated = true;
        log('CLASSLOAD_TRUNCATED', {pkg: PKG, uid: UID, user_id: Math.floor(UID / 100000),
          max_classes: CFG.maxClasses, seen: seen.size});
      }
      return;
    }
    seen.add(name);
    pending.push([name, attr.origin, attr.class_kind, attr.sdk_prefix, loaderId(loader), source]);
    if (pending.length >= CFG.batchSize) flush();
  } catch (e) {}
}

function recordMissing(raw, loader) {
  try {
    var name = attribute(raw, PKG).normalized;
    if (!name) return;
    missing++;
    if (!missingSeen.has(name) && missingSeen.size < CFG.missingSamples) {
      missingSeen.add(name);
      missingSamples.push([name, loaderId(loader)]);
    }
  } catch (e) {}
}

// findClass(String ...)：所有 APK dex 类的首次加载入口。
function hookFindClass() {
  var armed = [], failed = [];
  try {
    var base = Java.use('dalvik.system.BaseDexClassLoader');
    var overloads = base.findClass.overloads;
    for (var i = 0; i < overloads.length; i++) {
      (function (ov, index) {
        try {
          ov.implementation = function () {
            var args = Array.prototype.slice.call(arguments);
            var name = typeof args[0] === 'string' ? args[0] : null;
            var result;
            try {
              result = ov.apply(this, args);
            } catch (e) {
              if (name) recordMissing(name, this);
              throw e; // 观察模式：异常原对象重抛，绝不改写
            }
            if (name) record(name, this, 'find');
            return result;
          };
          armed.push('BaseDexClassLoader.findClass#' + index);
        } catch (e) { failed.push('findClass#' + index + ': ' + String(e)); }
      })(overloads[i], i);
    }
  } catch (e) { failed.push('BaseDexClassLoader: ' + String(e)); }
  return {armed: armed, failed: failed};
}

// defineClass(String, byte[], ...)：自定义加载器直接定义字节码的路径。
// 平台在应用启动时不会走这里，所以量很小；解不到就如实进 failed，不静默。
function hookDefineClass() {
  var armed = [], failed = [];
  try {
    var loader = Java.use('java.lang.ClassLoader');
    var overloads = loader.defineClass.overloads;
    for (var i = 0; i < overloads.length; i++) {
      (function (ov, index) {
        try {
          var types = ov.argumentTypes;
          if (!types.length || types[0].className !== 'java.lang.String') return;
          if (types.length < 2 || types[1].className !== '[B') return;
          ov.implementation = function () {
            var args = Array.prototype.slice.call(arguments);
            var name = typeof args[0] === 'string' ? args[0] : null;
            var result;
            try {
              result = ov.apply(this, args);
            } catch (e) {
              if (name) recordMissing(name, this);
              throw e;
            }
            if (name) record(name, this, 'define');
            return result;
          };
          armed.push('ClassLoader.defineClass#' + index);
        } catch (e) { failed.push('defineClass#' + index + ': ' + String(e)); }
      })(overloads[i], i);
    }
  } catch (e) { failed.push('ClassLoader: ' + String(e)); }
  return {armed: armed, failed: failed};
}

function main() {
  try {
    PKG = procName();
    var allowed = packages();
    if (allowed.indexOf(PKG) < 0) { log('NOT_TARGET', {pkg: PKG}); return; }
    UID = Number(Java.use('android.os.Process').myUid());
    var sdk = Number(Java.use('android.os.Build$VERSION').SDK_INT.value);
    log('CLASSLOAD_START', {pkg: PKG, uid: UID, user_id: Math.floor(UID / 100000), sdk,
      sdk_seed_prefixes: SDK_TABLE_SIZE, max_classes: CFG.maxClasses,
      batch_size: CFG.batchSize, flush_ms: CFG.flushMs});
    var find = hookFindClass();
    var define = hookDefineClass();
    var armed = find.armed.concat(define.armed);
    var failed = find.failed.concat(define.failed);
    log('ARMED', {pkg: PKG, hooks: armed.length, find_class: find.armed.length,
      define_class: define.armed.length, failed: failed});
    if (armed.length === 0) {
      log('ERROR', {where: 'classload_arm', pkg: PKG, message: 'no classload hooks installed'});
    }
    // 尾批兜底：最后不足 batchSize 的类靠定时器送出去（会话被强杀时可能丢失，如实接受）。
    timer = setInterval(flush, CFG.flushMs);
    console.log('[classload] ARMED in ' + PKG + ' (' + armed.length + ' overloads)');
  } catch (e) {
    log('ERROR', {where: 'main', message: String(e && e.stack ? e.stack : e)});
  }
}

Java.perform(main);
