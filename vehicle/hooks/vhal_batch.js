// ============================================================================
// 仅用于授权测试（自有设备与自有 APK）。
// VHAL 批量/异步/数组读取观察。签名以设备实测为准：
//   vehicle/rules/device_calibration/cpm-signatures-device35.json（android.car.jar javap）
//
// 实测结论（AAOS 35，android.car）：
//   * 没有 getProperties(int[])。此前的覆盖表与注释把不存在的签名写成缺口。
//   * 存在 getPropertiesAsync(java.util.List, ...GetPropertyCallback)：批量异步，
//     参数是 List<Integer>，结果由回调交付。
//   * 存在 getIntArrayProperty(int, int) -> int[]：同步读取，此前完全没有观测。
//   * getPropertyAsync 不存在，不要再按这个名字挂钩子。
//
// hook_vhal.js 只覆盖 5 个单属性标量读取；用上面这些 API 的应用此前一条读取都看不到。
// 只观察：先执行原实现 → 逐条记录 → 原样返回；异常原样重抛。不阻断、不改值。
// 每个重载独立 try/catch：某版本缺签名时只少一个钩子，不影响其余。
// ============================================================================
'use strict';

var MAX_BATCH_ITEMS = 64; // 单个集合的上限，防止异常返回值把日志打爆

function argumentNames(overload) {
  var names = [];
  try {
    var types = overload.argumentTypes;
    for (var i = 0; i < types.length; i++) names.push(String(types[i].className));
  } catch (e) { /* 取不到类型就当作不匹配 */ }
  return names;
}

function isIntArrayDescriptor(name) {
  // Frida 报 JNI 描述符 "[I"；少数桥接报 "int[]"。
  return name === '[I' || name === 'int[]';
}

function matchesIntArrayPair(names) {
  // getProperties(int[]) —— 其他 AAOS 版本可能有，存在就钩。
  return names.length === 1 && isIntArrayDescriptor(names[0]);
}

function matchesListAsync(names) {
  // getPropertiesAsync(List, [long], CancellationSignal, Executor, GetPropertyCallback)
  if (names.length < 2 || names[0] !== 'java.util.List') return false;
  return names[names.length - 1].indexOf('GetPropertyCallback') >= 0;
}

function matchesIntPairScalar(names) {
  // getIntArrayProperty(int propertyId, int areaId) -> int[]
  return names.length === 2 && names[0] === 'int' && names[1] === 'int';
}

function collectIds(source) {
  var out = [];
  try {
    if (source === null || source === undefined) return out;
    if (typeof source.length === 'number') {           // int[]
      for (var i = 0; i < source.length && i < MAX_BATCH_ITEMS; i++) out.push(source[i]);
    } else {                                            // java.util.List<Integer>
      var size = source.size();
      for (var j = 0; j < size && j < MAX_BATCH_ITEMS; j++) out.push(source.get(j));
    }
  } catch (e) { /* 非集合形态：放弃这一条 */ }
  return out;
}

function valueOfRow(row) {
  try {
    var id = row.getPropertyId();
    var area = null;
    var value = null;
    try { area = row.getAreaId(); } catch (e) { area = null; }
    try { value = String(row.getValue()); } catch (e) { value = null; }
    return { propId: id, areaId: area, value: value };
  } catch (e) {
    return null;
  }
}

function emitRows(api, rows, deps, caller) {
  var size = 0;
  try { size = rows.size(); } catch (e) { return 0; }
  var emitted = 0;
  for (var i = 0; i < size && i < MAX_BATCH_ITEMS; i++) {
    var parsed = valueOfRow(rows.get(i));
    if (!parsed || !deps.watch[parsed.propId]) continue;
    deps.emit(api, parsed.propId, parsed.areaId, caller, 'ok', parsed.value);
    emitted += 1;
  }
  return emitted;
}

function makeBatchImpl(api, deps, orig) {
  return function () {
    var args = Array.prototype.slice.call(arguments);
    var ret = orig.apply(this, args);
    try {
      if (!deps.isSystem()) {
        var caller = deps.callerInfo();
        if (deps.whitelisted(caller.pkg)) {
          var ids = collectIds(args[0]);
          var emitted = emitRows(api, ret, deps, caller);
          deps.vlog('VHAL_BATCH', {
            api: api, requested: ids.length, returned: emitted,
            watched: ids.filter(function (id) { return !!deps.watch[id]; }).length
          });
        }
      }
    } catch (e) {
      deps.vlog('ERROR', { where: api, msg: String(e) });
    }
    return ret;
  };
}

// 回调对象上包一层：不改它收到的参数、不阻断原回调。
// 绑定到具体重载，否则给方法代理设 implementation 会让所有重载共用同一实现。
function wrapCallback(callback, api, deps, caller) {
  if (callback === null || callback === undefined) return;
  try {
    var name = String(callback.getClass().getName());
    if (name.indexOf('GetPropertyCallback') < 0) return;
    var instance = Java.cast(callback, Java.use(name));
    if (!instance.onGetProperty) return;
    var overloads = instance.onGetProperty.overloads;
    for (var i = 0; i < overloads.length; i++) {
      (function (overload) {
        overload.implementation = function () {
          try {
            var parsed = valueOfRow(arguments[0]);
            if (parsed && deps.watch[parsed.propId] && deps.whitelisted(caller.pkg)) {
              deps.emit(api + '.onGetProperty', parsed.propId, parsed.areaId,
                caller, 'ok', parsed.value);
            }
          } catch (e) {
            deps.vlog('ERROR', { where: api + '.onGetProperty', msg: String(e) });
          }
          return overload.apply(this, arguments);
        };
      })(overloads[i]);
    }
  } catch (e) {
    deps.vlog('ERROR', { where: api + '.wrapCallback', msg: String(e) });
  }
}

function makeAsyncImpl(api, deps, orig) {
  return function () {
    var args = Array.prototype.slice.call(arguments);
    var ret = orig.apply(this, args);
    try {
      if (!deps.isSystem()) {
        var caller = deps.callerInfo();
        if (deps.whitelisted(caller.pkg)) {
          // 回调恒为最后一个参数：两个重载的中间参数个数不同。
          wrapCallback(args[args.length - 1], api, deps, caller);
          deps.vlog('VHAL_ASYNC_ARMED', {
            api: api, arg_count: args.length, requested: collectIds(args[0]).length
          });
        }
      }
    } catch (e) {
      deps.vlog('ERROR', { where: api, msg: String(e) });
    }
    return ret;
  };
}

function makeArrayImpl(api, deps, orig) {
  return function () {
    var args = Array.prototype.slice.call(arguments);
    var propId = args[0];
    var area = args[1];
    var ret = orig.apply(this, args);
    try {
      if (!deps.isSystem() && deps.watch[propId]) {
        var caller = deps.callerInfo();
        if (deps.whitelisted(caller.pkg)) {
          var value = null;
          try { value = JSON.stringify(Array.prototype.slice.call(ret)); } catch (e) { value = null; }
          deps.emit(api, propId, area, caller, 'ok', value);
        }
      }
    } catch (e) {
      deps.vlog('ERROR', { where: api, msg: String(e) });
    }
    return ret;
  };
}

/**
 * Install batch/async/array read hooks. Returns the labels that actually armed.
 * deps: {CPM, vlog, watch, callerInfo, whitelisted, isSystem, emit}
 */
export function hookBatchReads(deps) {
  var hooked = [];
  var plan = [
    { name: 'getPropertiesAsync', test: matchesListAsync, build: makeAsyncImpl },
    { name: 'getIntArrayProperty', test: matchesIntPairScalar, build: makeArrayImpl },
    { name: 'getProperties', test: matchesIntArrayPair, build: makeBatchImpl }
  ];
  for (var p = 0; p < plan.length; p++) {
    var spec = plan[p];
    var overloads;
    try { overloads = deps.CPM[spec.name].overloads; } catch (e) { continue; }
    for (var i = 0; i < overloads.length; i++) {
      var names = argumentNames(overloads[i]);
      if (!spec.test(names)) continue;
      (function (method, name, types) {
        try {
          method.implementation = spec.build(
            'cpm.' + name + '(' + types.join(',') + ')', deps, method);
          hooked.push('cpm.' + name + '(' + types.join(',') + ')');
        } catch (e) {
          deps.vlog('ERROR', { where: 'hook ' + name, msg: String(e) });
        }
      })(overloads[i], spec.name, names);
    }
  }
  return hooked;
}
